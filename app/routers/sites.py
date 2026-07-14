from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Site, User, Vendor, VpnConnection, generatable_vendors
from ..security.deps import audit, current_user, require_admin
import copy

from ..srx import defaults as defaults_svc
from ..srx import diff as diff_svc
from ..srx import generators, importer, interop, proposals, rename as rename_mod, suggest
from ..srx.model import Bgp, Endpoint, Phase1, Phase2, VpnProfile, all_warnings
from ..templates_env import render

router = APIRouter(prefix="/sites", tags=["sites"])
conn_router = APIRouter(prefix="/connections", tags=["connections"])


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _subnets(raw: str) -> list[str]:
    return [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]


def _slug(name: str) -> str:
    """Connection names become device config object identifiers, so normalise to a
    safe token (letters, digits, _.-) — spaces/other chars → hyphens."""
    import re
    return re.sub(r"[^A-Za-z0-9_.\-]+", "-", (name or "").strip()).strip("-")


def _unique_site_name(db: Session, base: str) -> str:
    name, i = base, 2
    while db.execute(select(Site).where(Site.name == name)).scalar_one_or_none():
        name = f"{base}-{i}"
        i += 1
    return name


def _unique_conn_name(db: Session, site_id: int, base: str) -> str:
    name, i = base, 2
    q = select(VpnConnection).where(VpnConnection.site_id == site_id,
                                    VpnConnection.name == name)
    while db.execute(q).scalar_one_or_none():
        name = f"{base}-{i}"
        i += 1
        q = select(VpnConnection).where(VpnConnection.site_id == site_id,
                                        VpnConnection.name == name)
    return name


def _profile(conn: VpnConnection) -> VpnProfile:
    return VpnProfile.from_dict(json.loads(conn.params_json))


def _save_profile(conn: VpnConnection, site: Site, profile: VpnProfile) -> None:
    """Pin the profile to the site's vendor, fill IKE IDs, regenerate config, persist."""
    profile.vendor = site.vendor.value
    suggest.fill_ike_ids(profile)
    conn.params_json = json.dumps(profile.to_dict())
    conn.generated_config = generators.generate(profile)


def _preview_config(site: Site, profile: VpnProfile) -> str:
    """Render what _save_profile *would* produce, without persisting anything."""
    p = copy.deepcopy(profile)
    p.vendor = site.vendor.value
    suggest.fill_ike_ids(p)
    return generators.generate(p)


def _diff_section(title: str, before: str, after: str) -> dict:
    return {"title": title, "before": before, "after": after,
            "rows": diff_svc.side_by_side(before, after),
            "changed": diff_svc.changed(before, after)}


def _render_diff(request, *, title, action, sections, fields):
    """Show a side-by-side before/after and require an explicit Apply.
    `fields` is re-posted as hidden inputs alongside confirm=1."""
    return render(request, "config_diff.html", diff_title=title, action=action,
                  sections=sections, fields=fields,
                  any_changed=any(s["changed"] for s in sections))


def _vendor_catalog() -> dict:
    return {v.value: proposals.vendor_options(v.value) for v in Vendor}


def _sites_page(request: Request, db: Session, **extra):
    rows = db.execute(select(Site).order_by(Site.id.desc())).scalars().all()
    counts = dict(db.execute(
        select(VpnConnection.site_id, func.count()).group_by(VpnConnection.site_id)
    ).all())
    d = defaults_svc.get_defaults(db)
    default_vendor = list(Vendor)[0].value
    return render(request, "sites.html", sites=rows, counts=counts, vendors=generatable_vendors(),
                  all_vendors=list(Vendor), defaults=d,
                  vopts=proposals.vendor_options(default_vendor),
                  vendor_catalog=_vendor_catalog(), default_vendor=default_vendor, **extra)


def _apply_interfaces(profile, tunnel_interface, wan_interface, tunnel_ip, remote_vendor):
    profile.tunnel_interface = (tunnel_interface or "").strip()
    profile.wan_interface = (wan_interface or "").strip()
    profile.tunnel_ip = (tunnel_ip or "").strip()
    profile.remote_vendor = (remote_vendor or "").strip()


def _bgp_from_form(bgp_enabled, bgp_local_as, bgp_peer_as, bgp_peer_ip, bgp_local_ip,
                   bgp_networks) -> Bgp:
    return Bgp(enabled=bool(bgp_enabled), local_as=bgp_local_as.strip(),
               peer_as=bgp_peer_as.strip(), peer_ip=bgp_peer_ip.strip(),
               local_ip=bgp_local_ip.strip(), networks=_subnets(bgp_networks))


def _build_profile_from_form(db, name, vendor, model, local_ip, local_id, local_subnets,
                             remote_ip, remote_id, remote_subnets, auth_method, psk,
                             p1_enc, p1_integ, p1_dh, p1_ver, p2_enc, p2_integ, p2_pfs):
    d = defaults_svc.get_defaults(db)
    p1 = Phase1(**d["phase1"])
    p2 = Phase2(**d["phase2"])
    p1.encryption = p1_enc or p1.encryption
    p1.integrity = p1_integ or p1.integrity
    p1.dh_group = p1_dh or p1.dh_group
    p1.ike_version = p1_ver or p1.ike_version
    p1.auth_method = auth_method
    p2.encryption = p2_enc or p2.encryption
    p2.integrity = p2_integ or p2.integrity
    p2.pfs_group = p2_pfs or p2.pfs_group
    return VpnProfile(
        name=name, vendor=vendor, model=model,
        local=Endpoint("local", local_ip, local_id, _subnets(local_subnets)),
        remote=Endpoint("remote", remote_ip, remote_id, _subnets(remote_subnets)),
        phase1=p1, phase2=p2, psk=psk,
    )


def _validate_endpoints(remote_ip, local_subnets, remote_subnets, auth_method, psk,
                        local_ip=""):
    errors = []
    if local_ip is not None and not local_ip.strip():
        # Needed so the far-end/peer config has a real remote gateway address.
        errors.append("Local public IP (this device's address) is required")
    # Blank remote_ip is allowed: addr_kind()/_addr_is_dynamic() treat it as a
    # dynamic/responder-only peer (no fixed address) rather than an error.
    if not _subnets(local_subnets):
        errors.append("At least one local protected subnet is required")
    if not _subnets(remote_subnets):
        errors.append("At least one remote protected subnet is required")
    if auth_method == "psk" and not psk.strip():
        errors.append("A pre-shared key is required when auth method is PSK")
    return errors


# --------------------------------------------------------------------------- #
# Sites (devices)
# --------------------------------------------------------------------------- #
@router.get("")
def sites_home(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _sites_page(request, db)


@router.post("/generate")
def generate_site(request: Request,
                  name: str = Form(...), vendor: str = Form(...), model: str = Form(""),
                  conn_name: str = Form(""),
                  local_ip: str = Form(""), local_id: str = Form(""), local_subnets: str = Form(""),
                  remote_ip: str = Form(""), remote_id: str = Form(""),
                  remote_subnets: str = Form(""),
                  auth_method: str = Form("certificate"), psk: str = Form(""),
                  p1_enc: str = Form(""), p1_integ: str = Form(""), p1_dh: str = Form(""),
                  p1_ver: str = Form(""),
                  p2_enc: str = Form(""), p2_integ: str = Form(""), p2_pfs: str = Form(""),
                  bgp_enabled: str = Form(""), bgp_local_as: str = Form(""),
                  bgp_peer_as: str = Form(""), bgp_peer_ip: str = Form(""),
                  bgp_local_ip: str = Form(""), bgp_networks: str = Form(""),
                  tunnel_interface: str = Form(""), wan_interface: str = Form(""),
                  tunnel_ip: str = Form(""), remote_vendor: str = Form(""),
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    errors = _validate_endpoints(remote_ip, local_subnets, remote_subnets, auth_method, psk, local_ip)
    if errors:
        return _sites_page(request, db, error="; ".join(errors))

    site = Site(name=_unique_site_name(db, name), vendor=Vendor(vendor), model=model,
                source="generated")
    db.add(site)
    db.flush()
    cname = _unique_conn_name(db, site.id, _slug(conn_name) or f"{_slug(name)}-vpn")
    profile = _build_profile_from_form(db, cname, vendor, model, local_ip, local_id,
                                       local_subnets, remote_ip, remote_id, remote_subnets,
                                       auth_method, psk, p1_enc, p1_integ, p1_dh, p1_ver,
                                       p2_enc, p2_integ, p2_pfs)
    profile.bgp = _bgp_from_form(bgp_enabled, bgp_local_as, bgp_peer_as, bgp_peer_ip,
                                 bgp_local_ip, bgp_networks)
    _apply_interfaces(profile, tunnel_interface, wan_interface, tunnel_ip, remote_vendor)
    conn = VpnConnection(site_id=site.id, name=cname, source="generated", params_json="{}")
    _save_profile(conn, site, profile)
    db.add(conn)
    db.flush()
    audit(db, request, "site.generate", f"{vendor}:{site.name}/{cname}", user=user)
    return RedirectResponse(f"/connections/{conn.id}", status_code=303)


@router.get("/import")
def import_form(request: Request, user: User = Depends(current_user)):
    return render(request, "import.html")


def _match_import_site(db: Session, parsed: dict, name: str) -> Site | None:
    """Find an existing site the import likely refers to: by name/hostname, else
    by a shared local public IP on any connection."""
    cand = {n.strip().lower() for n in (name, parsed.get("hostname")) if n and n.strip()}
    sites = db.execute(select(Site)).scalars().all()
    for s in sites:
        if s.name.lower() in cand:
            return s
    imported_ips = {item["profile"].local.public_ip for item in parsed["connections"]
                    if item["profile"].local.public_ip}
    if imported_ips:
        for s in sites:
            for c in s.connections:
                if _profile(c).local.public_ip in imported_ips:
                    return s
    return None


def _imported_config(prof: VpnProfile, raw: str) -> str:
    """The config text to store/diff for an imported connection. Some importers
    (e.g. the structured-Junos excerpt) omit BGP even when the profile captured
    it — append the generated BGP so it isn't lost on import/update/diff."""
    text = raw or ""
    if prof.bgp.enabled and "bgp" not in text.lower():
        from ..srx.bgp import bgp_config
        extra = bgp_config(prof.vendor, prof)
        if extra:
            text = (text.rstrip("\n") + "\n" + extra.lstrip("\n")) if text else extra
    return text


def _import_diff_sections(site: Site, parsed: dict, config_text: str) -> list[dict]:
    """Per-connection before/after between the existing site and the import."""
    by_name = {c.name: c for c in site.connections}
    sections = []
    for item in parsed["connections"]:
        prof = item["profile"]
        after = _imported_config(prof, item.get("config") or config_text)
        ex = by_name.get(prof.name)
        title = prof.name if ex else f"{prof.name} (new connection)"
        sections.append(_diff_section(title, ex.generated_config if ex else "", after))
    imported_names = {item["profile"].name for item in parsed["connections"]}
    for c in site.connections:
        if c.name not in imported_names:
            sections.append(_diff_section(f"{c.name} (kept — not in import)",
                                          c.generated_config or "", c.generated_config or ""))
    return sections


def _apply_import_update(db: Session, site: Site, parsed: dict, config_text: str) -> None:
    """Upsert the imported connections into an existing site (matched by name)."""
    by_name = {c.name: c for c in site.connections}
    for item in parsed["connections"]:
        prof = item["profile"]
        original = config_text                            # full original device config, verbatim
        after = _imported_config(prof, item.get("config") or config_text)
        ex = by_name.get(prof.name)
        if ex:
            ex.params_json = json.dumps(prof.to_dict())
            ex.generated_config = after
            ex.imported_config = original                # preserve original; never regenerated
            ex.needs_review = bool(item.get("review"))
            ex.review_note = item.get("review")
            ex.source = "imported"
        else:
            cname = _unique_conn_name(db, site.id, prof.name)
            prof.name = cname
            db.add(VpnConnection(site_id=site.id, name=cname, source="imported",
                                 params_json=json.dumps(prof.to_dict()),
                                 generated_config=after, imported_config=original,
                                 needs_review=bool(item.get("review")),
                                 review_note=item.get("review")))
    db.flush()


@router.post("/import")
async def do_import(request: Request, name: str = Form(""), config_text: str = Form(""),
                    action: str = Form(""), file: UploadFile = File(None),
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    # A file upload (pfSense config.xml, or a Digi ZIP backup) takes precedence
    # over paste. ZIP archives are unpacked to the config-bearing member.
    if file is not None and file.filename:
        try:
            config_text = importer.config_from_upload(await file.read(), file.filename)
        except Exception as e:  # noqa: BLE001
            return render(request, "import.html", error=f"Could not read the uploaded file: {e}")
    if not config_text.strip():
        return render(request, "import.html", error="Paste a config or upload a file")
    parsed = importer.import_site(config_text, name or None)
    if not parsed["connections"]:
        return render(request, "import.html", error="No VPN connections found in that config")

    existing = _match_import_site(db, parsed, name)

    # Re-importing a known site: preview the diff and let the user choose
    # update (default) or duplicate, before anything is written.
    if existing is not None and action == "":
        sections = _import_diff_sections(existing, parsed, config_text)
        return render(request, "import_review.html", site=existing, site_name=name,
                      config_text=config_text, sections=sections,
                      vendor=parsed["vendor"],
                      any_changed=any(s["changed"] for s in sections))

    if existing is not None and action == "update":
        _apply_import_update(db, existing, parsed, config_text)
        audit(db, request, "site.import_update",
              f"{existing.name} ({len(parsed['connections'])} connections)", user=user)
        return RedirectResponse(f"/sites/{existing.id}", status_code=303)

    # No match, or the user chose to create a duplicate.
    site = Site(name=_unique_site_name(db, name or parsed["hostname"]),
                vendor=Vendor(parsed["vendor"]), model=parsed["model"], source="imported")
    db.add(site)
    db.flush()
    for item in parsed["connections"]:
        profile = item["profile"]
        cname = _unique_conn_name(db, site.id, profile.name)
        profile.name = cname
        original = config_text                            # full original device config, verbatim
        conn = VpnConnection(site_id=site.id, name=cname, source="imported",
                             params_json=json.dumps(profile.to_dict()),
                             generated_config=_imported_config(profile,
                                                               item.get("config") or config_text),
                             imported_config=original,
                             needs_review=bool(item.get("review")),
                             review_note=item.get("review"))
        db.add(conn)
        db.flush()
    audit(db, request, "site.import",
          f"{parsed['vendor']}:{site.name} ({len(parsed['connections'])} connections)", user=user)
    # Land on the device page so all imported connections are visible.
    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@router.get("/reconcile")
def reconcile_page(request: Request, db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    """Find likely-duplicate sites (same normalised name) and offer a merge."""
    sites = db.execute(select(Site).order_by(Site.name)).scalars().all()
    counts = dict(db.execute(
        select(VpnConnection.site_id, func.count()).group_by(VpnConnection.site_id)).all())
    groups: dict[str, list[Site]] = {}
    for s in sites:
        groups.setdefault(_norm_name(s.name), []).append(s)
    dup_groups = [g for g in groups.values() if len(g) > 1]
    return render(request, "reconcile.html", dup_groups=dup_groups, sites=sites, counts=counts)


@router.post("/merge")
def merge_sites(request: Request, target_id: int = Form(...), source_id: int = Form(...),
                db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Merge one site into another: move its connections to the target, then
    delete the now-empty source. Peer links are preserved."""
    target = db.get(Site, target_id)
    source = db.get(Site, source_id)
    if not target or not source:
        raise HTTPException(404, "Not found")
    if target.id == source.id:
        return RedirectResponse("/sites/reconcile", status_code=303)
    moved = 0
    for c in list(source.connections):
        c.name = _unique_conn_name(db, target.id, c.name)
        c.site_id = target.id
        moved += 1
    db.flush()
    # Reload source so its (now-empty) connections collection doesn't cascade-delete
    # the connections we just re-homed.
    db.expire(source, ["connections"])
    db.delete(source)
    db.flush()
    audit(db, request, "site.merge",
          f"{source.name} -> {target.name} ({moved} connections)", user=user)
    return RedirectResponse(f"/sites/{target.id}", status_code=303)


@router.get("/{site_id}")
def site_detail(site_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    conns = []
    for c in site.connections:
        prof = _profile(c)
        conns.append({"c": c, "warnings": all_warnings(prof), "p": prof.to_dict()})
    d = defaults_svc.get_defaults(db)
    return render(request, "site.html", site=site, conns=conns, defaults=d,
                  vopts=proposals.vendor_options(site.vendor.value), all_vendors=list(Vendor))


@router.post("/{site_id}/connections")
def add_connection(site_id: int, request: Request,
                   conn_name: str = Form(""),
                   local_ip: str = Form(""), local_id: str = Form(""), local_subnets: str = Form(""),
                   remote_ip: str = Form(""), remote_id: str = Form(""),
                   remote_subnets: str = Form(""),
                   auth_method: str = Form("certificate"), psk: str = Form(""),
                   p1_enc: str = Form(""), p1_integ: str = Form(""), p1_dh: str = Form(""),
                   p1_ver: str = Form(""),
                   p2_enc: str = Form(""), p2_integ: str = Form(""), p2_pfs: str = Form(""),
                   bgp_enabled: str = Form(""), bgp_local_as: str = Form(""),
                   bgp_peer_as: str = Form(""), bgp_peer_ip: str = Form(""),
                   bgp_local_ip: str = Form(""), bgp_networks: str = Form(""),
                   tunnel_interface: str = Form(""), wan_interface: str = Form(""),
                   tunnel_ip: str = Form(""), remote_vendor: str = Form(""),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    errors = _validate_endpoints(remote_ip, local_subnets, remote_subnets, auth_method, psk, local_ip)
    if errors:
        return site_detail(site_id, request, db, user)  # simple: reload page
    cname = _unique_conn_name(db, site.id, _slug(conn_name) or f"{_slug(site.name)}-vpn")
    profile = _build_profile_from_form(db, cname, site.vendor.value, site.model or "",
                                       local_ip, local_id, local_subnets, remote_ip, remote_id,
                                       remote_subnets, auth_method, psk, p1_enc, p1_integ,
                                       p1_dh, p1_ver, p2_enc, p2_integ, p2_pfs)
    profile.bgp = _bgp_from_form(bgp_enabled, bgp_local_as, bgp_peer_as, bgp_peer_ip,
                                 bgp_local_ip, bgp_networks)
    _apply_interfaces(profile, tunnel_interface, wan_interface, tunnel_ip, remote_vendor)
    conn = VpnConnection(site_id=site.id, name=cname, source="generated", params_json="{}")
    _save_profile(conn, site, profile)
    db.add(conn)
    db.flush()
    audit(db, request, "conn.add", f"{site.name}/{cname}", user=user)
    return RedirectResponse(f"/connections/{conn.id}", status_code=303)


@router.post("/{site_id}/delete")
def delete_site(site_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    # Clear peer references from connections on other sites.
    ids = [c.id for c in site.connections]
    if ids:
        for other in db.execute(
            select(VpnConnection).where(VpnConnection.peer_connection_id.in_(ids))
        ).scalars():
            other.peer_connection_id = None
    name = site.name
    db.delete(site)
    audit(db, request, "site.delete", name, user=user)
    return RedirectResponse("/sites", status_code=303)


# --------------------------------------------------------------------------- #
# Connections
# --------------------------------------------------------------------------- #
def _all_presumed_pairs(db: Session) -> list[dict]:
    """Correlate every unpaired connection with the others and return each
    presumed pair once (highest score first)."""
    unpaired = db.execute(
        select(VpnConnection).where(VpnConnection.peer_connection_id.is_(None))
        .order_by(VpnConnection.id)
    ).scalars().all()
    seen, pairs = set(), []
    for conn in unpaired:
        for s in _suggest_peers(db, conn, _profile(conn)):
            other = s["conn"]
            key = tuple(sorted((conn.id, other.id)))
            if key in seen:
                continue
            seen.add(key)
            pairs.append({"a": conn, "b": other, "reasons": s["reasons"], "score": s["score"]})
    pairs.sort(key=lambda x: -x["score"])
    return pairs


@conn_router.get("/relationships")
def presumed_relationships(request: Request, db: Session = Depends(get_db),
                           user: User = Depends(current_user)):
    """Cross-site view of presumed tunnel relationships for approval."""
    return render(request, "relationships.html", pairs=_all_presumed_pairs(db))


def _fmt_config(vendor: str, text: str | None, fmt: str) -> str:
    """Render Junos config in the requested format so BOTH sides match: canonicalise
    to set-commands, then to curly for the 'curly' view. Non-Junos is returned as-is."""
    t = text or ""
    if vendor != "juniper_srx":
        return t
    as_set = importer.junos_curly_to_set(t)      # curly→set (set passes through)
    return importer.junos_set_to_curly(as_set) if fmt == "curly" else as_set


@conn_router.get("/{conn_id}")
def connection_detail(conn_id: int, request: Request, fmt: str = "set",
                      db: Session = Depends(get_db), user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    profile = _profile(conn)
    peer = db.get(VpnConnection, conn.peer_connection_id) if conn.peer_connection_id else None
    # Candidate connections to pair as the far-end (any other connection).
    candidates = db.execute(
        select(VpnConnection).where(VpnConnection.id != conn.id).order_by(VpnConnection.id)
    ).scalars().all()
    mirror = profile.mirror(f"{profile.name}-peer")
    suggest.fill_ike_ids(mirror)
    bgp_suggest = None
    if peer:
        inferred = suggest.infer_bgp(profile, _profile(peer))
        # Suggest only if it adds something not already configured.
        if inferred and (not profile.bgp.enabled
                         or profile.bgp.peer_ip != inferred.peer_ip
                         or profile.bgp.local_ip != inferred.local_ip):
            bgp_suggest = inferred.__dict__

    # Side-by-side: this side vs the far end (paired peer, else the on-the-fly mirror).
    fmt = "curly" if fmt == "curly" else "set"
    this_vendor = conn.site.vendor.value
    if peer:
        far_vendor = peer.site.vendor.value
        far_label = f"{peer.site.name} / {peer.name} ({peer.site.vendor.label})"
        far_raw = peer.generated_config
    else:
        far_vendor = (profile.remote_vendor or this_vendor)
        far_label = "Far end (generated on the fly)"
        m = profile.mirror(f"{profile.name}-peer")
        m.vendor = far_vendor
        suggest.fill_ike_ids(m)
        far_raw = generators.generate(m)
    # Interop check + structured proposals: each column is the node's ACTUAL config
    # (the real peer, or None when there's no configured peer — no fabricated mirror).
    peer_profile = _profile(peer) if peer else None
    far_profile = peer_profile if peer_profile else mirror
    interop_issues = interop.mismatches(
        profile, peer_profile, near_is_import=(conn.source == "imported")) if peer else []
    proposal_groups = interop.proposal_rows(profile, peer_profile)
    # Config panes: ensure BGP is included in each side (append if the text omits it).
    this_raw = _imported_config(profile, conn.generated_config or "")
    far_raw = _imported_config(far_profile, far_raw)
    sides = {
        "this_label": f"{conn.site.name} / {conn.name} ({conn.site.vendor.label})",
        "this_config": _fmt_config(this_vendor, this_raw, fmt),
        "far_label": far_label,
        "far_config": _fmt_config(far_vendor, far_raw, fmt),
        "imported": conn.imported_config or None,   # verbatim original, never reformatted
        "is_junos": this_vendor == "juniper_srx",
        "has_peer": bool(peer),
    }
    return render(request, "connection.html", conn=conn, site=conn.site,
                  profile=profile.to_dict(), warnings=all_warnings(profile), peer=peer,
                  peer_site=peer.site if peer else None, candidates=candidates,
                  sites=db.execute(select(Site).order_by(Site.name)).scalars().all(),
                  vendors=generatable_vendors(), peer_suggest=mirror.to_dict(),
                  suggestions=(_suggest_peers(db, conn, profile) if not peer else []),
                  bgp_suggest=bgp_suggest, sides=sides, fmt=fmt,
                  interop_issues=interop_issues, proposal_groups=proposal_groups)


def _same_tunnel_subnet(a: str, b: str) -> bool:
    """True if two tunnel-interface addresses are distinct hosts in the same
    small subnet (the classic /30 or /31 point-to-point tunnel pair)."""
    import ipaddress
    if not a or not b:
        return False
    try:
        ia, ib = ipaddress.ip_interface(a), ipaddress.ip_interface(b)
    except ValueError:
        return False
    return ia.ip != ib.ip and ia.network == ib.network and ia.network.prefixlen >= 29


def _suggest_peers(db: Session, conn: VpnConnection, profile: VpnProfile) -> list[dict]:
    """Infer likely peer connections for an unpaired connection by matching
    endpoints/subnets. Returns candidates only — pairing needs user confirmation."""
    if conn.peer_connection_id:
        return []
    out = []
    others = db.execute(
        select(VpnConnection).where(VpnConnection.id != conn.id,
                                    VpnConnection.peer_connection_id.is_(None))
    ).scalars().all()
    my_site = _norm_name(conn.site.name)
    for other in others:
        if other.site_id == conn.site_id:
            continue  # a tunnel's two ends live on different devices
        op = _profile(other)
        reasons, score = [], 0
        # Each side's remote gateway is the other's local public IP (both ways).
        if (profile.remote.public_ip and profile.remote.public_ip == op.local.public_ip
                and profile.local.public_ip and profile.local.public_ip == op.remote.public_ip):
            reasons.append("public IPs match both ways")
            score += 2
        # Protected subnets mirror (my local == its remote, and vice versa).
        if (profile.local.protected_subnets
                and sorted(profile.local.protected_subnets) == sorted(op.remote.protected_subnets)
                and sorted(profile.remote.protected_subnets) == sorted(op.local.protected_subnets)):
            reasons.append("protected subnets mirror")
            score += 1
        # Tunnel IPs in the same subnet (e.g. a shared /30) — a strong peer signal.
        if _same_tunnel_subnet(profile.tunnel_ip, op.tunnel_ip):
            reasons.append("tunnel IPs share a subnet")
            score += 2
        # Names cross-reference each device: my tunnel is named after the other's
        # site, and its tunnel is named after mine (common in imported SRX configs
        # where a tunnel is labelled by the far-end site).
        if (_name_refs(conn.name, other.site.name) and _name_refs(other.name, conn.site.name)):
            reasons.append("connection names cross-reference each site")
            score += 2
        if reasons:
            out.append({"conn": other, "site": other.site, "reasons": reasons, "score": score})
    out.sort(key=lambda x: -x["score"])
    return out


def _norm_name(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _name_refs(conn_name: str, site_name: str) -> bool:
    """True if a connection name references a site name (e.g. 'HESTIA-VPN' -> 'Hestia',
    'CAN2501-VPN' -> 'CAN-2501'). Ignores tiny/ambiguous tokens."""
    a, b = _norm_name(conn_name), _norm_name(site_name)
    return len(b) >= 3 and (b in a or a in b)


@conn_router.get("/{conn_id}/edit")
def edit_connection_form(conn_id: int, request: Request, db: Session = Depends(get_db),
                         user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    return render(request, "connection_edit.html", conn=conn, site=conn.site,
                  profile=_profile(conn).to_dict(), all_vendors=list(Vendor),
                  vopts=proposals.vendor_options(conn.site.vendor.value))


@conn_router.post("/{conn_id}/edit")
def edit_connection(conn_id: int, request: Request,
                    local_ip: str = Form(""), local_id: str = Form(""),
                    local_subnets: str = Form(""), remote_ip: str = Form(""),
                    remote_id: str = Form(""), remote_subnets: str = Form(""),
                    auth_method: str = Form("certificate"), psk: str = Form(""),
                    p1_enc: str = Form(""), p1_integ: str = Form(""), p1_dh: str = Form(""),
                    p1_ver: str = Form(""),
                    p2_enc: str = Form(""), p2_integ: str = Form(""), p2_pfs: str = Form(""),
                    bgp_enabled: str = Form(""), bgp_local_as: str = Form(""),
                    bgp_peer_as: str = Form(""), bgp_peer_ip: str = Form(""),
                    bgp_local_ip: str = Form(""), bgp_networks: str = Form(""),
                    tunnel_interface: str = Form(""), wan_interface: str = Form(""),
                    tunnel_ip: str = Form(""), remote_vendor: str = Form(""),
                    confirm: str = Form(""),
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    site = conn.site
    errors = _validate_endpoints(remote_ip, local_subnets, remote_subnets, auth_method,
                                 psk, local_ip)
    if errors:
        return render(request, "connection_edit.html", conn=conn, site=site,
                      profile=_profile(conn).to_dict(), all_vendors=list(Vendor),
                      vopts=proposals.vendor_options(site.vendor.value),
                      error="; ".join(errors))
    profile = _build_profile_from_form(db, conn.name, site.vendor.value, site.model or "",
                                       local_ip, local_id, local_subnets, remote_ip,
                                       remote_id, remote_subnets, auth_method, psk,
                                       p1_enc, p1_integ, p1_dh, p1_ver, p2_enc, p2_integ,
                                       p2_pfs)
    profile.bgp = _bgp_from_form(bgp_enabled, bgp_local_as, bgp_peer_as, bgp_peer_ip,
                                 bgp_local_ip, bgp_networks)
    _apply_interfaces(profile, tunnel_interface, wan_interface, tunnel_ip, remote_vendor)

    # Show a side-by-side diff of the effective config change and require approval.
    if confirm != "1":
        section = _diff_section(f"{site.name} / {conn.name} ({site.vendor.label})",
                                conn.generated_config or "", _preview_config(site, profile))
        fields = dict(local_ip=local_ip, local_id=local_id, local_subnets=local_subnets,
                      remote_ip=remote_ip, remote_id=remote_id, remote_subnets=remote_subnets,
                      auth_method=auth_method, psk=psk, p1_enc=p1_enc, p1_integ=p1_integ,
                      p1_dh=p1_dh, p1_ver=p1_ver, p2_enc=p2_enc, p2_integ=p2_integ,
                      p2_pfs=p2_pfs, bgp_enabled=bgp_enabled, bgp_local_as=bgp_local_as,
                      bgp_peer_as=bgp_peer_as, bgp_peer_ip=bgp_peer_ip,
                      bgp_local_ip=bgp_local_ip, bgp_networks=bgp_networks,
                      tunnel_interface=tunnel_interface, wan_interface=wan_interface,
                      tunnel_ip=tunnel_ip, remote_vendor=remote_vendor, confirm="1")
        return _render_diff(request, title=f"Review changes to {conn.name}",
                            action=f"/connections/{conn.id}/edit", sections=[section],
                            fields=fields)

    _save_profile(conn, site, profile)   # keeps the connection name, regenerates config
    db.flush()
    audit(db, request, "conn.edit", f"{site.name}/{conn.name}", user=user)
    return RedirectResponse(f"/connections/{conn.id}", status_code=303)


@conn_router.get("/{conn_id}/config")
def connection_config(conn_id: int, db: Session = Depends(get_db),
                      user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    return PlainTextResponse(conn.generated_config or "", media_type="text/plain")


def _far_end_profile(conn: VpnConnection, vendor: str | None) -> VpnProfile:
    """Build the mirrored far-end profile on the fly (not persisted)."""
    profile = _profile(conn)
    peer = profile.mirror(f"{profile.name}-peer")
    peer.vendor = vendor or conn.site.vendor.value
    peer.remote_vendor = conn.site.vendor.value  # the near device is the peer's far end
    suggest.fill_ike_ids(peer)
    return peer


@conn_router.get("/{conn_id}/far-end")
def far_end_view(conn_id: int, request: Request, vendor: str = "",
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    peer = _far_end_profile(conn, vendor or None)
    config = generators.generate(peer)
    return render(request, "farend.html", conn=conn, site=conn.site, peer=peer.to_dict(),
                  vendor=peer.vendor, config=config, warnings=all_warnings(peer),
                  vendors=generatable_vendors())


@conn_router.get("/{conn_id}/far-end.txt")
def far_end_download(conn_id: int, vendor: str = "", db: Session = Depends(get_db),
                     user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    config = generators.generate(_far_end_profile(conn, vendor or None))
    return PlainTextResponse(config, media_type="text/plain")


@conn_router.post("/{conn_id}/peer")
def build_far_end(conn_id: int, request: Request,
                  target: str = Form("new"),           # "new" | existing connection id
                  existing_conn_id: str = Form(""),
                  target_site_id: str = Form(""),       # existing site for a new connection
                  new_site_name: str = Form(""),
                  peer_vendor: str = Form(""),
                  peer_model: str = Form(""),
                  peer_conn_name: str = Form(""),
                  peer_public_ip: str = Form(""),
                  peer_ike_id: str = Form(""),
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    site = conn.site
    profile = _profile(conn)
    # Re-pairing changes the remote device — drop any existing pairing first.
    _unpair(db, conn)

    if target == "existing" and existing_conn_id:
        peer_conn = db.get(VpnConnection, int(existing_conn_id))
        if not peer_conn:
            raise HTTPException(404, "Selected connection not found")
        peer_site = peer_conn.site
        existing = _profile(peer_conn)
        # Mirror our crypto onto the existing far-end, preserving its real local
        # endpoint identity (public IP / subnets), and point our side at it.
        peer_profile = profile.mirror(peer_conn.name)
        peer_profile.local = existing.local
        profile.remote.public_ip = existing.local.public_ip or profile.remote.public_ip
        if existing.local.protected_subnets:
            profile.remote.protected_subnets = existing.local.protected_subnets
        # Each side learns the other's platform (drives SRX traffic-selectors).
        peer_profile.remote_vendor = site.vendor.value
        profile.remote_vendor = peer_site.vendor.value
        _save_profile(peer_conn, peer_site, peer_profile)   # update existing firewall
        _save_profile(conn, site, profile)                  # update our side to match
        conn.peer_connection_id = peer_conn.id
        peer_conn.peer_connection_id = conn.id
        db.flush()
        audit(db, request, "conn.pair_existing", f"{conn.name}<->{peer_conn.name}", user=user)
        return _both_ends(request, db, conn, peer_conn)

    # --- create a new far-end connection --------------------------------- #
    if target_site_id:
        peer_site = db.get(Site, int(target_site_id))
        if not peer_site:
            raise HTTPException(404, "Target site not found")
    else:
        pv = peer_vendor or site.vendor.value
        peer_site = Site(name=_unique_site_name(db, new_site_name or f"{site.name}-peer"),
                         vendor=Vendor(pv), model=peer_model, source="generated")
        db.add(peer_site)
        db.flush()

    cname = _unique_conn_name(db, peer_site.id, _slug(peer_conn_name) or f"{profile.name}-peer")
    peer_profile = profile.mirror(cname)
    if peer_public_ip:
        peer_profile.local.public_ip = peer_public_ip
    if peer_ike_id:
        peer_profile.local.id = peer_ike_id
    # Each side learns the other's platform (drives SRX traffic-selectors).
    peer_profile.remote_vendor = site.vendor.value
    peer_conn = VpnConnection(site_id=peer_site.id, name=cname, source="generated",
                              params_json="{}")
    _save_profile(peer_conn, peer_site, peer_profile)
    db.add(peer_conn)
    db.flush()
    # Point our side's remote at the new far-end's public IP + record its platform.
    profile.remote_vendor = peer_site.vendor.value
    if peer_public_ip:
        profile.remote.public_ip = peer_public_ip
    _save_profile(conn, site, profile)
    conn.peer_connection_id = peer_conn.id
    peer_conn.peer_connection_id = conn.id
    db.flush()
    audit(db, request, "conn.build_far_end",
          f"{conn.name}->{peer_site.name}/{cname}({peer_profile.vendor})", user=user)
    return _both_ends(request, db, conn, peer_conn)


@conn_router.post("/{conn_id}/rename")
def rename_connection(conn_id: int, request: Request, new_name: str = Form(...),
                      db: Session = Depends(get_db), user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    new_name = _slug(new_name)
    old = conn.name
    if not new_name or new_name == old:
        return RedirectResponse(f"/connections/{conn.id}", status_code=303)
    # Enforce uniqueness within the site.
    clash = db.execute(select(VpnConnection).where(
        VpnConnection.site_id == conn.site_id, VpnConnection.name == new_name,
        VpnConnection.id != conn.id)).scalar_one_or_none()
    if clash:
        return RedirectResponse(f"/connections/{conn.id}", status_code=303)

    site = conn.site
    profile = _profile(conn)
    # In-place device rename syntax (uses the OLD profile object names).
    rename_syntax = rename_mod.rename_config(site.vendor.value, profile, old, new_name)
    # Apply the rename: update the profile + connection, regenerate config.
    profile.name = new_name
    conn.name = new_name
    _save_profile(conn, site, profile)
    db.flush()
    audit(db, request, "conn.rename", f"{site.name}: {old} -> {new_name}", user=user)
    return render(request, "rename.html", conn=conn, site=site, old=old, new=new_name,
                  rename_syntax=rename_syntax)


def _unpair(db: Session, conn: VpnConnection) -> None:
    """Break the pairing between conn and its current peer (both directions)."""
    if not conn.peer_connection_id:
        return
    peer = db.get(VpnConnection, conn.peer_connection_id)
    if peer and peer.peer_connection_id == conn.id:
        peer.peer_connection_id = None
    conn.peer_connection_id = None


@conn_router.post("/{conn_id}/pair-confirm")
def pair_confirm(conn_id: int, request: Request, peer_id: int = Form(...),
                 confirm: str = Form(""),
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Confirm an inferred pairing: link two existing, unpaired connections. Keeps
    each side's own crypto; sets peer platform and regenerates both configs."""
    conn = db.get(VpnConnection, conn_id)
    peer = db.get(VpnConnection, peer_id)
    if not conn or not peer:
        raise HTTPException(404, "Not found")
    if conn.peer_connection_id or peer.peer_connection_id:
        return RedirectResponse(f"/connections/{conn.id}", status_code=303)  # already paired

    cp = _profile(conn)
    cp.remote_vendor = peer.site.vendor.value
    pp = _profile(peer)
    pp.remote_vendor = conn.site.vendor.value

    # Preview both sides' effective changes and require approval before applying.
    if confirm != "1":
        sections = [
            _diff_section(f"{conn.site.name} / {conn.name} ({conn.site.vendor.label})",
                          conn.generated_config or "", _preview_config(conn.site, cp)),
            _diff_section(f"{peer.site.name} / {peer.name} ({peer.site.vendor.label})",
                          peer.generated_config or "", _preview_config(peer.site, pp)),
        ]
        return _render_diff(request, title=f"Review pairing {conn.name} ↔ {peer.name}",
                            action=f"/connections/{conn.id}/pair-confirm",
                            sections=sections, fields={"peer_id": peer.id, "confirm": "1"})

    conn.peer_connection_id = peer.id
    peer.peer_connection_id = conn.id
    _save_profile(conn, conn.site, cp)
    _save_profile(peer, peer.site, pp)
    db.flush()
    audit(db, request, "conn.pair_confirm", f"{conn.name}<->{peer.name}", user=user)
    return _both_ends(request, db, conn, peer)


@conn_router.post("/{conn_id}/apply-bgp")
def apply_inferred_bgp(conn_id: int, request: Request, confirm: str = Form(""),
                       db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Apply the inferred BGP peering to this connection and its paired peer."""
    conn = db.get(VpnConnection, conn_id)
    if not conn or not conn.peer_connection_id:
        raise HTTPException(404, "Not found or not paired")
    peer = db.get(VpnConnection, conn.peer_connection_id)
    cp, pp = _profile(conn), _profile(peer)
    near_bgp = suggest.infer_bgp(cp, pp)
    if near_bgp:
        cp.bgp = near_bgp
    peer_bgp = suggest.infer_bgp(pp, cp)
    if peer_bgp:
        pp.bgp = peer_bgp

    if confirm != "1":
        sections = [
            _diff_section(f"{conn.site.name} / {conn.name} ({conn.site.vendor.label})",
                          conn.generated_config or "", _preview_config(conn.site, cp)),
            _diff_section(f"{peer.site.name} / {peer.name} ({peer.site.vendor.label})",
                          peer.generated_config or "", _preview_config(peer.site, pp)),
        ]
        return _render_diff(request, title=f"Review inferred BGP for {conn.name} ↔ {peer.name}",
                            action=f"/connections/{conn.id}/apply-bgp",
                            sections=sections, fields={"confirm": "1"})

    if near_bgp:
        _save_profile(conn, conn.site, cp)
    if peer_bgp:
        _save_profile(peer, peer.site, pp)
    db.flush()
    audit(db, request, "conn.bgp_inferred", f"{conn.name}<->{peer.name}", user=user)
    return RedirectResponse(f"/connections/{conn.id}", status_code=303)


@conn_router.post("/{conn_id}/unpair")
def unpair_connection(conn_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(current_user)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    label = conn.name
    _unpair(db, conn)
    db.flush()
    audit(db, request, "conn.unpair", label, user=user)
    return RedirectResponse(f"/connections/{conn.id}", status_code=303)


@conn_router.post("/{conn_id}/delete")
def delete_connection(conn_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    conn = db.get(VpnConnection, conn_id)
    if not conn:
        raise HTTPException(404, "Not found")
    for other in db.execute(
        select(VpnConnection).where(VpnConnection.peer_connection_id == conn.id)
    ).scalars():
        other.peer_connection_id = None
    site_id = conn.site_id
    label = f"{conn.site.name}/{conn.name}"
    db.delete(conn)
    audit(db, request, "conn.delete", label, user=user)
    return RedirectResponse(f"/sites/{site_id}", status_code=303)


def _both_ends(request: Request, db: Session, near: VpnConnection, far: VpnConnection):
    return render(request, "bothends.html",
                  near={"conn": near, "site": near.site,
                        "warnings": all_warnings(_profile(near))},
                  far={"conn": far, "site": far.site,
                       "warnings": all_warnings(_profile(far))})
