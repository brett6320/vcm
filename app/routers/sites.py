from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Site, User, Vendor
from ..security.deps import audit, current_user, require_admin
from ..srx import defaults as defaults_svc
from ..srx import generators, importer, proposals, suggest
from ..srx.model import Endpoint, Phase1, Phase2, VpnProfile, all_warnings
from ..templates_env import render

router = APIRouter(prefix="/sites", tags=["sites"])


def _subnets(raw: str) -> list[str]:
    return [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]


def _unique_name(db: Session, base: str) -> str:
    name, i = base, 2
    while db.execute(select(Site).where(Site.name == name)).scalar_one_or_none():
        name = f"{base}-{i}"
        i += 1
    return name


@router.get("")
def sites_home(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    sites = db.execute(select(Site).order_by(Site.id.desc())).scalars().all()
    d = defaults_svc.get_defaults(db)
    return render(request, "sites.html", sites=sites, vendors=list(Vendor), defaults=d,
                  opts=proposals.options())


@router.post("/generate")
def generate_site(request: Request,
                  name: str = Form(...), vendor: str = Form(...), model: str = Form(""),
                  local_ip: str = Form(""), local_id: str = Form(""), local_subnets: str = Form(""),
                  remote_ip: str = Form(""), remote_id: str = Form(""),
                  remote_subnets: str = Form(""),
                  auth_method: str = Form("certificate"), psk: str = Form(""),
                  p1_enc: str = Form(""), p1_integ: str = Form(""), p1_dh: str = Form(""),
                  p1_ver: str = Form(""),
                  p2_enc: str = Form(""), p2_integ: str = Form(""), p2_pfs: str = Form(""),
                  make_peer: str = Form(""), peer_name: str = Form(""),
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    d = defaults_svc.get_defaults(db)
    p1 = Phase1(**d["phase1"])
    p2 = Phase2(**d["phase2"])
    # override with any supplied form values (blank => keep default)
    p1.encryption = p1_enc or p1.encryption
    p1.integrity = p1_integ or p1.integrity
    p1.dh_group = p1_dh or p1.dh_group
    p1.ike_version = p1_ver or p1.ike_version
    p1.auth_method = auth_method
    p2.encryption = p2_enc or p2.encryption
    p2.integrity = p2_integ or p2.integrity
    p2.pfs_group = p2_pfs or p2.pfs_group

    profile = VpnProfile(
        name=name, vendor=vendor, model=model,
        local=Endpoint("local", local_ip, local_id, _subnets(local_subnets)),
        remote=Endpoint("remote", remote_ip, remote_id, _subnets(remote_subnets)),
        phase1=p1, phase2=p2, psk=psk,
    )
    profile.name = _unique_name(db, name)
    name = profile.name
    suggest.fill_ike_ids(profile)  # auto-fill any blank IKE IDs
    config = generators.generate(profile)
    warnings = all_warnings(profile)

    site = Site(name=name, vendor=Vendor(vendor), model=model,
                params_json=json.dumps(profile.to_dict()), generated_config=config,
                source="generated")
    db.add(site)
    db.flush()
    audit(db, request, "site.generate", f"{vendor}:{name}", user=user)

    # Optionally build the compatible peer (far-end) config with mirrored params.
    if make_peer:
        pname = _unique_name(db, peer_name or f"{name}-peer")
        peer_profile = profile.mirror(pname)
        peer_config = generators.generate(peer_profile)
        peer_site = Site(name=pname, vendor=Vendor(vendor), model=model,
                         params_json=json.dumps(peer_profile.to_dict()),
                         generated_config=peer_config, source="generated",
                         peer_site_id=site.id)
        db.add(peer_site)
        db.flush()
        site.peer_site_id = peer_site.id
        audit(db, request, "site.generate_peer", f"{vendor}:{pname}", user=user)

    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@router.get("/import")
def import_form(request: Request, user: User = Depends(current_user)):
    return render(request, "import.html")


@router.post("/import")
def do_import(request: Request, name: str = Form(""), config_text: str = Form(...),
              db: Session = Depends(get_db), user: User = Depends(current_user)):
    profile = importer.import_config(config_text, name or None)
    warnings = all_warnings(profile)
    profile.name = _unique_name(db, profile.name)
    # Persist only the VPN-relevant sections, not the whole pasted device config.
    vpn_only = importer.extract_vpn_sections(config_text, profile.vendor)
    site = Site(name=profile.name, vendor=Vendor(profile.vendor), model=profile.model,
                params_json=json.dumps(profile.to_dict()),
                generated_config=vpn_only or config_text, source="imported")
    db.add(site)
    db.flush()
    audit(db, request, "site.import", f"{profile.vendor}:{profile.name}", user=user)
    mirror = profile.mirror(f"{profile.name}-peer")
    suggest.fill_ike_ids(mirror)
    return render(request, "site.html", site=site, profile=profile.to_dict(),
                  warnings=warnings, imported=True, vendors=list(Vendor),
                  peer_suggest=mirror.to_dict())


@router.get("/{site_id}")
def site_detail(site_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    profile = VpnProfile.from_dict(json.loads(site.params_json))
    peer = db.get(Site, site.peer_site_id) if site.peer_site_id else None
    # Suggested far-end defaults (mirror of this side) to prefill the peer form.
    mirror = profile.mirror(f"{profile.name}-peer")
    suggest.fill_ike_ids(mirror)
    return render(request, "site.html", site=site, profile=profile.to_dict(),
                  warnings=all_warnings(profile), peer=peer, vendors=list(Vendor),
                  peer_suggest=mirror.to_dict())


@router.post("/{site_id}/peer")
def make_peer(site_id: int, request: Request, peer_name: str = Form(""),
              peer_vendor: str = Form(""), peer_public_ip: str = Form(""),
              peer_ike_id: str = Form(""), peer_model: str = Form(""),
              db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Generate the compatible far-end config for an existing (e.g. imported) site.
    Crypto is mirrored (guaranteed interop); endpoint specifics are prompted for."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    profile = VpnProfile.from_dict(json.loads(site.params_json))
    pname = _unique_name(db, peer_name or f"{profile.name}-peer")
    peer_profile = profile.mirror(pname)
    # Apply operator-supplied far-end details (peer_profile.local == the far end).
    if peer_vendor:
        peer_profile.vendor = peer_vendor
    if peer_public_ip:
        peer_profile.local.public_ip = peer_public_ip
    if peer_ike_id:
        peer_profile.local.id = peer_ike_id
    suggest.fill_ike_ids(peer_profile)
    peer_config = generators.generate(peer_profile)
    peer = Site(name=pname, vendor=Vendor(peer_profile.vendor), model=peer_model or site.model,
                params_json=json.dumps(peer_profile.to_dict()), generated_config=peer_config,
                source="generated", peer_site_id=site.id)
    db.add(peer)
    db.flush()
    site.peer_site_id = peer.id
    audit(db, request, "site.peer_from_existing", f"{pname}({peer_profile.vendor})", user=user)
    return RedirectResponse(f"/sites/{peer.id}", status_code=303)


@router.post("/{site_id}/delete")
def delete_site(site_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    """Admin-only: delete a site/peer and clear back-references from any site that
    pointed to it as its peer."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    for other in db.execute(select(Site).where(Site.peer_site_id == site_id)).scalars():
        other.peer_site_id = None
    name = site.name
    db.delete(site)
    audit(db, request, "site.delete", name, user=user)
    return RedirectResponse("/sites", status_code=303)


@router.get("/{site_id}/config")
def site_config(site_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Not found")
    return PlainTextResponse(site.generated_config or "", media_type="text/plain")
