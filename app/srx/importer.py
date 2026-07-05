"""Import existing appliance configs into a VpnProfile to seed the site DB.

Reverse-maps vendor keywords back to canonical algorithm ids so an imported peer
can be re-generated or a compatible far-end produced. Best-effort: unparsed lines
are ignored, and whatever crypto params are found populate the profile.
"""
from __future__ import annotations

import re

from .model import Endpoint, Phase1, Phase2, VpnProfile
from .proposals import DH_GROUPS, ENCRYPTION, INTEGRITY


def _reverse(table: dict, vendor: str, kw: str) -> str:
    kw = (kw or "").lower()
    for canon, algo in table.items():
        if algo.vendor.get(vendor, "").lower() == kw or algo.name == kw:
            return canon
    return kw


def extract_vpn_sections(text: str, vendor: str) -> str:
    """Strip everything except VPN-relevant config so we don't persist unrelated
    (and possibly sensitive) device state — only IKE/IPsec/tunnel sections."""
    if vendor == "juniper_srx":
        keep = []
        for line in text.splitlines():
            s = line.strip()
            if (s.startswith("set security ike") or s.startswith("set security ipsec")
                    or "interfaces st0" in s
                    or ("routing-options" in s and "st0" in s)):
                keep.append(line.rstrip())
        return "\n".join(keep) + ("\n" if keep else "")
    if vendor == "digi":
        keep = [l.rstrip() for l in text.splitlines() if re.match(r"\s*ipsec\s+\S+", l)]
        return "\n".join(keep) + ("\n" if keep else "")
    if vendor == "cradlepoint":
        keep = [l.rstrip() for l in text.splitlines() if "vpn/tunnels" in l]
        return "\n".join(keep) + ("\n" if keep else "")
    if vendor == "pfsense":
        return _extract_brace_blocks(text, ("connections", "secrets"))
    if vendor == "fortinet":
        keep, grab = [], False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("config vpn ipsec"):
                grab = True
            if grab:
                keep.append(line.rstrip())
            if s == "end":
                grab = False
        return "\n".join(keep) + ("\n" if keep else "")
    if vendor == "palo_alto":
        keep = [l.rstrip() for l in text.splitlines()
                if re.search(r"network (ike|tunnel ipsec)", l)]
        return "\n".join(keep) + ("\n" if keep else "")
    if vendor == "cisco_firepower":
        keep = [l.rstrip() for l in text.splitlines()
                if re.match(r"\s*(crypto |tunnel-group |access-list |group-policy )", l)]
        return "\n".join(keep) + ("\n" if keep else "")
    return text


def _extract_brace_blocks(text: str, names: tuple[str, ...]) -> str:
    """Return the balanced-brace blocks for the given top-level section names
    (e.g. swanctl `connections { ... }` / `secrets { ... }`)."""
    out: list[str] = []
    for name in names:
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*{", text):
            start, brace = m.start(), m.end() - 1
            depth, i = 0, brace
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        out.append(text[start:i + 1])
                        break
                i += 1
    return "\n".join(out) + ("\n" if out else "")


def detect_vendor(text: str) -> str:
    if "set security ike" in text or "set security ipsec" in text:
        return "juniper_srx"
    # Structured (curly-brace) Junos: a `security { ... ike { ... } }` hierarchy.
    if re.search(r"\bsecurity\s*{", text) and re.search(r"\n\s*ike\s*{", text):
        return "juniper_srx"
    if "config vpn ipsec phase1-interface" in text or "config vpn ipsec phase2-interface" in text:
        return "fortinet"
    if "set network ike crypto-profiles" in text or "set network tunnel ipsec" in text \
            or "set network ike gateway" in text:
        return "palo_alto"
    if re.search(r"crypto ikev[12] (policy|ipsec-proposal)", text) \
            or re.search(r"^\s*crypto map ", text, re.M) or "tunnel-group" in text:
        return "cisco_firepower"
    if "config set vpn/tunnels" in text:
        return "cradlepoint"
    if "connections {" in text or "esp_proposals" in text or "swanctl" in text:
        return "pfsense"
    if re.search(r"^\s*ipsec\s+\S+\s+\S", text, re.M):
        return "digi"
    return "juniper_srx"


def is_structured_junos(text: str) -> bool:
    return bool(re.search(r"\bsecurity\s*{", text) and re.search(r"\n\s*ike\s*{", text))


# --------------------------------------------------------------------------- #
# Curly-brace Junos parsing helpers
# --------------------------------------------------------------------------- #
def _balanced(text: str, brace_idx: int) -> str:
    """Given the index of an opening '{', return the inner text up to its match."""
    depth = 0
    for i in range(brace_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_idx + 1:i]
    return text[brace_idx + 1:]


def _find_block(text: str, header: str) -> str | None:
    """Inner text of the first `header { ... }` (header is a regex)."""
    m = re.search(header + r"\s*{", text)
    if not m:
        return None
    return _balanced(text, m.end() - 1)


def _named_blocks(body: str, keyword: str) -> dict[str, str]:
    """Map name -> inner text for every active `keyword <name> { ... }` in body.
    `inactive:`-prefixed stanzas are skipped."""
    out: dict[str, str] = {}
    for m in re.finditer(r"(?:^|\n)([ \t]*)(inactive:\s*)?" + re.escape(keyword)
                         + r"\s+(\S+)\s*{", body):
        if m.group(2):  # inactive
            continue
        out[m.group(3)] = _balanced(body, m.end() - 1)
    return out


def _scalar(body: str, key: str) -> str | None:
    m = re.search(r"\b" + re.escape(key) + r"\s+([^\s;{}]+)\s*;", body)
    return m.group(1) if m else None


def _norm_ipsec_auth(kw: str) -> str:
    # hmac-sha-256-128 -> sha-256 ; hmac-sha1-96 -> sha1
    kw = kw.lower()
    kw = re.sub(r"^hmac-", "", kw)
    kw = re.sub(r"-(96|128|160|192|256|384|512)$", "", kw)
    return kw


def import_config(text: str, name: str | None = None) -> VpnProfile:
    """Single-connection import (kept for callers/tests). Returns the first
    connection found."""
    site = import_site(text, name)
    if site["connections"]:
        return site["connections"][0]["profile"]
    # Fallback to legacy line-style importers.
    vendor = detect_vendor(text)
    if vendor == "digi":
        return _import_digi(text, name)
    if vendor == "pfsense":
        return _import_pfsense(text, name)
    if vendor == "cradlepoint":
        return _import_cradlepoint(text, name)
    return _import_srx(text, name)


def import_site(text: str, name: str | None = None) -> dict:
    """Parse a device config into a site with one or more VPN connections.

    Returns: {vendor, model, hostname, connections: [{profile, config, review}]}
    where `review` is None or a reason string when parsing was incomplete.
    """
    vendor = detect_vendor(text)
    if vendor == "juniper_srx" and is_structured_junos(text):
        return _import_junos_structured(text, name)

    # Single-connection line/brace-style formats.
    if vendor == "digi":
        profile = _import_digi(text, name)
    elif vendor == "pfsense":
        profile = _import_pfsense(text, name)
    elif vendor == "cradlepoint":
        profile = _import_cradlepoint(text, name)
    elif vendor == "fortinet":
        profile = _import_fortinet(text, name)
    elif vendor == "palo_alto":
        profile = _import_palo(text, name)
    elif vendor == "cisco_firepower":
        profile = _import_cisco(text, name)
    else:
        profile = _import_srx(text, name)
    vpn_only = extract_vpn_sections(text, vendor)
    review = None
    if not profile.remote.public_ip and not profile.remote.protected_subnets:
        review = ("Could not parse endpoint details from this config — parameters "
                  "shown are defaults. Verify against the source before use.")
    return {"vendor": vendor, "model": profile.model or "", "hostname": name or profile.name,
            "connections": [{"profile": profile, "config": vpn_only or text, "review": review}]}


# --------------------------------------------------------------------------- #
# Structured (curly-brace) Junos SRX — one connection per `vpn` stanza
# --------------------------------------------------------------------------- #
def _import_junos_structured(text: str, name: str | None) -> dict:
    v = "juniper_srx"
    hostname = name or _scalar(text, "host-name") or "imported-srx"
    mm = re.search(r"#\s*Model:\s*(\S+)", text, re.I)
    model = mm.group(1) if mm else ""

    security = _find_block(text, r"\bsecurity") or ""
    ike = _find_block(security, r"\bike") or ""
    ipsec = _find_block(security, r"\bipsec") or ""

    ike_props = _named_blocks(ike, "proposal")
    ike_pols = _named_blocks(ike, "policy")
    gateways = _named_blocks(ike, "gateway")
    ipsec_props = _named_blocks(ipsec, "proposal")
    ipsec_pols = _named_blocks(ipsec, "policy")
    vpns = _named_blocks(ipsec, "vpn")

    connections = []
    for vname, vbody in vpns.items():
        conn = _junos_connection(v, vname, vbody, gateways, ike_pols, ike_props,
                                 ipsec_pols, ipsec_props)
        connections.append(conn)

    return {"vendor": v, "model": model, "hostname": hostname, "connections": connections}


def _junos_connection(v, vname, vbody, gateways, ike_pols, ike_props, ipsec_pols, ipsec_props):
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    review = []

    bind = _scalar(vbody, "bind-interface")
    gwname = _scalar(vbody, "gateway")
    ipsecpolname = _scalar(vbody, "ipsec-policy")

    # proxy-identity local/remote (traffic selectors)
    proxy = _find_block(vbody, r"proxy-identity")
    if proxy:
        if lm := _scalar(proxy, "local"):
            local.protected_subnets = [lm]
        if rm := _scalar(proxy, "remote"):
            remote.protected_subnets = [rm]

    gw = gateways.get(gwname or "", "")
    if gw:
        remote.public_ip = _scalar(gw, "address") or ""
        # dynamic peers: hostname either `dynamic hostname X;` or inside dynamic { }
        if not remote.public_ip:
            dyn = _find_block(gw, r"dynamic")
            hostname = _scalar(dyn, "hostname") if dyn else _dynamic_hostname(gw)
            if hostname:
                remote.id = hostname
        if lid := re.search(r"local-identity\s+hostname\s+(\S+);", gw):
            local.id = lid.group(1)
        if rid := re.search(r"remote-identity\s+hostname\s+(\S+);", gw):
            remote.id = rid.group(1)
        if "v2-only" in gw:
            p1.ike_version = "ikev2"
        else:
            p1.ike_version = "ikev1"
        if dpd := _scalar(gw, "interval"):
            try:
                p1.dpd_seconds = int(dpd)
            except ValueError:
                pass
        ikepolname = _scalar(gw, "ike-policy")
    else:
        ikepolname = None
        review.append(f"gateway '{gwname}' not found")

    # Phase 1 from ike policy -> proposal
    ikepol = ike_pols.get(ikepolname or "", "")
    if ikepol:
        if "certificate" in ikepol:
            p1.auth_method = "certificate"
        ikepropname = _scalar(ikepol, "proposals")
        prop = ike_props.get(ikepropname or "", "")
        if prop:
            if e := _scalar(prop, "encryption-algorithm"):
                p1.encryption = _reverse(ENCRYPTION, v, e)
            if a := _scalar(prop, "authentication-algorithm"):
                p1.integrity = _reverse(INTEGRITY, v, a)
            if d := _scalar(prop, "dh-group"):
                p1.dh_group = _reverse(DH_GROUPS, v, d)
            if lt := _scalar(prop, "lifetime-seconds"):
                try:
                    p1.lifetime_seconds = int(lt)
                except ValueError:
                    pass
            if "pre-shared-keys" in prop:
                p1.auth_method = "psk"
            elif "rsa-signatures" in prop:
                p1.auth_method = "certificate"
        else:
            review.append("ike proposal not found")
    else:
        review.append("ike policy not found")

    # Phase 2 from ipsec policy -> proposal
    ipsecpol = ipsec_pols.get(ipsecpolname or "", "")
    if ipsecpol:
        pfs = _find_block(ipsecpol, r"perfect-forward-secrecy")
        if pfs and (k := _scalar(pfs, "keys")):
            p2.pfs_group = _reverse(DH_GROUPS, v, k)
        ipsecpropname = _scalar(ipsecpol, "proposals")
        prop = ipsec_props.get(ipsecpropname or "", "")
        if prop:
            if e := _scalar(prop, "encryption-algorithm"):
                p2.encryption = _reverse(ENCRYPTION, v, e)
            if a := _scalar(prop, "authentication-algorithm"):
                p2.integrity = _reverse(INTEGRITY, v, _norm_ipsec_auth(a))
            if pr := _scalar(prop, "protocol"):
                p2.protocol = pr
    else:
        review.append("ipsec policy not found")

    profile = VpnProfile(name=vname, vendor=v, local=local, remote=remote, phase1=p1, phase2=p2)
    # Reconstruct a focused config excerpt for this connection.
    config = _junos_excerpt(vname, vbody, gwname, gw, ikepolname, ikepol, ipsecpolname,
                            ipsecpol, ike_props, ipsec_props, bind)
    return {"profile": profile, "config": config,
            "review": "; ".join(review) if review else None}


def _dynamic_hostname(gw: str) -> str | None:
    m = re.search(r"dynamic\s+hostname\s+(\S+);", gw)
    return m.group(1) if m else None


def _junos_excerpt(vname, vbody, gwname, gw, ikepolname, ikepol, ipsecpolname, ipsecpol,
                   ike_props, ipsec_props, bind) -> str:
    def wrap(kind, nm, inner):
        return f"    {kind} {nm} {{{inner}}}" if inner else ""

    ikepropname = _scalar(ikepol, "proposals") if ikepol else None
    ipsecpropname = _scalar(ipsecpol, "proposals") if ipsecpol else None
    parts = ["security {", "  ike {"]
    if ikepropname:
        parts.append(wrap("proposal", ikepropname, ike_props.get(ikepropname, "")))
    if ikepolname:
        parts.append(wrap("policy", ikepolname, ikepol))
    if gwname:
        parts.append(wrap("gateway", gwname, gw))
    parts += ["  }", "  ipsec {"]
    if ipsecpropname:
        parts.append(wrap("proposal", ipsecpropname, ipsec_props.get(ipsecpropname, "")))
    if ipsecpolname:
        parts.append(wrap("policy", ipsecpolname, ipsecpol))
    parts.append(wrap("vpn", vname, vbody))
    parts += ["  }", "}"]
    return _redact("\n".join(p for p in parts if p))


def _redact(text: str) -> str:
    """Strip secret material that may appear in IKE stanzas before we persist it."""
    text = re.sub(r'(pre-shared-key\s+ascii-text)\s+"?[^;"]+"?;', r"\1 <redacted>;", text)
    text = re.sub(r'(pre-shared-key\s+hexadecimal)\s+\S+;', r"\1 <redacted>;", text)
    text = re.sub(r'(encrypted-password)\s+"?[^;"]+"?;', r"\1 <redacted>;", text)
    return text


# --------------------------------------------------------------------------- #
def _import_srx(text: str, name: str | None) -> VpnProfile:
    v = "juniper_srx"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name

    for line in text.splitlines():
        line = line.strip()
        if m := re.search(r"ike proposal (\S+)", line):
            inferred = inferred or m.group(1).replace("ike-prop-", "")
        if m := re.search(r"encryption-algorithm (\S+)", line):
            if "ike" in line:
                p1.encryption = _reverse(ENCRYPTION, v, m.group(1))
            else:
                p2.encryption = _reverse(ENCRYPTION, v, m.group(1))
        if m := re.search(r"dh-group (\S+)", line):
            p1.dh_group = _reverse(DH_GROUPS, v, m.group(1))
        if m := re.search(r"perfect-forward-secrecy keys (\S+)", line):
            p2.pfs_group = _reverse(DH_GROUPS, v, m.group(1))
        if m := re.search(r"ike (?:proposal \S+ )?authentication-algorithm (\S+)", line):
            p1.integrity = _reverse(INTEGRITY, v, m.group(1))
        if "authentication-method rsa-signatures" in line:
            p1.auth_method = "certificate"
        elif "pre-shared-keys" in line:
            p1.auth_method = "psk"
        if m := re.search(r"gateway \S+ address (\S+)", line):
            remote.public_ip = m.group(1)
        if "v2-only" in line:
            p1.ike_version = "ikev2"
        elif "v1-only" in line:
            p1.ike_version = "ikev1"
        if m := re.search(r"static route (\S+) next-hop", line):
            remote.protected_subnets.append(m.group(1))
        if m := re.search(r"traffic-selector \S+ local-ip (\S+)", line):
            local.protected_subnets.append(m.group(1))
        if m := re.search(r"traffic-selector \S+ remote-ip (\S+)", line):
            remote.protected_subnets.append(m.group(1))

    return VpnProfile(name=inferred or "imported-srx", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _import_digi(text: str, name: str | None) -> VpnProfile:
    v = "digi"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name
    kv = {}
    for line in text.splitlines():
        m = re.match(r"\s*ipsec\s+(\S+)\s+(\S+)\s+(.+)", line)
        if not m:
            continue
        inferred = inferred or m.group(1)
        kv[m.group(2)] = m.group(3).strip().strip('"')
    if "peer" in kv:
        remote.public_ip = kv["peer"]
    if "ike_version" in kv:
        p1.ike_version = "ikev2" if kv["ike_version"] == "2" else "ikev1"
    if "ike_enc" in kv:
        p1.encryption = _reverse(ENCRYPTION, v, kv["ike_enc"])
    if "ike_auth" in kv:
        p1.integrity = _reverse(INTEGRITY, v, kv["ike_auth"])
    if "ike_dh" in kv:
        p1.dh_group = _reverse(DH_GROUPS, v, kv["ike_dh"])
    if "esp_enc" in kv:
        p2.encryption = _reverse(ENCRYPTION, v, kv["esp_enc"])
    if "esp_auth" in kv:
        p2.integrity = _reverse(INTEGRITY, v, kv["esp_auth"])
    if "pfs_dh" in kv:
        p2.pfs_group = _reverse(DH_GROUPS, v, kv["pfs_dh"])
    if "auth_method" in kv:
        p1.auth_method = "certificate" if kv["auth_method"] == "rsasig" else "psk"
    return VpnProfile(name=inferred or "imported-digi", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _classify_token(vendor: str, tok: str):
    """Return (kind, canonical) for a strongSwan-style proposal token."""
    for kind, table in (("enc", ENCRYPTION), ("integ", INTEGRITY), ("dh", DH_GROUPS)):
        for canon, algo in table.items():
            if algo.vendor.get(vendor, "").lower() == tok.lower() or algo.name == tok.lower():
                return kind, canon
    return None, tok


def _import_pfsense(text: str, name: str | None) -> VpnProfile:
    v = "pfsense"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name

    if m := re.search(r"connections\s*{\s*([\w\-]+)\s*{", text):
        inferred = inferred or m.group(1)
    if m := re.search(r"version\s*=\s*(\d)", text):
        p1.ike_version = "ikev2" if m.group(1) == "2" else "ikev1"
    if m := re.search(r"remote_addrs\s*=\s*(\S+)", text):
        remote.public_ip = m.group(1)
    if m := re.search(r"local_addrs\s*=\s*(\S+)", text):
        local.public_ip = m.group(1)
    if re.search(r"auth\s*=\s*pubkey", text):
        p1.auth_method = "certificate"
    elif re.search(r"auth\s*=\s*psk", text):
        p1.auth_method = "psk"

    if m := re.search(r"(?<!esp_)proposals\s*=\s*(\S+)", text):
        for tok in m.group(1).split("-"):
            kind, canon = _classify_token(v, tok)
            if kind == "enc":
                p1.encryption = canon
            elif kind == "integ":
                p1.integrity = canon
            elif kind == "dh":
                p1.dh_group = canon
    if m := re.search(r"esp_proposals\s*=\s*(\S+)", text):
        for tok in m.group(1).split("-"):
            kind, canon = _classify_token(v, tok)
            if kind == "enc":
                p2.encryption = canon
            elif kind == "integ":
                p2.integrity = canon
            elif kind == "dh":
                p2.pfs_group = canon
    if m := re.search(r"local_ts\s*=\s*(\S+)", text):
        local.protected_subnets = [s for s in m.group(1).split(",") if s]
    if m := re.search(r"remote_ts\s*=\s*(\S+)", text):
        remote.protected_subnets = [s for s in m.group(1).split(",") if s]

    return VpnProfile(name=inferred or "imported-pfsense", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _import_fortinet(text: str, name: str | None) -> VpnProfile:
    v = "fortinet"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name
    if m := re.search(r'phase1-interface\s+edit\s+"([^"]+)"', text, re.S):
        inferred = inferred or m.group(1)
    elif m := re.search(r'edit\s+"([^"]+)"', text):
        inferred = inferred or m.group(1)
    if m := re.search(r"set remote-gw (\S+)", text):
        remote.public_ip = m.group(1)
    if m := re.search(r"set ike-version (\d)", text):
        p1.ike_version = "ikev2" if m.group(1) == "2" else "ikev1"
    # first proposal line = phase1, look for a second for phase2
    props = re.findall(r"set proposal (\S+)", text)
    if props:
        _fortinet_prop(props[0], p1, v)
    if len(props) > 1:
        _fortinet_prop(props[1], p2, v)
    dhs = re.findall(r"set dhgrp (\S+)", text)
    if dhs:
        p1.dh_group = _reverse(DH_GROUPS, v, dhs[0])
    if len(dhs) > 1:
        p2.pfs_group = _reverse(DH_GROUPS, v, dhs[1])
    if "set authmethod signature" in text:
        p1.auth_method = "certificate"
    elif "set psksecret" in text:
        p1.auth_method = "psk"
    return VpnProfile(name=inferred or "imported-fortinet", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _fortinet_prop(prop: str, phase, v: str) -> None:
    # e.g. "aes256-sha256" or "aes256gcm"
    if "gcm" in prop:
        phase.encryption = _reverse(ENCRYPTION, v, prop)
        return
    parts = prop.split("-")
    if parts:
        phase.encryption = _reverse(ENCRYPTION, v, parts[0])
    if len(parts) > 1:
        phase.integrity = _reverse(INTEGRITY, v, parts[1])


def _import_palo(text: str, name: str | None) -> VpnProfile:
    v = "palo_alto"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name
    if m := re.search(r"set network tunnel ipsec (\S+)", text):
        inferred = inferred or m.group(1)
    if m := re.search(r"ike-crypto-profiles \S+ encryption (\S+)", text):
        p1.encryption = _reverse(ENCRYPTION, v, m.group(1))
    if m := re.search(r"ike-crypto-profiles \S+ hash (\S+)", text):
        p1.integrity = _reverse(INTEGRITY, v, m.group(1))
    if m := re.search(r"ike-crypto-profiles \S+ dh-group (\S+)", text):
        p1.dh_group = _reverse(DH_GROUPS, v, m.group(1))
    if m := re.search(r"ipsec-crypto-profiles \S+ esp encryption (\S+)", text):
        p2.encryption = _reverse(ENCRYPTION, v, m.group(1))
    if m := re.search(r"ipsec-crypto-profiles \S+ esp authentication (\S+)", text):
        p2.integrity = _reverse(INTEGRITY, v, m.group(1))
    if m := re.search(r"ipsec-crypto-profiles \S+ dh-group (\S+)", text):
        p2.pfs_group = _reverse(DH_GROUPS, v, m.group(1))
    if m := re.search(r"gateway \S+ peer-address ip (\S+)", text):
        remote.public_ip = m.group(1)
    if "protocol version ikev1" in text:
        p1.ike_version = "ikev1"
    elif "protocol version ikev2" in text:
        p1.ike_version = "ikev2"
    if "authentication certificate" in text:
        p1.auth_method = "certificate"
    elif "pre-shared-key" in text:
        p1.auth_method = "psk"
    return VpnProfile(name=inferred or "imported-palo", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _import_cisco(text: str, name: str | None) -> VpnProfile:
    v = "cisco_firepower"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name
    if m := re.search(r"crypto map (\S+)_map", text):
        inferred = inferred or m.group(1)
    p1.ike_version = "ikev2" if "crypto ikev2 policy" in text else "ikev1"
    if m := re.search(r"ikev2 policy[\s\S]{0,200}?encryption (\S+)", text):
        p1.encryption = _reverse(ENCRYPTION, v, m.group(1))
    elif m := re.search(r"ikev1 policy[\s\S]{0,200}?encryption (\S+)", text):
        p1.encryption = _reverse(ENCRYPTION, v, m.group(1))
    if m := re.search(r"\n\s*integrity (\S+)", text):
        p1.integrity = _reverse(INTEGRITY, v, m.group(1))
    elif m := re.search(r"\n\s*hash (\S+)", text):
        p1.integrity = _reverse(INTEGRITY, v, m.group(1))
    if m := re.search(r"\n\s*group (\S+)", text):
        p1.dh_group = _reverse(DH_GROUPS, v, m.group(1))
    if m := re.search(r"protocol esp encryption (\S+)", text):
        p2.encryption = _reverse(ENCRYPTION, v, m.group(1))
    if m := re.search(r"protocol esp integrity (\S+)", text):
        p2.integrity = _reverse(INTEGRITY, v, m.group(1))
    if m := re.search(r"set pfs (\S+)", text):
        p2.pfs_group = _reverse(DH_GROUPS, v, m.group(1))
    if m := re.search(r"set peer (\S+)", text):
        remote.public_ip = m.group(1)
    if "rsa-sig" in text or "authentication certificate" in text:
        p1.auth_method = "certificate"
    elif "pre-shared-key" in text or "pre-share" in text:
        p1.auth_method = "psk"
    return VpnProfile(name=inferred or "imported-cisco", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)


def _import_cradlepoint(text: str, name: str | None) -> VpnProfile:
    v = "cradlepoint"
    p1, p2 = Phase1(), Phase2()
    local, remote = Endpoint(name="local"), Endpoint(name="remote")
    inferred = name
    for line in text.splitlines():
        m = re.match(r"\s*config set vpn/tunnels/(\S+?)/(\S+)\s+(.+)", line)
        if not m:
            continue
        inferred = inferred or m.group(1)
        path, val = m.group(2), m.group(3).strip().strip('"')
        if path.endswith("remote_gateway"):
            remote.public_ip = val
        elif path.endswith("ike/version"):
            p1.ike_version = "ikev2" if val == "2" else "ikev1"
        elif path.endswith("p1/encryption"):
            p1.encryption = _reverse(ENCRYPTION, v, val)
        elif path.endswith("p1/hash"):
            p1.integrity = _reverse(INTEGRITY, v, val)
        elif path.endswith("p1/dh_group"):
            p1.dh_group = _reverse(DH_GROUPS, v, val)
        elif path.endswith("p2/encryption"):
            p2.encryption = _reverse(ENCRYPTION, v, val)
        elif path.endswith("p2/hash"):
            p2.integrity = _reverse(INTEGRITY, v, val)
        elif path.endswith("p2/pfs_group"):
            p2.pfs_group = _reverse(DH_GROUPS, v, val)
        elif path.endswith("auth_mode"):
            p1.auth_method = "certificate" if val == "certificate" else "psk"
        elif path.endswith("local_networks"):
            local.protected_subnets = [s for s in val.split(",") if s]
        elif path.endswith("remote_networks"):
            remote.protected_subnets = [s for s in val.split(",") if s]
    return VpnProfile(name=inferred or "imported-cradlepoint", vendor=v, local=local,
                      remote=remote, phase1=p1, phase2=p2)
