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
    if re.search(r"^\s*ipsec\s+\S+\s+", text, re.M):
        return "digi"
    if "config set vpn/tunnels" in text:
        return "cradlepoint"
    if "connections {" in text or "esp_proposals" in text or "swanctl" in text:
        return "pfsense"
    return "juniper_srx"


def import_config(text: str, name: str | None = None) -> VpnProfile:
    vendor = detect_vendor(text)
    if vendor == "juniper_srx":
        return _import_srx(text, name)
    if vendor == "digi":
        return _import_digi(text, name)
    if vendor == "pfsense":
        return _import_pfsense(text, name)
    return _import_cradlepoint(text, name)


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
