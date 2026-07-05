"""Per-vendor VPN config generation from a VpnProfile.

Each generator returns set/CLI-style configuration text. Insecure algorithm use
is annotated inline as comments and also returned as structured warnings via
`model.all_warnings`.
"""
from __future__ import annotations

from .model import VpnProfile
from .proposals import DH_GROUPS, ENCRYPTION, INTEGRITY, vendor_kw


def generate(profile: VpnProfile) -> str:
    fn = _REGISTRY.get(profile.vendor)
    if not fn:
        raise ValueError(f"No generator for vendor '{profile.vendor}'")
    return fn(profile)


# --------------------------------------------------------------------------- #
# Juniper SRX (200-300 series) — set-style configuration
# --------------------------------------------------------------------------- #
def gen_juniper_srx(p: VpnProfile) -> str:
    v = "juniper_srx"
    enc1 = vendor_kw(ENCRYPTION, p.phase1.encryption, v)
    int1 = vendor_kw(INTEGRITY, p.phase1.integrity, v)
    dh1 = vendor_kw(DH_GROUPS, p.phase1.dh_group, v)
    enc2 = vendor_kw(ENCRYPTION, p.phase2.encryption, v)
    int2 = vendor_kw(INTEGRITY, p.phase2.integrity, v)
    pfs = vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)
    n = p.name
    st0 = f"st0.{p.st0_unit}"

    lines = [f"# ---- Juniper SRX IPsec VPN: {n} ----"]
    # IKE proposal
    lines += [
        f"set security ike proposal ike-prop-{n} authentication-method "
        + ("rsa-signatures" if p.phase1.auth_method == "certificate" else "pre-shared-keys"),
        f"set security ike proposal ike-prop-{n} dh-group {dh1}",
        f"set security ike proposal ike-prop-{n} encryption-algorithm {enc1}",
    ]
    if "gcm" not in enc1:
        lines.append(f"set security ike proposal ike-prop-{n} authentication-algorithm {int1}")
    lines.append(f"set security ike proposal ike-prop-{n} lifetime-seconds "
                 f"{p.phase1.lifetime_seconds}")
    # IKE policy
    lines += [
        f"set security ike policy ike-pol-{n} mode main",
        f"set security ike policy ike-pol-{n} proposals ike-prop-{n}",
    ]
    if p.phase1.auth_method == "certificate":
        lines.append(f"set security ike policy ike-pol-{n} certificate local-certificate "
                     f"{n}-local")
    else:
        lines.append(f"set security ike policy ike-pol-{n} pre-shared-key ascii-text "
                     f"\"{p.psk or 'CHANGE-ME'}\"")
    # IKE gateway
    lines += [
        f"set security ike gateway gw-{n} ike-policy ike-pol-{n}",
        f"set security ike gateway gw-{n} address {p.remote.public_ip}",
        f"set security ike gateway gw-{n} external-interface ge-0/0/0",
        f"set security ike gateway gw-{n} version "
        + ("v2-only" if p.phase1.ike_version == "ikev2" else "v1-only"),
        f"set security ike gateway gw-{n} dead-peer-detection interval {p.phase1.dpd_seconds}",
    ]
    if p.remote.id:
        lines.append(f"set security ike gateway gw-{n} remote-identity "
                     f"distinguished-name container \"{p.remote.id}\"")
    if p.local.id:
        lines.append(f"set security ike gateway gw-{n} local-identity "
                     f"distinguished-name")
    # IPsec proposal
    lines += [
        f"set security ipsec proposal ipsec-prop-{n} protocol {p.phase2.protocol}",
        f"set security ipsec proposal ipsec-prop-{n} encryption-algorithm {enc2}",
    ]
    if "gcm" not in enc2:
        lines.append(f"set security ipsec proposal ipsec-prop-{n} "
                     f"authentication-algorithm hmac-{int2}-128")
    lines.append(f"set security ipsec proposal ipsec-prop-{n} lifetime-seconds "
                 f"{p.phase2.lifetime_seconds}")
    # IPsec policy
    lines += [
        f"set security ipsec policy ipsec-pol-{n} perfect-forward-secrecy keys {pfs}",
        f"set security ipsec policy ipsec-pol-{n} proposals ipsec-prop-{n}",
    ]
    # VPN + bind
    lines += [
        f"set security ipsec vpn vpn-{n} bind-interface {st0}",
        f"set security ipsec vpn vpn-{n} ike gateway gw-{n}",
        f"set security ipsec vpn vpn-{n} ike ipsec-policy ipsec-pol-{n}",
        f"set security ipsec vpn vpn-{n} establish-tunnels immediately",
    ]
    # st0 interface + zones + routes
    lines.append(f"set interfaces {st0} family inet")
    for subnet in p.remote.protected_subnets:
        lines.append(f"set routing-options static route {subnet} next-hop {st0}")
    # Proxy IDs (traffic selectors)
    for i, (l, r) in enumerate(_pairs(p.local.protected_subnets, p.remote.protected_subnets)):
        lines.append(f"set security ipsec vpn vpn-{n} traffic-selector ts{i} local-ip {l}")
        lines.append(f"set security ipsec vpn vpn-{n} traffic-selector ts{i} remote-ip {r}")
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# Digi (Accelerated / TransPort — Digi Remote Manager CLI style)
# --------------------------------------------------------------------------- #
def gen_digi(p: VpnProfile) -> str:
    v = "digi"
    n = p.name
    lines = [f"# ---- Digi IPsec tunnel: {n} ----",
             f"ipsec {n} enable on",
             f"ipsec {n} ike_version {'2' if p.phase1.ike_version == 'ikev2' else '1'}",
             f"ipsec {n} peer {p.remote.public_ip}",
             f"ipsec {n} auth_method "
             + ("rsasig" if p.phase1.auth_method == "certificate" else "psk"),
             f"ipsec {n} ike_enc {vendor_kw(ENCRYPTION, p.phase1.encryption, v)}",
             f"ipsec {n} ike_auth {vendor_kw(INTEGRITY, p.phase1.integrity, v)}",
             f"ipsec {n} ike_dh {vendor_kw(DH_GROUPS, p.phase1.dh_group, v)}",
             f"ipsec {n} esp_enc {vendor_kw(ENCRYPTION, p.phase2.encryption, v)}",
             f"ipsec {n} esp_auth {vendor_kw(INTEGRITY, p.phase2.integrity, v)}",
             f"ipsec {n} pfs_dh {vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)}",
             f"ipsec {n} ike_lifetime {p.phase1.lifetime_seconds}",
             f"ipsec {n} esp_lifetime {p.phase2.lifetime_seconds}"]
    if p.phase1.auth_method == "certificate":
        lines.append(f"ipsec {n} local_cert {n}-local.pem")
        lines.append(f"ipsec {n} ca_cert {n}-ca.pem")
    elif p.psk:
        lines.append(f"ipsec {n} psk \"{p.psk}\"")
    for i, (l, r) in enumerate(_pairs(p.local.protected_subnets, p.remote.protected_subnets)):
        lines.append(f"ipsec {n} local_subnet{i} {l}")
        lines.append(f"ipsec {n} remote_subnet{i} {r}")
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# Cradlepoint (NCOS — router config, JSON-ish set commands)
# --------------------------------------------------------------------------- #
def gen_cradlepoint(p: VpnProfile) -> str:
    v = "cradlepoint"
    n = p.name
    lines = [f"# ---- Cradlepoint NCOS IPsec tunnel: {n} ----",
             f"config set vpn/tunnels/{n}/enabled true",
             f"config set vpn/tunnels/{n}/ike/version "
             f"{'2' if p.phase1.ike_version == 'ikev2' else '1'}",
             f"config set vpn/tunnels/{n}/remote_gateway {p.remote.public_ip}",
             f"config set vpn/tunnels/{n}/auth_mode "
             + ("certificate" if p.phase1.auth_method == "certificate" else "psk"),
             f"config set vpn/tunnels/{n}/ike/p1/encryption "
             f"{vendor_kw(ENCRYPTION, p.phase1.encryption, v)}",
             f"config set vpn/tunnels/{n}/ike/p1/hash "
             f"{vendor_kw(INTEGRITY, p.phase1.integrity, v)}",
             f"config set vpn/tunnels/{n}/ike/p1/dh_group "
             f"{vendor_kw(DH_GROUPS, p.phase1.dh_group, v)}",
             f"config set vpn/tunnels/{n}/ike/p2/encryption "
             f"{vendor_kw(ENCRYPTION, p.phase2.encryption, v)}",
             f"config set vpn/tunnels/{n}/ike/p2/hash "
             f"{vendor_kw(INTEGRITY, p.phase2.integrity, v)}",
             f"config set vpn/tunnels/{n}/ike/p2/pfs_group "
             f"{vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)}"]
    if p.phase1.auth_method == "certificate":
        lines.append(f"config set vpn/tunnels/{n}/certificate/local {n}-local")
        lines.append(f"config set vpn/tunnels/{n}/certificate/ca {n}-ca")
    elif p.psk:
        lines.append(f"config set vpn/tunnels/{n}/psk \"{p.psk}\"")
    lines.append(f"config set vpn/tunnels/{n}/local_networks "
                 f"{','.join(p.local.protected_subnets)}")
    lines.append(f"config set vpn/tunnels/{n}/remote_networks "
                 f"{','.join(p.remote.protected_subnets)}")
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# pfSense (strongSwan / swanctl.conf) — also usable on raw strongSwan
# --------------------------------------------------------------------------- #
def gen_pfsense(p: VpnProfile) -> str:
    v = "pfsense"
    n = p.name
    ike = "-".join([vendor_kw(ENCRYPTION, p.phase1.encryption, v),
                    vendor_kw(INTEGRITY, p.phase1.integrity, v),
                    vendor_kw(DH_GROUPS, p.phase1.dh_group, v)])
    esp_parts = [vendor_kw(ENCRYPTION, p.phase2.encryption, v)]
    if "gcm" not in p.phase2.encryption:
        esp_parts.append(vendor_kw(INTEGRITY, p.phase2.integrity, v))
    esp_parts.append(vendor_kw(DH_GROUPS, p.phase2.pfs_group, v))
    esp = "-".join(esp_parts)
    local_ts = ",".join(p.local.protected_subnets or ["0.0.0.0/0"])
    remote_ts = ",".join(p.remote.protected_subnets or ["0.0.0.0/0"])
    auth = "pubkey" if p.phase1.auth_method == "certificate" else "psk"

    lines = [
        f"# ---- pfSense / strongSwan swanctl.conf: {n} ----",
        "connections {",
        f"  {n} {{",
        f"    version = {2 if p.phase1.ike_version == 'ikev2' else 1}",
        f"    local_addrs  = {p.local.public_ip or '%any'}",
        f"    remote_addrs = {p.remote.public_ip}",
        f"    proposals = {ike}",
        f"    dpd_delay = {p.phase1.dpd_seconds}s",
        "    local {",
        f"      auth = {auth}",
    ]
    if auth == "pubkey":
        lines.append(f"      certs = {n}-local.crt")
    if p.local.id:
        lines.append(f"      id = {p.local.id}")
    lines += ["    }", "    remote {", f"      auth = {auth}"]
    if p.remote.id:
        lines.append(f"      id = {p.remote.id}")
    if auth == "psk":
        lines.append("      # PSK defined in secrets block below")
    lines += ["    }", "    children {", f"      {n} {{",
              f"        local_ts  = {local_ts}",
              f"        remote_ts = {remote_ts}",
              f"        esp_proposals = {esp}",
              f"        life_time = {p.phase2.lifetime_seconds}s",
              "        start_action = start", "      }", "    }",
              f"    reauth_time = {p.phase1.lifetime_seconds}s", "  }", "}"]
    if auth == "psk":
        lines += ["secrets {", f"  ike-{n} {{",
                  f"    id = {p.remote.public_ip}",
                  f"    secret = \"{p.psk or 'CHANGE-ME'}\"", "  }", "}"]
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
def _pairs(a: list[str], b: list[str]):
    a = a or ["0.0.0.0/0"]
    b = b or ["0.0.0.0/0"]
    for i in range(max(len(a), len(b))):
        yield a[min(i, len(a) - 1)], b[min(i, len(b) - 1)]


def _annotate(p: VpnProfile, config: str) -> str:
    from .model import all_warnings

    warns = all_warnings(p)
    if not warns:
        return config
    banner = ["", "# ==================== SECURITY WARNINGS ===================="]
    for w in warns:
        banner.append(f"#  [{w['severity'].upper()}] {w['message']}")
    banner.append("# ===========================================================")
    return config + "\n".join(banner) + "\n"


_REGISTRY = {
    "juniper_srx": gen_juniper_srx,
    "digi": gen_digi,
    "cradlepoint": gen_cradlepoint,
    "pfsense": gen_pfsense,
}
