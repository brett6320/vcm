"""Per-vendor VPN config generation from a VpnProfile.

Each generator returns set/CLI-style configuration text. Insecure algorithm use
is annotated inline as comments and also returned as structured warnings via
`model.all_warnings`.
"""
from __future__ import annotations

from .model import VpnProfile
from .proposals import DH_GROUPS, ENCRYPTION, INTEGRITY, vendor_kw


# Only these peers are route-based (VTI / no proxy-IDs, negotiate 0.0.0.0/0) — an
# SRX tunnel to them can rely on st0 routing without traffic-selectors. Everyone
# else (pfSense/strongSwan, AWS, Azure, Cisco crypto-map, MikroTik, Digi,
# Cradlepoint) negotiates SPECIFIC traffic selectors that must match on both sides.
ROUTE_BASED_PEERS = {"juniper_srx", "fortinet", "palo_alto"}


def is_policy_based(vendor: str) -> bool:
    # Unknown/blank peer => treat as policy-based (safer: include selectors).
    return bool(vendor) and vendor not in ROUTE_BASED_PEERS


def addr_kind(value: str) -> str:
    """Classify an endpoint address for gateway config:
    'ip' (literal IPv4/6), 'fqdn' (a DNS/DDNS hostname), or 'dynamic' (blank —
    the peer has no fixed address, so we must be the responder / accept %any)."""
    import ipaddress
    v = (value or "").strip()
    if not v:
        return "dynamic"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        return "fqdn"


def _srx_ident(ident: str) -> str:
    """Junos IKE identity type by the ID's shape: DN -> distinguished-name,
    IP -> inet, otherwise a hostname/FQDN (the default for our IKE IDs)."""
    import ipaddress
    if "=" in ident:                       # e.g. CN=fw.example.com
        return "distinguished-name"
    try:
        ipaddress.ip_address(ident)
        return f"inet {ident}"
    except ValueError:
        return f"hostname {ident}"


def generate(profile: VpnProfile) -> str:
    fn = _REGISTRY.get(profile.vendor)
    if not fn:
        raise ValueError(f"No generator for vendor '{profile.vendor}'")
    cfg = fn(profile)
    if profile.bgp.enabled:
        from .bgp import bgp_config
        cfg += bgp_config(profile.vendor, profile)
    return cfg


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
    st0 = p.tunnel_interface or f"st0.{p.st0_unit}"
    wan = p.wan_interface or "ge-0/0/0"

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
    # IKE gateway. A dynamic-address peer (blank IP) is identified by its IKE ID
    # (hostname), with the SRX acting as responder; otherwise use the address
    # (SRX resolves a DNS/DDNS hostname just like a literal IP).
    kind = addr_kind(p.remote.public_ip)
    if kind == "dynamic":
        gw_addr = (f"set security ike gateway gw-{n} dynamic hostname {p.remote.id}"
                   if p.remote.id
                   else f"# gw-{n}: dynamic peer needs a remote IKE ID (hostname) to match")
    else:
        gw_addr = f"set security ike gateway gw-{n} address {p.remote.public_ip}"
    lines += [
        f"set security ike gateway gw-{n} ike-policy ike-pol-{n}",
        gw_addr,
        f"set security ike gateway gw-{n} external-interface {wan}",
    ]
    # IKEv1 dynamic/FQDN peer ID requires aggressive mode on Junos.
    if kind in ("dynamic", "fqdn") and p.phase1.ike_version != "ikev2":
        lines.append(f"set security ike policy ike-pol-{n} mode aggressive"
                     "   # required: IKEv1 + dynamic/FQDN peer")
    lines += [
        f"set security ike gateway gw-{n} version "
        + ("v2-only" if p.phase1.ike_version == "ikev2" else "v1-only"),
        f"set security ike gateway gw-{n} dead-peer-detection interval {p.phase1.dpd_seconds}",
    ]
    if p.local.id:
        lines.append(f"set security ike gateway gw-{n} local-identity "
                     + _srx_ident(p.local.id))
    if p.remote.id:
        lines.append(f"set security ike gateway gw-{n} remote-identity "
                     + _srx_ident(p.remote.id))
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
    # st0 interface (+ optional IP) + routes
    if p.tunnel_ip:
        lines.append(f"set interfaces {st0} family inet address {p.tunnel_ip}")
    else:
        lines.append(f"set interfaces {st0} family inet")
    for subnet in p.remote.protected_subnets:
        lines.append(f"set routing-options static route {subnet} next-hop {st0}")
    # Phase-2 selectors are required whenever the far end negotiates specific
    # selectors (pfSense/strongSwan, AWS, Azure, Cisco, MikroTik, Digi, Cradlepoint).
    # A single subnet pair -> proxy-identity (classic, matches one peer Phase 2);
    # multiple pairs -> traffic-selectors. Only route-based VTI peers omit them.
    if is_policy_based(p.remote_vendor):
        lines += _srx_selectors(n, p, p.remote_vendor)
    elif p.remote_vendor:
        lines.append(f"# Far end ({p.remote_vendor}) is route-based (VTI); proxy-identity/"
                     "traffic-selectors not required — st0 routing carries traffic.")
    else:
        lines += _srx_selectors(n, p, "the peer")
        lines.append("# Far-end platform not specified; selectors included as a safe default.")
    return _annotate(p, "\n".join(lines))


def _srx_selectors(n: str, p: VpnProfile, who: str) -> list[str]:
    pairs = list(_pairs(p.local.protected_subnets, p.remote.protected_subnets))
    out: list[str] = []
    if len(pairs) == 1:
        l, r = pairs[0]
        out += [f"set security ipsec vpn vpn-{n} ike proxy-identity local {l}",
                f"set security ipsec vpn vpn-{n} ike proxy-identity remote {r}",
                f"set security ipsec vpn vpn-{n} ike proxy-identity service any",
                f"# proxy-identity REQUIRED: it MUST match {who}'s Phase 2 "
                "(pfSense: Local Network = remote here, Remote Network = local here)."]
    else:
        for i, (l, r) in enumerate(pairs):
            out.append(f"set security ipsec vpn vpn-{n} traffic-selector ts{i} local-ip {l}")
            out.append(f"set security ipsec vpn vpn-{n} traffic-selector ts{i} remote-ip {r}")
        out.append(f"# traffic-selectors REQUIRED: each MUST match a {who} Phase 2 entry "
                   "(one selector per peer local/remote network pair).")
    return out


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
def _swanctl_conf(p: VpnProfile, v: str, banner: str) -> str:
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
    # A dynamic peer (no fixed address) -> %any; we can't initiate to it, so trap.
    remote_dynamic = addr_kind(p.remote.public_ip) == "dynamic"
    remote_addr = "%any" if remote_dynamic else p.remote.public_ip

    lines = [
        f"# ---- {banner}: {n} ----",
        "connections {",
        f"  {n} {{",
        f"    version = {2 if p.phase1.ike_version == 'ikev2' else 1}",
        f"    local_addrs  = {p.local.public_ip or '%any'}",
        f"    remote_addrs = {remote_addr}",
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
              f"        start_action = {'trap' if remote_dynamic else 'start'}",
              "      }", "    }",
              f"    reauth_time = {p.phase1.lifetime_seconds}s", "  }", "}"]
    if auth == "psk":
        lines += ["secrets {", f"  ike-{n} {{",
                  f"    id = {p.remote.id or ('%any' if remote_dynamic else p.remote.public_ip)}",
                  f"    secret = \"{p.psk or 'CHANGE-ME'}\"", "  }", "}"]
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# pfSense — GUI field values (VPN > IPsec > Tunnels). pfSense manages swanctl
# itself from config.xml, so operators fill these fields in the web UI.
# --------------------------------------------------------------------------- #
def _pf_enc(canon: str) -> tuple[str, str, bool]:
    # Returns (algorithm, key_length, is_icv). For AES-CBC the length is the cipher
    # key size; for AES-GCM pfSense's "Key length" is the ICV/tag length (def 128).
    return {
        "aes-256-cbc": ("AES", "256", False), "aes-192-cbc": ("AES", "192", False),
        "aes-128-cbc": ("AES", "128", False),
        "aes-256-gcm": ("AES256-GCM", "128", True),
        "aes-192-gcm": ("AES192-GCM", "128", True),
        "aes-128-gcm": ("AES128-GCM", "128", True),
        "3des": ("3DES", "", False), "des": ("DES", "", False),
    }.get(canon, (canon.upper(), "", False))


def _pf_hash(canon: str) -> str:
    return {"sha1": "SHA1", "sha256": "SHA256", "sha384": "SHA384",
            "sha512": "SHA512", "md5": "MD5"}.get(canon, canon.upper())


def gen_pfsense(p: VpnProfile) -> str:
    n = p.name
    cert = p.phase1.auth_method == "certificate"
    e1, k1, icv1 = _pf_enc(p.phase1.encryption)
    e2, k2, icv2 = _pf_enc(p.phase2.encryption)
    gcm1 = "gcm" in p.phase1.encryption
    gcm2 = "gcm" in p.phase2.encryption

    def _keylen(k, icv):
        if not k:
            return ""
        return f"  Key length: {k} bits" + (" (ICV)" if icv else "")
    iface = p.wan_interface or "WAN"
    myid = f"Fully qualified domain name ({p.local.id})" if p.local.id else "My IP address"
    peerid = f"Fully qualified domain name ({p.remote.id})" if p.remote.id else "Peer IP address"
    # A DNS/DDNS hostname goes straight in Remote Gateway (pfSense re-resolves it,
    # policy-based only). A dynamic peer uses 0.0.0.0 (one such tunnel per interface)
    # and MUST identify by FQDN/email, with Child SA Start Action = None.
    rkind = addr_kind(p.remote.public_ip)
    rgw = "0.0.0.0" if rkind == "dynamic" else p.remote.public_ip

    out = [f"# ---- pfSense GUI settings — VPN > IPsec > Tunnels ({n}) ----",
           "[Phase 1 — Edit Phase 1]",
           f"  Key Exchange version : {'IKEv2' if p.phase1.ike_version == 'ikev2' else 'IKEv1'}",
           "  Internet Protocol    : IPv4",
           f"  Interface            : {iface}",
           f"  Remote Gateway       : {rgw}",
           f"  Authentication Method: {'Mutual Certificate' if cert else 'Mutual PSK'}",
           f"  My identifier        : {myid}",
           f"  Peer identifier      : {peerid}"]
    if rkind == "dynamic":
        out.append("  # Dynamic peer: Peer identifier must be FQDN/email (not Peer IP),"
                   " set Child SA Start Action = None, policy-based only (one per interface).")
    elif rkind == "fqdn":
        out.append("  # DDNS hostname: policy-based tunnels only (not VTI); pfSense"
                   " re-resolves periodically.")
    if cert:
        out.append(f"  My Certificate       : {n}-local")
    else:
        out.append("  Pre-Shared Key       : <set on device>")
    out.append(f"  Encryption Algorithm : {e1}" + _keylen(k1, icv1))
    if not gcm1:
        out.append(f"  Hash                 : {_pf_hash(p.phase1.integrity)}")
    out += [f"  DH Group             : {p.phase1.dh_group}",
            f"  Life Time            : {p.phase1.lifetime_seconds}",
            "",
            "[Phase 2 — Edit Phase 2]",
            "  Mode                 : Tunnel IPv4",
            f"  Local Network        : {(p.local.protected_subnets or ['0.0.0.0/0'])[0]}",
            f"  Remote Network       : {(p.remote.protected_subnets or ['0.0.0.0/0'])[0]}",
            "  Protocol             : ESP",
            f"  Encryption Algorithms: {e2}" + _keylen(k2, icv2)]
    if not gcm2:
        out.append(f"  Hash Algorithms      : {_pf_hash(p.phase2.integrity)}")
    out += [f"  PFS key group        : {p.phase2.pfs_group}",
            f"  Life Time            : {p.phase2.lifetime_seconds}"]
    return _annotate(p, "\n".join(out))


# --------------------------------------------------------------------------- #
# Native strongSwan (swanctl.conf) — same renderer as pfSense's swanctl output
# --------------------------------------------------------------------------- #
def gen_strongswan(p: VpnProfile) -> str:
    return _swanctl_conf(p, "strongswan", "native strongSwan swanctl.conf")


# --------------------------------------------------------------------------- #
# MikroTik RouterOS (/ip ipsec CLI)
# --------------------------------------------------------------------------- #
def gen_mikrotik(p: VpnProfile) -> str:
    v = "mikrotik"
    n = p.name
    enc1 = vendor_kw(ENCRYPTION, p.phase1.encryption, v)
    p1_enc = _mt_profile_enc(enc1)  # phase1 profile uses e.g. "aes-256"
    h1 = vendor_kw(INTEGRITY, p.phase1.integrity, v)
    dh1 = vendor_kw(DH_GROUPS, p.phase1.dh_group, v)
    enc2 = vendor_kw(ENCRYPTION, p.phase2.encryption, v)
    h2 = vendor_kw(INTEGRITY, p.phase2.integrity, v)
    pfs = vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)
    exch = "ike2" if p.phase1.ike_version == "ikev2" else "main"
    l = (p.local.protected_subnets or ["0.0.0.0/0"])[0]
    r = (p.remote.protected_subnets or ["0.0.0.0/0"])[0]

    # Peer address: literal IP keeps /32; a DNS/DDNS hostname is used bare (RouterOS
    # resolves it); a dynamic peer has no address -> passive (responder) matching by ID.
    kind = addr_kind(p.remote.public_ip)
    if kind == "ip":
        peer_addr = f"address={p.remote.public_ip}/32 "
    elif kind == "fqdn":
        # RouterOS resolves (and re-resolves) the FQDN; keep /32 for compatibility.
        peer_addr = f"address={p.remote.public_ip}/32 "
    else:
        # Dynamic peer: responder, wildcard address match.
        peer_addr = "address=0.0.0.0/0 passive=yes "
    lines = [f"# ---- MikroTik RouterOS IPsec VPN: {n} ----",
             f"/ip ipsec profile add name={n} hash-algorithm={h1} enc-algorithm={p1_enc} "
             f"dh-group={dh1} lifetime={_secs(p.phase1.lifetime_seconds)}",
             f"/ip ipsec proposal add name={n} auth-algorithms={h2} enc-algorithms={enc2} "
             f"pfs-group={pfs} lifetime={_secs(p.phase2.lifetime_seconds)}",
             f"/ip ipsec peer add name={n} {peer_addr}profile={n} "
             f"exchange-mode={exch}"]
    if p.phase1.auth_method == "certificate":
        lines.append(f"/ip ipsec identity add peer={n} auth-method=digital-signature "
                     f"certificate={n}-local")
    else:
        lines.append(f'/ip ipsec identity add peer={n} auth-method=pre-shared-key '
                     f'secret="{p.psk or "CHANGE-ME"}"')
    lines.append(f"/ip ipsec policy add peer={n} src-address={l} dst-address={r} "
                 f"tunnel=yes proposal={n}")
    return _annotate(p, "\n".join(lines))


def _mt_profile_enc(enc2_kw: str) -> str:
    # RouterOS phase-1 profile enc-algorithm: aes-256 / aes-192 / aes-128 / 3des / des.
    m = {"aes-256-cbc": "aes-256", "aes-256-gcm": "aes-256", "aes-192-cbc": "aes-192",
         "aes-128-cbc": "aes-128", "aes-128-gcm": "aes-128", "3des": "3des", "des": "des"}
    return m.get(enc2_kw, "aes-256")


def _secs(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


# --------------------------------------------------------------------------- #
# Fortinet (FortiOS CLI)
# --------------------------------------------------------------------------- #
def gen_fortinet(p: VpnProfile) -> str:
    v = "fortinet"
    n = p.name[:31]  # FortiOS name length limit
    enc1 = vendor_kw(ENCRYPTION, p.phase1.encryption, v)
    h1 = vendor_kw(INTEGRITY, p.phase1.integrity, v)
    enc2 = vendor_kw(ENCRYPTION, p.phase2.encryption, v)
    h2 = vendor_kw(INTEGRITY, p.phase2.integrity, v)
    prop1 = enc1 if "gcm" in enc1 else f"{enc1}-{h1}"
    prop2 = enc2 if "gcm" in enc2 else f"{enc2}-{h2}"
    dh1 = vendor_kw(DH_GROUPS, p.phase1.dh_group, v)
    pfs = vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)
    cert = p.phase1.auth_method == "certificate"

    wan = p.wan_interface or "wan1"
    # Remote gateway: static IP, DDNS hostname (set type ddns + remotegw-ddns),
    # or a dial-up dynamic peer (set type dynamic, no remote-gw).
    kind = addr_kind(p.remote.public_ip)
    if kind == "ip":
        gw_lines = ["        set type static", f"        set remote-gw {p.remote.public_ip}"]
    elif kind == "fqdn":
        gw_lines = ["        set type ddns", f'        set remotegw-ddns "{p.remote.public_ip}"']
    else:
        # dial-up responder: accept any peer address, allow tunnel-interface creation
        gw_lines = ["        set type dynamic",
                    "        set peertype any", "        set net-device enable"]
    lines = [f"# ---- FortiGate IPsec VPN: {n} ----",
             "config vpn ipsec phase1-interface",
             f'    edit "{n}"',
             gw_lines[0],
             f'        set interface "{wan}"',
             f"        set ike-version {'2' if p.phase1.ike_version == 'ikev2' else '1'}",
             *gw_lines[1:],
             f"        set proposal {prop1}",
             f"        set dhgrp {dh1}",
             f"        set keylife {p.phase1.lifetime_seconds}"]
    if cert:
        lines += ["        set authmethod signature",
                  f'        set certificate "{n}-local"']
    else:
        lines.append(f'        set psksecret "{p.psk or "CHANGE-ME"}"')
    if p.remote.id:
        lines.append(f'        set peerid "{p.remote.id}"')
    lines += ["    next", "end",
              "config vpn ipsec phase2-interface",
              f'    edit "{n}"',
              f'        set phase1name "{n}"',
              f"        set proposal {prop2}",
              f"        set dhgrp {pfs}",
              f"        set keylifeseconds {p.phase2.lifetime_seconds}"]
    l, r = (p.local.protected_subnets or ["0.0.0.0/0"])[0], \
           (p.remote.protected_subnets or ["0.0.0.0/0"])[0]
    lines += [f"        set src-subnet {_ip_mask(l)}",
              f"        set dst-subnet {_ip_mask(r)}",
              "    next", "end"]
    if p.tunnel_ip:
        lines += ["config system interface", f'    edit "{n}"',
                  f"        set ip {_ip_mask(p.tunnel_ip)}", "    next", "end"]
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# Palo Alto (PAN-OS set CLI)
# --------------------------------------------------------------------------- #
def _palo_peer_addr(gw: str, addr: str) -> str:
    """PAN-OS peer-address keyword by address kind: ip / fqdn / dynamic."""
    kind = addr_kind(addr)
    if kind == "ip":
        return f"set network ike gateway {gw} peer-address ip {addr}"
    if kind == "fqdn":
        return f"set network ike gateway {gw} peer-address fqdn {addr}"
    return f"set network ike gateway {gw} peer-address dynamic"


def gen_palo_alto(p: VpnProfile) -> str:
    v = "palo_alto"
    n = p.name
    ikep = f"{n}-ike"
    ipsecp = f"{n}-ipsec"
    gw = f"{n}-gw"
    ver = "ikev2" if p.phase1.ike_version == "ikev2" else "ikev1"
    wan = p.wan_interface or "ethernet1/1"
    tun = p.tunnel_interface or "tunnel.1"
    b = "set network ike crypto-profiles"
    lines = [f"# ---- Palo Alto (PAN-OS) IPsec VPN: {n} ----",
             f"{b} ike-crypto-profiles {ikep} hash {vendor_kw(INTEGRITY, p.phase1.integrity, v)}",
             f"{b} ike-crypto-profiles {ikep} dh-group {vendor_kw(DH_GROUPS, p.phase1.dh_group, v)}",
             f"{b} ike-crypto-profiles {ikep} encryption {vendor_kw(ENCRYPTION, p.phase1.encryption, v)}",
             f"{b} ike-crypto-profiles {ikep} lifetime seconds {p.phase1.lifetime_seconds}",
             f"{b} ipsec-crypto-profiles {ipsecp} esp encryption {vendor_kw(ENCRYPTION, p.phase2.encryption, v)}",
             f"{b} ipsec-crypto-profiles {ipsecp} esp authentication {vendor_kw(INTEGRITY, p.phase2.integrity, v)}",
             f"{b} ipsec-crypto-profiles {ipsecp} dh-group {vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)}",
             f"{b} ipsec-crypto-profiles {ipsecp} lifetime seconds {p.phase2.lifetime_seconds}",
             f"set network ike gateway {gw} protocol version {ver}",
             f"set network ike gateway {gw} protocol {ver} ike-crypto-profile {ikep}",
             _palo_peer_addr(gw, p.remote.public_ip),
             f"set network ike gateway {gw} local-address interface {wan}"]
    # A dynamic/FQDN peer means we respond only (passive); IKEv1 also needs aggressive mode.
    if addr_kind(p.remote.public_ip) in ("dynamic", "fqdn"):
        lines.append(f"set network ike gateway {gw} protocol {ver} exchange-mode aggressive"
                     if ver == "ikev1" else
                     f"# {gw}: dynamic/FQDN peer — enable Passive Mode (respond only)")
        if ver == "ikev1":
            lines.append(f"# {gw}: dynamic/FQDN peer also requires Passive Mode enabled")
    if p.phase1.auth_method == "certificate":
        lines.append(f"set network ike gateway {gw} local-id type fqdn id {p.local.id or n}")
        lines.append(f"set network ike gateway {gw} authentication certificate local-certificate {n}-local")
    else:
        lines.append(f"set network ike gateway {gw} authentication pre-shared-key key {p.psk or 'CHANGE-ME'}")
    lines += [f"set network tunnel ipsec {n} auto-key ike-gateway {gw}",
              f"set network tunnel ipsec {n} auto-key ipsec-crypto-profile {ipsecp}",
              f"set network tunnel ipsec {n} tunnel-interface {tun}"]
    if p.tunnel_ip:
        lines.append(f"set network interface tunnel units {tun} ip {p.tunnel_ip}")
    return _annotate(p, "\n".join(lines))


# --------------------------------------------------------------------------- #
# Cisco Firepower Threat Defense (FlexConfig / ASA-style site-to-site)
# --------------------------------------------------------------------------- #
def gen_cisco_firepower(p: VpnProfile) -> str:
    v = "cisco_firepower"
    n = p.name
    # ASA/FTD do NOT accept a hostname in `set peer` (no DNS/`dynamic` keyword like
    # IOS). So BOTH a DDNS hostname and a truly dynamic IP must use a dynamic crypto
    # map + tunnel-group DefaultL2LGroup (responder) — flag rather than emit a bad peer.
    peer_dynamic = addr_kind(p.remote.public_ip) in ("dynamic", "fqdn")
    peer = "<dynamic-peer>" if peer_dynamic else p.remote.public_ip
    enc1 = vendor_kw(ENCRYPTION, p.phase1.encryption, v)
    h1 = vendor_kw(INTEGRITY, p.phase1.integrity, v)
    enc2 = vendor_kw(ENCRYPTION, p.phase2.encryption, v)
    h2 = vendor_kw(INTEGRITY, p.phase2.integrity, v)
    dh1 = vendor_kw(DH_GROUPS, p.phase1.dh_group, v)
    pfs = vendor_kw(DH_GROUPS, p.phase2.pfs_group, v)
    ikev2 = p.phase1.ike_version == "ikev2"
    l = (p.local.protected_subnets or ["0.0.0.0/0"])[0]
    r = (p.remote.protected_subnets or ["0.0.0.0/0"])[0]

    lines = [f"! ---- Cisco Firepower/FTD (FlexConfig) IPsec VPN: {n} ----"]
    if peer_dynamic:
        lines.append("! Dynamic-IP peer: replace the static crypto map with a "
                     "'crypto dynamic-map' and use tunnel-group DefaultL2LGroup (responder).")
    if ikev2:
        lines += ["crypto ikev2 policy 10",
                  f" encryption {enc1}", f" integrity {h1}", f" group {dh1}",
                  f" prf {h1}", f" lifetime seconds {p.phase1.lifetime_seconds}",
                  f"crypto ipsec ikev2 ipsec-proposal {n}",
                  f" protocol esp encryption {enc2}",
                  f" protocol esp integrity {h2}"]
    else:
        lines += ["crypto ikev1 policy 10", " authentication "
                  + ("rsa-sig" if p.phase1.auth_method == "certificate" else "pre-share"),
                  f" encryption {enc1}", f" hash {h1}", f" group {dh1}",
                  f" lifetime {p.phase1.lifetime_seconds}",
                  f"crypto ipsec ikev1 transform-set {n} esp-{enc1} esp-{h1}-hmac"]
    lines += [f"access-list {n}_acl extended permit ip {_ip_mask(l)} {_ip_mask(r)}",
              f"crypto map {n}_map 10 match address {n}_acl",
              f"crypto map {n}_map 10 set peer {peer}"]
    if ikev2:
        lines.append(f"crypto map {n}_map 10 set ikev2 ipsec-proposal {n}")
        lines.append(f"crypto map {n}_map 10 set pfs {_pan_group(pfs)}")
    else:
        lines.append(f"crypto map {n}_map 10 set ikev1 transform-set {n}")
    lines += [f"crypto map {n}_map interface {p.wan_interface or 'outside'}",
              f"tunnel-group {peer} type ipsec-l2l",
              f"tunnel-group {peer} ipsec-attributes"]
    if p.phase1.auth_method == "certificate":
        lines.append(f" ikev2 local-authentication certificate {n}-trustpoint")
        lines.append(" ikev2 remote-authentication certificate")
    else:
        lines.append(f" ikev2 local-authentication pre-shared-key {p.psk or 'CHANGE-ME'}")
        lines.append(f" ikev2 remote-authentication pre-shared-key {p.psk or 'CHANGE-ME'}")
    return _annotate(p, "\n".join(lines))


def _pan_group(g: str) -> str:
    return g  # cisco uses bare group numbers, already mapped


def _ip_mask(cidr: str) -> str:
    """'10.1.0.0/24' -> '10.1.0.0 255.255.255.0' (ASA/FortiOS style)."""
    import ipaddress as _ip
    try:
        net = _ip.ip_network(cidr, strict=False)
        return f"{net.network_address} {net.netmask}"
    except ValueError:
        return cidr


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
    "fortinet": gen_fortinet,
    "palo_alto": gen_palo_alto,
    "cisco_firepower": gen_cisco_firepower,
    "strongswan": gen_strongswan,
    "mikrotik": gen_mikrotik,
    "aws": lambda p: _cloud_note("AWS", p),
    "azure": lambda p: _cloud_note("Azure", p),
}


def _cloud_note(cloud: str, p: VpnProfile) -> str:
    return (f"# {cloud} VPN gateway config is managed by {cloud}. Import the "
            f"{cloud}-provided configuration, then generate the far-end (on-prem) "
            f"config from this connection.")
