"""Heuristics for auto-suggesting IKE identities when the operator leaves them
blank. Certificate auth → prefer a FQDN/DN-style ID; PSK → fall back to the
public IP (IP-type ID). Deterministic so both sides agree."""
from __future__ import annotations

import ipaddress

from .model import Endpoint, VpnProfile


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def suggest_ike_id(profile: VpnProfile, endpoint: Endpoint, *, domain: str = "vpn.local") -> str:
    """Return a suggested IKE ID for one endpoint (never overrides a set value)."""
    if endpoint.id:
        return endpoint.id
    if profile.phase1.auth_method == "certificate":
        # FQDN-style ID keyed off the site + side; matches a cert SAN/CN convention.
        side = endpoint.name or "gw"
        return f"{profile.name}-{side}.{domain}".lower()
    # PSK or unknown: use the public IP if we have one, else a synthetic FQDN.
    if endpoint.public_ip and _is_ip(endpoint.public_ip):
        return endpoint.public_ip
    return f"{profile.name}-{endpoint.name or 'gw'}.{domain}".lower()


def fill_ike_ids(profile: VpnProfile, domain: str = "vpn.local") -> VpnProfile:
    """Populate blank local/remote IKE IDs in place, returning the profile."""
    if not profile.local.id:
        profile.local.id = suggest_ike_id(profile, profile.local, domain=domain)
    if not profile.remote.id:
        profile.remote.id = suggest_ike_id(profile, profile.remote, domain=domain)
    return profile


def _tunnel_addr(cidr: str) -> str:
    if not cidr:
        return ""
    try:
        return str(ipaddress.ip_interface(cidr).ip)
    except ValueError:
        return cidr.split("/")[0]


def infer_bgp(near: VpnProfile, peer: VpnProfile):
    """Infer BGP peering for a connected pair from tunnel IPs + existing BGP.

    Neighbor = the peer's tunnel-interface IP; local = our tunnel-interface IP.
    ASNs are taken from whichever side already has them (mirrored from the peer).
    Returns a Bgp or None if there's nothing to infer.
    """
    from .model import Bgp

    near_ip = _tunnel_addr(near.tunnel_ip) or near.bgp.local_ip
    peer_ip = _tunnel_addr(peer.tunnel_ip) or peer.bgp.local_ip or peer.bgp.peer_ip
    have_asn = near.bgp.local_as or peer.bgp.enabled
    if not (peer_ip or near_ip) and not have_asn:
        return None

    b = Bgp(enabled=True)
    b.local_as = near.bgp.local_as or (peer.bgp.peer_as if peer.bgp.enabled else "")
    b.peer_as = near.bgp.peer_as or (peer.bgp.local_as if peer.bgp.enabled else "")
    b.local_ip = near_ip
    b.peer_ip = peer_ip
    b.networks = near.bgp.networks or near.local.protected_subnets
    return b
