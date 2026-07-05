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
