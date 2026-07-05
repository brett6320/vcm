"""Vendor-neutral VPN connection profile. Generators translate this to each
platform's syntax; importers parse a config back into this shape."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Endpoint:
    name: str = "site"
    public_ip: str = ""          # gateway address / hostname
    id: str = ""                 # IKE ID (FQDN, DN, IP, email)
    protected_subnets: list[str] = field(default_factory=list)  # local nets


@dataclass
class Phase1:
    ike_version: str = "ikev2"
    encryption: str = "aes-256-gcm"
    integrity: str = "sha384"
    dh_group: str = "20"
    lifetime_seconds: int = 28800
    auth_method: str = "certificate"   # certificate | psk
    dpd_seconds: int = 10


@dataclass
class Phase2:
    encryption: str = "aes-256-gcm"
    integrity: str = "sha384"
    pfs_group: str = "20"
    lifetime_seconds: int = 3600
    protocol: str = "esp"


@dataclass
class VpnProfile:
    name: str
    vendor: str                 # juniper_srx | digi | cradlepoint
    model: str = ""
    local: Endpoint = field(default_factory=Endpoint)
    remote: Endpoint = field(default_factory=Endpoint)
    phase1: Phase1 = field(default_factory=Phase1)
    phase2: Phase2 = field(default_factory=Phase2)
    psk: str = ""               # only if auth_method == psk (not recommended)
    # PKI references — which local cert/CA chain the device presents.
    local_cert_id: int | None = None
    ca_id: int | None = None
    st0_unit: int = 0           # SRX secure tunnel interface unit

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "VpnProfile":
        return VpnProfile(
            name=d["name"], vendor=d["vendor"], model=d.get("model", ""),
            local=Endpoint(**d.get("local", {})), remote=Endpoint(**d.get("remote", {})),
            phase1=Phase1(**d.get("phase1", {})), phase2=Phase2(**d.get("phase2", {})),
            psk=d.get("psk", ""), local_cert_id=d.get("local_cert_id"),
            ca_id=d.get("ca_id"), st0_unit=d.get("st0_unit", 0),
        )

    def mirror(self, new_name: str) -> "VpnProfile":
        """Produce the peer profile: swap local/remote, keep crypto identical so
        both sides are guaranteed compatible."""
        m = VpnProfile.from_dict(self.to_dict())
        m.name = new_name
        m.local, m.remote = m.remote, m.local
        m.local_cert_id, m.ca_id = None, self.ca_id
        return m


def all_warnings(p: VpnProfile) -> list[dict]:
    from .proposals import rate_proposal

    w = rate_proposal(p.phase1.encryption, p.phase1.integrity, p.phase1.dh_group,
                      p.phase1.ike_version)
    # Phase 2 shares the IKE version; rate it as ikev2 so the ike-version warning
    # (already emitted for phase 1) isn't duplicated here.
    w += rate_proposal(p.phase2.encryption, p.phase2.integrity, p.phase2.pfs_group,
                       "ikev2")
    if p.phase1.auth_method == "psk":
        w.append({"kind": "auth", "value": "psk", "severity": "weak",
                  "message": "Pre-shared key auth — prefer certificate auth via PKI"})
    # Collapse identical warnings (e.g. the same weak algorithm in P1 and P2).
    seen, deduped = set(), []
    for item in w:
        key = (item["kind"], item["value"], item["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped
