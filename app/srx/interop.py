"""Compare the two ends of a tunnel and flag interoperability problems.

When two *imported* connections are paired, each keeps its own crypto — so the
proposals can disagree and the tunnel won't come up. This surfaces those
mismatches (and suboptimal-but-matching settings) with a remediation hint. The
imported side is authoritative: remediation always suggests aligning the *other*
end to the imported values, never rewriting the import.
"""
from __future__ import annotations

from .model import VpnProfile
from .proposals import rate_proposal


def _cmp(field, near, far, *, near_is_import, remediate_extra=""):
    if str(near) == str(far):
        return None
    fix_side = "far end" if near_is_import else "this end"
    keep = near if near_is_import else far
    msg = f"{field}: this end = {near!r}, far end = {far!r}"
    rem = f"Set the {fix_side} to {keep!r} so both match." + (
        f" {remediate_extra}" if remediate_extra else "")
    return {"field": field, "near": str(near), "far": str(far),
            "severity": "mismatch", "message": msg, "remediation": rem}


def proposal_rows(near: VpnProfile, far: VpnProfile) -> list[dict]:
    """Structured side-by-side of the IKE/IPsec proposal parameters for both ends,
    grouped by phase. Each row is {label, near, far, match}; `match` is False when
    the two ends disagree (these values must be equal for the tunnel to come up)."""
    p1n, p1f, p2n, p2f = near.phase1, far.phase1, near.phase2, far.phase2

    def row(label, a, b):
        return {"label": label, "near": str(a), "far": str(b), "match": str(a) == str(b)}

    return [
        {"section": "Phase 1 (IKE)", "rows": [
            row("IKE version", p1n.ike_version, p1f.ike_version),
            row("Encryption", p1n.encryption, p1f.encryption),
            row("Integrity", p1n.integrity, p1f.integrity),
            row("DH group", p1n.dh_group, p1f.dh_group),
            row("Auth method", p1n.auth_method, p1f.auth_method),
            row("Lifetime (s)", p1n.lifetime_seconds, p1f.lifetime_seconds),
            row("DPD (s)", p1n.dpd_seconds, p1f.dpd_seconds),
        ]},
        {"section": "Phase 2 (IPsec)", "rows": [
            row("Protocol", p2n.protocol, p2f.protocol),
            row("Encryption", p2n.encryption, p2f.encryption),
            row("Integrity", p2n.integrity, p2f.integrity),
            row("PFS group", p2n.pfs_group, p2f.pfs_group),
            row("Lifetime (s)", p2n.lifetime_seconds, p2f.lifetime_seconds),
        ]},
    ]


def mismatches(near: VpnProfile, far: VpnProfile, *, near_is_import: bool = True) -> list[dict]:
    """Return interop problems between the two ends (empty when they agree).

    `near` is the local connection; `far` is the paired peer. When `near_is_import`
    the local side is treated as authoritative (remediation targets the far end).
    """
    out: list[dict] = []
    p1n, p1f = near.phase1, far.phase1
    p2n, p2f = near.phase2, far.phase2
    checks = [
        ("IKE version", p1n.ike_version, p1f.ike_version),
        ("Phase 1 encryption", p1n.encryption, p1f.encryption),
        ("Phase 1 integrity", p1n.integrity, p1f.integrity),
        ("Phase 1 DH group", p1n.dh_group, p1f.dh_group),
        ("Authentication method", p1n.auth_method, p1f.auth_method),
        ("Phase 2 encryption", p2n.encryption, p2f.encryption),
        ("Phase 2 integrity", p2n.integrity, p2f.integrity),
        ("Phase 2 PFS group", p2n.pfs_group, p2f.pfs_group),
    ]
    for field, a, b in checks:
        m = _cmp(field, a, b, near_is_import=near_is_import)
        if m:
            out.append(m)

    # Traffic selectors must mirror: my local == its remote, and vice versa.
    if sorted(near.local.protected_subnets) != sorted(far.remote.protected_subnets) \
            or sorted(near.remote.protected_subnets) != sorted(far.local.protected_subnets):
        out.append({
            "field": "Traffic selectors", "severity": "mismatch",
            "near": ", ".join(near.local.protected_subnets) + " / "
                    + ", ".join(near.remote.protected_subnets),
            "far": ", ".join(far.local.protected_subnets) + " / "
                   + ", ".join(far.remote.protected_subnets),
            "message": "Protected subnets don't mirror between the ends.",
            "remediation": "Each end's local subnets must equal the other's remote "
                           "subnets. Align the far end to mirror the imported side.",
        })

    # IKE identities should cross-match for the tunnel to authenticate.
    if near.local.id and far.remote.id and near.local.id != far.remote.id:
        out.append({"field": "IKE identity (local↔peer-remote)", "severity": "mismatch",
                    "near": near.local.id, "far": far.remote.id,
                    "message": f"This end's local ID {near.local.id!r} != far end's "
                               f"remote ID {far.remote.id!r}.",
                    "remediation": f"Set the far end's remote-identity to {near.local.id!r}."})

    # Suboptimal (matching) crypto — surface once, referencing the shared value.
    for w in rate_proposal(p1n.encryption, p1n.integrity, p1n.dh_group, p1n.ike_version):
        if str(p1n.encryption) == str(p1f.encryption) and w["kind"] == "encryption":
            out.append({"field": "Phase 1 encryption", "severity": "suboptimal",
                        "near": p1n.encryption, "far": p1f.encryption,
                        "message": w["message"],
                        "remediation": "Both ends agree but this is weak — consider "
                                       "upgrading both to aes-256-gcm."})
            break
    return out
