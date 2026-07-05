"""IKE/IPSec algorithm catalog with security ratings and insecure-use warnings.

`Security` ranks each algorithm. When a connection profile uses anything rated
`weak` or `broken`, the generator surfaces a warning (and can refuse in strict
mode). Ratings reflect current guidance (NIST SP 800-77r1, RFC 8221/8247).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Security(str, enum.Enum):
    broken = "broken"      # do not use — cryptographically broken
    weak = "weak"          # deprecated / insufficient margin
    acceptable = "acceptable"
    strong = "strong"


@dataclass(frozen=True)
class Algo:
    name: str                 # canonical id used internally
    security: Security
    note: str = ""
    # per-vendor keyword mapping (how each platform spells this algorithm)
    vendor: dict = field(default_factory=dict)


# --- IKE (phase 1) auth/PRF & encryption & DH groups ----------------------- #
ENCRYPTION = {
    "des": Algo("des", Security.broken, "56-bit DES — trivially broken",
                {"juniper_srx": "des-cbc", "cisco_firepower": "des", "fortinet": "des",
                 "palo_alto": "des"}),
    "3des": Algo("3des", Security.weak, "Sweet32; deprecated",
                 {"juniper_srx": "3des-cbc", "digi": "3des", "cradlepoint": "3des",
                  "pfsense": "3des", "cisco_firepower": "3des", "fortinet": "3des",
                  "palo_alto": "3des"}),
    "aes-128-cbc": Algo("aes-128-cbc", Security.acceptable, "",
                        {"juniper_srx": "aes-128-cbc", "digi": "aes128",
                         "cradlepoint": "aes128", "pfsense": "aes128",
                         "cisco_firepower": "aes", "fortinet": "aes128",
                         "palo_alto": "aes-128-cbc"}),
    "aes-192-cbc": Algo("aes-192-cbc", Security.acceptable, "",
                        {"juniper_srx": "aes-192-cbc", "pfsense": "aes192",
                         "cisco_firepower": "aes-192", "fortinet": "aes192",
                         "palo_alto": "aes-192-cbc"}),
    "aes-256-cbc": Algo("aes-256-cbc", Security.strong, "",
                        {"juniper_srx": "aes-256-cbc", "digi": "aes256",
                         "cradlepoint": "aes256", "pfsense": "aes256",
                         "cisco_firepower": "aes-256", "fortinet": "aes256",
                         "palo_alto": "aes-256-cbc"}),
    "aes-128-gcm": Algo("aes-128-gcm", Security.strong, "AEAD",
                        {"juniper_srx": "aes-128-gcm", "digi": "aes128gcm",
                         "pfsense": "aes128gcm16", "cisco_firepower": "aes-gcm",
                         "fortinet": "aes128gcm", "palo_alto": "aes-128-gcm"}),
    "aes-256-gcm": Algo("aes-256-gcm", Security.strong, "AEAD, preferred",
                        {"juniper_srx": "aes-256-gcm", "digi": "aes256gcm",
                         "cradlepoint": "aes256gcm", "pfsense": "aes256gcm16",
                         "cisco_firepower": "aes-gcm-256", "fortinet": "aes256gcm",
                         "palo_alto": "aes-256-gcm"}),
}

INTEGRITY = {
    "md5": Algo("md5", Security.broken, "MD5 — broken",
                {"juniper_srx": "md5", "digi": "md5", "pfsense": "md5",
                 "cisco_firepower": "md5", "fortinet": "md5", "palo_alto": "md5"}),
    "sha1": Algo("sha1", Security.weak, "SHA-1 — deprecated",
                 {"juniper_srx": "sha1", "digi": "sha1", "cradlepoint": "sha1",
                  "pfsense": "sha1", "cisco_firepower": "sha", "fortinet": "sha1",
                  "palo_alto": "sha1"}),
    "sha256": Algo("sha256", Security.strong, "",
                   {"juniper_srx": "sha-256", "digi": "sha256", "cradlepoint": "sha256",
                    "pfsense": "sha256", "cisco_firepower": "sha256", "fortinet": "sha256",
                    "palo_alto": "sha256"}),
    "sha384": Algo("sha384", Security.strong, "",
                   {"juniper_srx": "sha-384", "digi": "sha384", "cradlepoint": "sha384",
                    "pfsense": "sha384", "cisco_firepower": "sha384", "fortinet": "sha384",
                    "palo_alto": "sha384"}),
    "sha512": Algo("sha512", Security.strong, "",
                   {"juniper_srx": "sha-512", "digi": "sha512", "pfsense": "sha512",
                    "cisco_firepower": "sha512", "fortinet": "sha512",
                    "palo_alto": "sha512"}),
}

# DH / PFS groups
DH_GROUPS = {
    "1": Algo("1", Security.broken, "MODP-768 — broken",
              {"juniper_srx": "group1", "pfsense": "modp768", "cisco_firepower": "1",
               "palo_alto": "group1"}),
    "2": Algo("2", Security.weak, "MODP-1024 — weak (Logjam)",
              {"juniper_srx": "group2", "pfsense": "modp1024", "cisco_firepower": "2",
               "fortinet": "2", "palo_alto": "group2"}),
    "5": Algo("5", Security.weak, "MODP-1536 — weak",
              {"juniper_srx": "group5", "pfsense": "modp1536", "cisco_firepower": "5",
               "fortinet": "5", "palo_alto": "group5"}),
    "14": Algo("14", Security.acceptable, "MODP-2048", {"juniper_srx": "group14",
               "digi": "14", "cradlepoint": "14", "pfsense": "modp2048",
               "cisco_firepower": "14", "fortinet": "14", "palo_alto": "group14"}),
    "15": Algo("15", Security.acceptable, "MODP-3072",
               {"juniper_srx": "group15", "pfsense": "modp3072", "cisco_firepower": "15",
                "fortinet": "15", "palo_alto": "group15"}),
    "16": Algo("16", Security.strong, "MODP-4096",
               {"juniper_srx": "group16", "pfsense": "modp4096", "cisco_firepower": "16",
                "fortinet": "16", "palo_alto": "group16"}),
    "19": Algo("19", Security.strong, "ECP-256", {"juniper_srx": "group19",
               "digi": "19", "cradlepoint": "19", "pfsense": "ecp256",
               "cisco_firepower": "19", "fortinet": "19", "palo_alto": "group19"}),
    "20": Algo("20", Security.strong, "ECP-384", {"juniper_srx": "group20",
               "digi": "20", "pfsense": "ecp384", "cisco_firepower": "20",
               "fortinet": "20", "palo_alto": "group20"}),
    "21": Algo("21", Security.strong, "ECP-521",
               {"juniper_srx": "group21", "pfsense": "ecp521", "cisco_firepower": "21",
                "fortinet": "21", "palo_alto": "group21"}),
}

# IKE version
IKE_VERSIONS = {"ikev1": Security.weak, "ikev2": Security.strong}


def _lookup(table: dict, key: str) -> Algo | None:
    return table.get(key.lower()) if key else None


def rate_proposal(enc: str, integ: str, dh: str, ikev: str = "ikev2") -> list[dict]:
    """Return a list of warnings for a proposal. Empty list == all-strong."""
    warnings: list[dict] = []

    def check(kind: str, algo: Algo | None, raw: str):
        if algo is None:
            warnings.append({"kind": kind, "value": raw, "severity": "unknown",
                             "message": f"Unknown {kind} '{raw}'"})
        elif algo.security in (Security.broken, Security.weak):
            warnings.append({"kind": kind, "value": raw, "severity": algo.security.value,
                             "message": f"{kind} {raw}: {algo.note}"})

    check("encryption", _lookup(ENCRYPTION, enc), enc)
    check("integrity", _lookup(INTEGRITY, integ), integ)
    check("dh-group", _lookup(DH_GROUPS, dh), dh)
    iv = IKE_VERSIONS.get((ikev or "").lower())
    if iv in (Security.broken, Security.weak):
        warnings.append({"kind": "ike-version", "value": ikev, "severity": "weak",
                         "message": f"{ikev} is deprecated; prefer IKEv2"})
    # AEAD (GCM) provides integrity itself; flag redundant/none-integrity combos loosely.
    return warnings


def vendor_kw(table: dict, key: str, vendor: str) -> str:
    algo = _lookup(table, key)
    if not algo:
        return key
    return algo.vendor.get(vendor, algo.name)


_SEC_ORDER = {"strong": 0, "acceptable": 1, "weak": 2, "broken": 3}


def options() -> dict:
    """Ordered (strong-first) option lists for building rated <select> menus."""
    def opts(table):
        rows = [{"value": k, "security": a.security.value, "note": a.note}
                for k, a in table.items()]
        return sorted(rows, key=lambda o: (_SEC_ORDER[o["security"]], o["value"]))

    return {
        "encryption": opts(ENCRYPTION),
        "integrity": opts(INTEGRITY),
        "dh_groups": opts(DH_GROUPS),
        "ike_versions": [{"value": k, "security": v.value}
                         for k, v in sorted(IKE_VERSIONS.items(),
                                            key=lambda kv: _SEC_ORDER[kv[1].value])],
        "auth_methods": [{"value": "certificate", "security": "strong"},
                         {"value": "psk", "security": "weak"}],
    }


def catalog() -> dict:
    """Machine-readable catalog for the UI (defaults editor + warnings legend)."""
    def dump(t):
        return {k: {"security": a.security.value, "note": a.note} for k, a in t.items()}
    return {
        "encryption": dump(ENCRYPTION),
        "integrity": dump(INTEGRITY),
        "dh_groups": dump(DH_GROUPS),
        "ike_versions": {k: v.value for k, v in IKE_VERSIONS.items()},
    }
