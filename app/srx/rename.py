"""Generate the syntax to rename a VPN connection's objects in place on a device.

Renaming a connection in VCM changes every object whose name embeds the tunnel
name. Where a platform supports an atomic rename, we emit those commands; where it
doesn't (ASA-style), we emit delete/re-create guidance referencing the freshly
generated config for the new name.
"""
from __future__ import annotations

from .model import VpnProfile


def rename_config(vendor: str, profile: VpnProfile, old: str, new: str) -> str:
    fn = _REGISTRY.get(vendor)
    if not fn:
        return f"# No rename template for vendor '{vendor}'."
    return fn(profile, old, new)


def _juniper(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- Juniper SRX: rename VPN {o} -> {n} (commit after) ----",
        f"rename security ike proposal ike-prop-{o} to ike-prop-{n}",
        f"rename security ike policy ike-pol-{o} to ike-pol-{n}",
        f"rename security ike gateway gw-{o} to gw-{n}",
        f"rename security ipsec proposal ipsec-prop-{o} to ipsec-prop-{n}",
        f"rename security ipsec policy ipsec-pol-{o} to ipsec-pol-{n}",
        f"rename security ipsec vpn vpn-{o} to vpn-{n}",
    ])


def _fortinet(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- FortiGate: rename tunnel {o} -> {n} ----",
        "config vpn ipsec phase1-interface", f"    rename {o} to {n}", "end",
        "config vpn ipsec phase2-interface", f"    rename {o} to {n}", "end",
    ])


def _palo(p: VpnProfile, o: str, n: str) -> str:
    b = "rename network ike crypto-profiles"
    return "\n".join([
        f"# ---- Palo Alto (PAN-OS): rename {o} -> {n} (commit after) ----",
        f"{b} ike-crypto-profiles {o}-ike to {n}-ike",
        f"{b} ipsec-crypto-profiles {o}-ipsec to {n}-ipsec",
        f"rename network ike gateway {o}-gw to {n}-gw",
        f"rename network tunnel ipsec {o} to {n}",
    ])


def _mikrotik(p: VpnProfile, o: str, n: str) -> str:
    # RouterOS references objects by internal id, so renaming keeps bindings intact.
    return "\n".join([
        f"# ---- MikroTik RouterOS: rename {o} -> {n} ----",
        f"/ip ipsec profile set [find name={o}] name={n}",
        f"/ip ipsec proposal set [find name={o}] name={n}",
        f"/ip ipsec peer set [find name={o}] name={n}",
    ])


def _swanctl(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- strongSwan/pfSense (swanctl): rename {o} -> {n} ----",
        f"# Edit swanctl.conf: rename the block  connections {{ {o} {{ ... }} }}  to  {n},",
        f"# rename its child SA ({o} -> {n}) and any secrets id, then reload:",
        "swanctl --load-conns",
        "swanctl --terminate --ike " + o + "   # drop the old SA if still up",
    ])


def _digi(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- Digi: no in-place rename; re-create as {n} and remove {o} ----",
        f"# 1) Apply the newly generated config (tunnel named {n}).",
        f"ipsec {o} enable off",
        f"# 2) Optionally delete the old tunnel {o} from the device config.",
    ])


def _cradlepoint(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- Cradlepoint NCOS: copy to {n} then delete {o} ----",
        f"# 1) Apply the newly generated config (vpn/tunnels/{n}/...).",
        f"config del vpn/tunnels/{o}",
    ])


def _cisco(p: VpnProfile, o: str, n: str) -> str:
    return "\n".join([
        f"# ---- Cisco Firepower/ASA: no atomic rename; re-create as {n} ----",
        f"# 1) Apply the newly generated config for {n} (proposal/acl/crypto map).",
        f"# 2) Repoint/replace the crypto map entry, then remove the old objects:",
        f"no crypto ipsec ikev2 ipsec-proposal {o}",
        f"no access-list {o}_acl",
        f"# (remove the old crypto map {o}_map entry once {n} is active)",
    ])


_REGISTRY = {
    "juniper_srx": _juniper,
    "fortinet": _fortinet,
    "palo_alto": _palo,
    "mikrotik": _mikrotik,
    "pfsense": _swanctl,
    "strongswan": _swanctl,
    "digi": _digi,
    "cradlepoint": _cradlepoint,
    "cisco_firepower": _cisco,
}
