"""Optional BGP-over-tunnel configuration, appended to the VPN config when
enabled. Only platforms that support BGP emit config; others get a note.
"""
from __future__ import annotations

import ipaddress

from .model import VpnProfile

# Platforms with usable BGP support (pfSense via FRR).
BGP_VENDORS = {"juniper_srx", "cisco_firepower", "fortinet", "palo_alto",
               "mikrotik", "pfsense"}


def supports_bgp(vendor: str) -> bool:
    return vendor in BGP_VENDORS


def bgp_config(vendor: str, p: VpnProfile) -> str:
    if not p.bgp.enabled:
        return ""
    if vendor not in BGP_VENDORS:
        return (f"\n# NOTE: BGP requested but not supported on {vendor}; configure "
                "dynamic routing out-of-band or use static routes.")
    fn = _REGISTRY[vendor]
    return "\n" + fn(p)


def _mask(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return f"{net.network_address} {net.netmask}"
    except ValueError:
        return cidr


def _juniper(p: VpnProfile) -> str:
    b, n = p.bgp, p.name
    lines = [f"# ---- BGP over {n} ----",
             f"set routing-options autonomous-system {b.local_as}",
             f"set protocols bgp group {n}-bgp type external",
             f"set protocols bgp group {n}-bgp peer-as {b.peer_as}",
             f"set protocols bgp group {n}-bgp neighbor {b.peer_ip}"]
    if b.local_ip:
        lines.append(f"set protocols bgp group {n}-bgp local-address {b.local_ip}")
    for net in b.networks:
        lines.append(f"set policy-options policy-statement {n}-adv term t1 from route-filter "
                     f"{net} exact")
    return "\n".join(lines)


def _cisco(p: VpnProfile) -> str:
    b = p.bgp
    lines = [f"! ---- BGP over {p.name} ----",
             f"router bgp {b.local_as}",
             f" neighbor {b.peer_ip} remote-as {b.peer_as}",
             " address-family ipv4",
             f"  neighbor {b.peer_ip} activate"]
    for net in b.networks:
        lines.append(f"  network {_mask(net)}")
    lines.append(" exit-address-family")
    return "\n".join(lines)


def _fortinet(p: VpnProfile) -> str:
    b = p.bgp
    lines = ["config router bgp", f"    set as {b.local_as}",
             "    config neighbor", f'        edit "{b.peer_ip}"',
             f"            set remote-as {b.peer_as}", "        next", "    end"]
    if b.networks:
        lines.append("    config network")
        for i, net in enumerate(b.networks, 1):
            lines += [f"        edit {i}", f"            set prefix {_mask(net)}", "        next"]
        lines.append("    end")
    lines.append("end")
    return "\n".join(lines)


def _palo(p: VpnProfile) -> str:
    b, n = p.bgp, p.name
    vr = "set network virtual-router default protocol bgp"
    lines = [f"# ---- BGP over {n} ----",
             f"{vr} enable yes", f"{vr} router-id {b.local_ip or b.peer_ip}",
             f"{vr} local-as {b.local_as}",
             f"{vr} peer-group {n}-pg peer {n}-peer peer-as {b.peer_as}",
             f"{vr} peer-group {n}-pg peer {n}-peer peer-address ip {b.peer_ip}"]
    return "\n".join(lines)


def _mikrotik(p: VpnProfile) -> str:
    b, n = p.bgp, p.name
    lines = [f"# ---- BGP over {n} (RouterOS v7) ----",
             f"/routing bgp connection add name={n}-bgp remote.address={b.peer_ip} "
             f"remote.as={b.peer_as} local.role=ebgp as={b.local_as}"
             + (f" local.address={b.local_ip}" if b.local_ip else "")]
    for net in b.networks:
        lines.append(f"/routing bgp advertisements ... network={net}  # advertise {net}")
    return "\n".join(lines)


def _pfsense(p: VpnProfile) -> str:
    b = p.bgp
    lines = [f"# ---- FRR BGP over {p.name} (pfSense: Services > FRR) ----",
             f"router bgp {b.local_as}",
             f" neighbor {b.peer_ip} remote-as {b.peer_as}",
             " address-family ipv4 unicast",
             f"  neighbor {b.peer_ip} activate"]
    for net in b.networks:
        lines.append(f"  network {net}")
    lines.append(" exit-address-family")
    return "\n".join(lines)


_REGISTRY = {
    "juniper_srx": _juniper,
    "cisco_firepower": _cisco,
    "fortinet": _fortinet,
    "palo_alto": _palo,
    "mikrotik": _mikrotik,
    "pfsense": _pfsense,
}
