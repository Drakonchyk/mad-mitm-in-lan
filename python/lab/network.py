#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
import socket
import subprocess

try:
    from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, get_if_list, srp
except ModuleNotFoundError as exc:
    ARP = Ether = conf = get_if_addr = get_if_hwaddr = get_if_list = srp = None
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None


IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


@dataclass(frozen=True)
class HostRecord:
    ip: str
    mac: str


def list_interfaces() -> list[str]:
    if SCAPY_IMPORT_ERROR is None:
        return sorted(get_if_list())
    return sorted(name for _, name in socket.if_nameindex())


def default_interface() -> str:
    if SCAPY_IMPORT_ERROR is None:
        return str(conf.iface)

    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )
    fields = result.stdout.split()
    if "dev" in fields:
        return fields[fields.index("dev") + 1]

    interfaces = [name for name in list_interfaces() if name != "lo"]
    return interfaces[0] if interfaces else "lo"


def require_scapy() -> None:
    if SCAPY_IMPORT_ERROR is not None:
        raise RuntimeError("Scapy is required for these lab research commands. Install python3-scapy.")


def default_gateway_ip() -> str:
    require_scapy()
    return conf.route.route("0.0.0.0")[2]


def interface_ipv4(interface: str) -> str:
    require_scapy()
    return get_if_addr(interface)


def interface_mac(interface: str) -> str:
    require_scapy()
    return get_if_hwaddr(interface).lower()


def interface_on_subnet(interface: str, subnet: str) -> bool:
    return ip_address(interface_ipv4(interface)) in ip_network(subnet, strict=False)


def resolve_mac(ip: str, interface: str, timeout: float = 2.0) -> str | None:
    require_scapy()
    packet = Ether(dst=BROADCAST_MAC) / ARP(pdst=ip)
    answered, _ = srp(packet, iface=interface, timeout=timeout, inter=0.2, verbose=False)
    for _, response in answered:
        return response.hwsrc.lower()
    return None


def scan_subnet(subnet: str, interface: str, timeout: float = 2.0) -> list[HostRecord]:
    require_scapy()
    packet = Ether(dst=BROADCAST_MAC) / ARP(pdst=subnet)
    answered, _ = srp(packet, iface=interface, timeout=timeout, inter=0.2, verbose=False)
    hosts = [
        HostRecord(ip=response.psrc, mac=response.hwsrc.lower())
        for _, response in answered
    ]
    return sorted(hosts, key=lambda host: ip_address(host.ip))


def ipv4_forwarding_enabled() -> bool:
    return IP_FORWARD_PATH.read_text(encoding="utf-8").strip() == "1"


def set_ipv4_forwarding(enabled: bool) -> None:
    IP_FORWARD_PATH.write_text("1\n" if enabled else "0\n", encoding="utf-8")
