#!/usr/bin/env python3
from __future__ import annotations

from lab.config import LabSettings
from lab.network import HostRecord, interface_on_subnet, scan_subnet
from mitm.attacks import ArpPoisoner, DnsSpoofer


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
