#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lab.config import load_lab_config, load_lab_settings


@dataclass(frozen=True)
class LabTemplateRenderer:
    repo_root: Path
    config: dict[str, str]
    detector_domains: list[str]
    attacker_ip: str
    victim_ip: str
    lab_subnet: str

    @classmethod
    def from_repo_root(
        cls,
        repo_root: Path,
        *,
        attacker_ip: str | None = None,
        victim_ip: str | None = None,
    ) -> "LabTemplateRenderer":
        config = load_lab_config(repo_root / "lab.conf")
        settings = load_lab_settings(repo_root / "lab.conf")
        return cls(
            repo_root=repo_root,
            config=config,
            detector_domains=list(settings.detector_domains),
            attacker_ip=attacker_ip or str(settings.attacker_ip),
            victim_ip=victim_ip or str(settings.victim_ip),
            lab_subnet=str(settings.lab_subnet),
        )

    def render_detector_text(self) -> str:
        domain_list = ", ".join(repr(domain) for domain in self.detector_domains)
        source = (self.repo_root / "python" / "detector" / "live.py").read_text(encoding="utf-8")
        return (
            source.replace("__GATEWAY_IP__", self.config["GATEWAY_IP"])
            .replace("__DNS_SERVER__", self.config["DNS_SERVER"])
            .replace("__ATTACKER_IP__", "")
            .replace("__VICTIM_IP__", "")
            .replace("__LAB_SUBNET__", self.lab_subnet)
            .replace("__PYTHON_DOMAIN_LIST__", domain_list)
        )

    def render_zeek_policy_text(self) -> str:
        domains = ", ".join(f'"{domain.lower()}"' for domain in self.config["DETECTOR_DOMAINS"].split() if domain)
        source = (self.repo_root / "config" / "mitm-lab-live.zeek").read_text(encoding="utf-8")
        return (
            source.replace("__GATEWAY_IP__", self.config["GATEWAY_IP"])
            .replace("__DNS_SERVER__", self.config["DNS_SERVER"])
            .replace("__ATTACKER_IP__", self.attacker_ip)
            .replace("__VICTIM_IP__", self.victim_ip)
            .replace("__ATTACKER_MAC__", self.config["ATTACKER_MAC"].lower())
            .replace("__GATEWAY_MAC__", self.config["GATEWAY_LAB_MAC"].lower())
            .replace("__ZEEK_DOMAIN_SET__", domains)
        )

    def write_detector(self, output_path: Path) -> None:
        output_path.write_text(self.render_detector_text(), encoding="utf-8")

    def write_zeek_policy(self, output_path: Path) -> None:
        output_path.write_text(self.render_zeek_policy_text(), encoding="utf-8")
