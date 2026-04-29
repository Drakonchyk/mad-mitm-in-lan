#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LAB_CONF_PATH = REPO_ROOT / "lab.conf"
VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass(frozen=True)
class LabSettings:
    raw: dict[str, str]
    lab_name: str
    lab_subnet: IPv4Network
    gateway_ip: IPv4Address
    dns_server: IPv4Address
    detector_domains: tuple[str, ...]


def _expand(value: str, values: dict[str, str]) -> str:
    def replacer(match: re.Match[str]) -> str:
        name = match.group(1)
        return values.get(name, match.group(0))

    return VAR_RE.sub(replacer, value)


def load_lab_config(path: Path = LAB_CONF_PATH) -> dict[str, str]:
    values: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value.startswith('"') and raw_value.endswith('"'):
            raw_value = raw_value[1:-1]

        values[key] = _expand(raw_value, values)

    return values


def load_lab_settings(path: Path = LAB_CONF_PATH) -> LabSettings:
    values = load_lab_config(path)
    return LabSettings(
        raw=values,
        lab_name=values["LAB_NAME"],
        lab_subnet=ip_network(values["LAB_SUBNET"], strict=False),
        gateway_ip=ip_address(values["GATEWAY_IP"]),
        dns_server=ip_address(values["DNS_SERVER"]),
        detector_domains=tuple(domain for domain in values["DETECTOR_DOMAINS"].split() if domain),
    )
