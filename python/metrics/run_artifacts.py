#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
from statistics import mean, stdev
from typing import Any, Iterable


PING_RTT_RE = re.compile(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms")
CURL_TOTAL_RE = re.compile(r"time_total=([0-9.]+)")

DETECTOR_STATE_EVENTS = {
    "gateway_mac_changed",
    "gateway_mac_restored",
    "multiple_gateway_macs_seen",
    "single_gateway_mac_restored",
    "icmp_redirects_seen",
    "domain_resolution_changed",
    "domain_resolution_restored",
}

DETECTOR_PACKET_ALERT_EVENTS = {
    "arp_spoof_packet_seen",
    "icmp_redirect_packet_seen",
    "dns_spoof_packet_seen",
}


@dataclass(frozen=True)
class ProbeWindow:
    ts: str
    ping_gateway_avg_ms: float | None = None
    ping_attacker_avg_ms: float | None = None
    curl_total_s: float | None = None
    domains: dict[str, list[str]] = field(default_factory=dict)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_traffic_windows(
    path: Path,
    *,
    gateway_ip: str | None = None,
    attacker_ip: str | None = None,
) -> list[ProbeWindow]:
    windows: list[ProbeWindow] = []
    if not path.exists():
        return windows

    current: dict[str, Any] | None = None
    current_domain: str | None = None
    current_ping_target: str | None = None

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("ts="):
            if current is not None:
                windows.append(
                    ProbeWindow(
                        ts=current["ts"],
                        ping_gateway_avg_ms=current.get("ping_gateway_avg_ms"),
                        ping_attacker_avg_ms=current.get("ping_attacker_avg_ms"),
                        curl_total_s=current.get("curl_total_s"),
                        domains=current["domains"],
                    )
                )
            current = {
                "ts": line.removeprefix("ts="),
                "ping_gateway_avg_ms": None,
                "ping_attacker_avg_ms": None,
                "curl_total_s": None,
                "domains": {},
            }
            current_domain = None
            current_ping_target = None
            continue

        if current is None:
            continue

        if line.startswith("PING "):
            target_ip = ""
            parts = line.split()
            if len(parts) >= 2:
                target_ip = parts[1]
            current_ping_target = None
            if gateway_ip and target_ip == gateway_ip:
                current_ping_target = "gateway"
            elif attacker_ip and target_ip == attacker_ip:
                current_ping_target = "attacker"
            continue

        ping_match = PING_RTT_RE.search(line)
        if ping_match and current_ping_target:
            avg_value = float(ping_match.group(2))
            if current_ping_target == "gateway":
                current["ping_gateway_avg_ms"] = avg_value
            elif current_ping_target == "attacker":
                current["ping_attacker_avg_ms"] = avg_value
            current_ping_target = None
            continue

        if line.startswith("domain="):
            current_domain = line.removeprefix("domain=")
            current["domains"].setdefault(current_domain, [])
            continue

        if current_domain and all(ch.isdigit() or ch == "." for ch in line):
            current["domains"][current_domain].append(line)
            continue

        curl_match = CURL_TOTAL_RE.search(line)
        if curl_match:
            current["curl_total_s"] = float(curl_match.group(1))

    if current is not None:
        windows.append(
            ProbeWindow(
                ts=current["ts"],
                ping_gateway_avg_ms=current.get("ping_gateway_avg_ms"),
                ping_attacker_avg_ms=current.get("ping_attacker_avg_ms"),
                curl_total_s=current.get("curl_total_s"),
                domains=current["domains"],
            )
        )
    return windows


def parse_iperf_mbps(path: Path) -> float | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    bps = payload.get("end", {}).get("sum_received", {}).get("bits_per_second")
    if not bps:
        return None
    return float(bps) / 1_000_000.0


def parse_iperf_connection(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return (None, None)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return (None, None)

    connected = payload.get("start", {}).get("connected", [])
    if not connected:
        return (None, None)

    connection = connected[0]
    return (
        connection.get("local_host"),
        connection.get("remote_host"),
    )


def mean_or_none(values: Iterable[float | None]) -> float | None:
    clean = [value for value in values if value is not None]
    if not clean:
        return None
    return mean(clean)


def stddev_or_zero(values: Iterable[float | None]) -> float:
    clean = [value for value in values if value is not None]
    if len(clean) < 2:
        return 0.0
    return stdev(clean)


def detector_event_counter(records: Iterable[dict[str, Any]]) -> Counter[str]:
    return Counter(str(record.get("event", "unknown")) for record in records if isinstance(record, dict))
