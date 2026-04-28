#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from statistics import mean, stdev
from typing import Any, Iterable


PING_RTT_RE = re.compile(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms")
CURL_TOTAL_RE = re.compile(r"time_total=([0-9.]+)")
OVS_FLOW_PACKETS_RE = re.compile(r"\bn_packets=(\d+)")
OVS_FLOW_BYTES_RE = re.compile(r"\bn_bytes=(\d+)")

DETECTOR_STATE_EVENTS = {
    "gateway_mac_changed",
    "gateway_mac_restored",
    "multiple_gateway_macs_seen",
    "single_gateway_mac_restored",
    "icmp_redirects_seen",
    "domain_resolution_changed",
    "domain_resolution_restored",
    "rogue_dhcp_server_seen",
    "rogue_dhcp_server_cleared",
    "dhcp_binding_conflict_seen",
}

DETECTOR_PACKET_ALERT_EVENTS = {
    "arp_spoof_packet_seen",
    "icmp_redirect_packet_seen",
    "dns_spoof_packet_seen",
    "rogue_dhcp_server_seen",
    "dhcp_binding_conflict_seen",
    "dhcp_reply_from_untrusted_switch_port_seen",
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


def detector_artifact_dir(run_dir: Path) -> Path:
    detector_dir = run_dir / "detector"
    if detector_dir.exists():
        return detector_dir
    return run_dir / "victim"


def detector_delta_path(run_dir: Path) -> Path:
    return detector_artifact_dir(run_dir) / "detector.delta.jsonl"


def detector_state_path(run_dir: Path) -> Path:
    return detector_artifact_dir(run_dir) / "detector.state.json"


def detector_explained_path(run_dir: Path) -> Path:
    return detector_artifact_dir(run_dir) / "detector-explained.txt"


def zeek_artifact_dir(run_dir: Path) -> Path:
    for candidate in (run_dir / "zeek" / "host", run_dir / "zeek" / "victim"):
        if candidate.exists():
            return candidate
    return run_dir / "zeek" / "host"


def zeek_notice_path(run_dir: Path) -> Path:
    return zeek_artifact_dir(run_dir) / "notice.log"


def zeek_stats_path(run_dir: Path) -> Path:
    return zeek_artifact_dir(run_dir) / "stats.log"


def suricata_artifact_dir(run_dir: Path) -> Path:
    for candidate in (run_dir / "suricata" / "host", run_dir / "suricata" / "victim"):
        if candidate.exists():
            return candidate
    return run_dir / "suricata" / "host"


def suricata_eve_path(run_dir: Path) -> Path:
    return suricata_artifact_dir(run_dir) / "eve.json"


def suricata_stats_path(run_dir: Path) -> Path:
    return suricata_artifact_dir(run_dir) / "stats.log"


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_log_time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc)
        except ValueError:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def nested_number(payload: dict[str, Any], path: str) -> float | None:
    current: Any = payload
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    try:
        return float(current)
    except (TypeError, ValueError):
        return None


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


def parse_synthetic_traffic_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    summary: dict[str, Any] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("event") == "synthetic_traffic_finished":
            summary = payload
    return summary


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


def detector_throughput_summary(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    heartbeats = [
        record for record in records
        if isinstance(record, dict) and record.get("event") == "heartbeat"
    ]
    if not heartbeats:
        return {}

    def numeric_values(key: str) -> list[float]:
        values: list[float] = []
        for record in heartbeats:
            try:
                values.append(float(record[key]))
            except (KeyError, TypeError, ValueError):
                continue
        return values

    latest = heartbeats[-1]
    seen_pps = numeric_values("interval_seen_pps")
    processed_pps = numeric_values("interval_processed_pps")
    return {
        "packets_seen": latest.get("packets_seen", "-"),
        "packets_processed": latest.get("packets_processed", "-"),
        "packets_sampled_out": latest.get("packets_sampled_out", "-"),
        "max_interval_seen_pps": max(seen_pps) if seen_pps else None,
        "max_interval_processed_pps": max(processed_pps) if processed_pps else None,
        "latest_lifetime_seen_pps": latest.get("lifetime_seen_pps"),
        "latest_lifetime_processed_pps": latest.get("lifetime_processed_pps"),
        "avg_processing_ms": latest.get("avg_processing_ms"),
        "max_processing_ms": latest.get("max_processing_ms"),
    }


def load_zeek_log_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    fields: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                records.append(payload)
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue
        values = line.split("\t")
        records.append(dict(zip(fields, values)))
    return records


def zeek_throughput_summary(path: Path) -> dict[str, Any]:
    records = [
        record for record in load_zeek_log_records(path)
        if parse_log_time(record.get("ts")) is not None
    ]
    if not records:
        return {}

    records.sort(key=lambda record: parse_log_time(record.get("ts")) or datetime.max.replace(tzinfo=timezone.utc))
    timestamps = [parse_log_time(record.get("ts")) for record in records]
    interval_hints: list[float] = []
    for previous, current in zip(timestamps, timestamps[1:]):
        if previous is None or current is None:
            continue
        delta = (current - previous).total_seconds()
        if delta > 0:
            interval_hints.append(delta)
    fallback_interval = mean(interval_hints) if interval_hints else None

    processed_pps: list[float] = []
    seen_pps: list[float] = []
    dropped_packets = 0.0
    processed_packets = 0.0
    seen_packets = 0.0

    for index, record in enumerate(records):
        interval = None
        if index > 0 and timestamps[index - 1] is not None and timestamps[index] is not None:
            interval = (timestamps[index] - timestamps[index - 1]).total_seconds()
        elif len(timestamps) > 1 and timestamps[0] is not None and timestamps[1] is not None:
            interval = (timestamps[1] - timestamps[0]).total_seconds()
        if interval is None or interval <= 0:
            interval = fallback_interval

        processed = nested_number(record, "pkts_proc") or 0.0
        seen = nested_number(record, "pkts_link")
        dropped = nested_number(record, "pkts_dropped") or 0.0
        processed_packets += processed
        seen_packets += seen if seen is not None else processed
        dropped_packets += dropped
        if interval and interval > 0:
            processed_pps.append(processed / interval)
            seen_pps.append((seen if seen is not None else processed) / interval)

    return {
        "packets_seen": int(seen_packets),
        "packets_processed": int(processed_packets),
        "packets_dropped": int(dropped_packets),
        "max_interval_seen_pps": max(seen_pps) if seen_pps else None,
        "max_interval_processed_pps": max(processed_pps) if processed_pps else None,
        "latest_lifetime_seen_pps": None,
        "latest_lifetime_processed_pps": None,
    }


def suricata_throughput_summary(eve_path: Path) -> dict[str, Any]:
    stats_records = [
        record for record in load_jsonl(eve_path)
        if record.get("event_type") == "stats" and isinstance(record.get("stats"), dict)
    ]
    if not stats_records:
        return {}

    stats_records.sort(key=lambda record: parse_log_time(record.get("timestamp")) or datetime.max.replace(tzinfo=timezone.utc))
    latest = stats_records[-1]
    latest_stats = latest.get("stats", {})
    packets_processed = nested_number(latest_stats, "decoder.pkts")
    packets_seen = (
        nested_number(latest_stats, "capture.kernel_packets")
        or nested_number(latest_stats, "capture.kernel_packets_delta")
        or packets_processed
    )
    packets_dropped = nested_number(latest_stats, "capture.kernel_drops") or 0.0

    processed_pps: list[float] = []
    seen_pps: list[float] = []
    for previous, current in zip(stats_records, stats_records[1:]):
        previous_ts = parse_log_time(previous.get("timestamp"))
        current_ts = parse_log_time(current.get("timestamp"))
        if previous_ts is None or current_ts is None:
            continue
        interval = (current_ts - previous_ts).total_seconds()
        if interval <= 0:
            continue
        previous_stats = previous.get("stats", {})
        current_stats = current.get("stats", {})
        current_processed = nested_number(current_stats, "decoder.pkts")
        previous_processed = nested_number(previous_stats, "decoder.pkts")
        current_seen = nested_number(current_stats, "capture.kernel_packets") or current_processed
        previous_seen = nested_number(previous_stats, "capture.kernel_packets") or previous_processed
        if current_processed is not None and previous_processed is not None:
            processed_pps.append(max(current_processed - previous_processed, 0.0) / interval)
        if current_seen is not None and previous_seen is not None:
            seen_pps.append(max(current_seen - previous_seen, 0.0) / interval)

    uptime = nested_number(latest_stats, "uptime")
    if uptime and uptime > 0:
        if not processed_pps and packets_processed is not None:
            processed_pps.append(packets_processed / uptime)
        if not seen_pps and packets_seen is not None:
            seen_pps.append(packets_seen / uptime)

    return {
        "packets_seen": int(packets_seen) if packets_seen is not None else "-",
        "packets_processed": int(packets_processed) if packets_processed is not None else "-",
        "packets_dropped": int(packets_dropped),
        "max_interval_seen_pps": max(seen_pps) if seen_pps else None,
        "max_interval_processed_pps": max(processed_pps) if processed_pps else None,
        "latest_lifetime_seen_pps": (packets_seen / uptime) if packets_seen is not None and uptime and uptime > 0 else None,
        "latest_lifetime_processed_pps": (packets_processed / uptime) if packets_processed is not None and uptime and uptime > 0 else None,
    }


def parse_ovs_dhcp_snooping_stats(path: Path) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "available": False,
        "mode": "n/a",
        "flows": 0,
        "packets": 0,
        "bytes": 0,
        "packets_by_action": {},
    }
    if not path.exists():
        return stats

    action_packets: Counter[str] = Counter()
    stats["available"] = True
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("mode="):
            stats["mode"] = line.removeprefix("mode=")
            continue
        if "priority=300" not in line or "tp_src=67" not in line or "tp_dst=68" not in line:
            continue

        packet_match = OVS_FLOW_PACKETS_RE.search(line)
        byte_match = OVS_FLOW_BYTES_RE.search(line)
        packets = int(packet_match.group(1)) if packet_match else 0
        byte_count = int(byte_match.group(1)) if byte_match else 0
        action = line.split("actions=", 1)[1].strip() if "actions=" in line else "unknown"

        stats["flows"] = int(stats["flows"]) + 1
        stats["packets"] = int(stats["packets"]) + packets
        stats["bytes"] = int(stats["bytes"]) + byte_count
        action_packets[action] += packets

    stats["packets_by_action"] = dict(action_packets)
    return stats


def parse_ovs_switch_truth_snooping_stats(path: Path) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "available": False,
        "enabled": "n/a",
        "flows": 0,
        "packets": 0,
        "bytes": 0,
        "packets_by_type": {},
        "packets_by_action": {},
    }
    if not path.exists():
        return stats

    type_packets: Counter[str] = Counter()
    action_packets: Counter[str] = Counter()
    stats["available"] = True
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("enabled="):
            stats["enabled"] = line.removeprefix("enabled=")
            continue
        if "priority=290" not in line:
            continue

        if "arp" in line and "arp_spa=" in line:
            attack_type = "arp_spoof"
        elif "tp_src=53" in line or "udp,tp_src=53" in line:
            attack_type = "dns_source_violation"
        else:
            continue

        packet_match = OVS_FLOW_PACKETS_RE.search(line)
        byte_match = OVS_FLOW_BYTES_RE.search(line)
        packets = int(packet_match.group(1)) if packet_match else 0
        byte_count = int(byte_match.group(1)) if byte_match else 0
        action = line.split("actions=", 1)[1].strip() if "actions=" in line else "unknown"

        stats["flows"] = int(stats["flows"]) + 1
        stats["packets"] = int(stats["packets"]) + packets
        stats["bytes"] = int(stats["bytes"]) + byte_count
        type_packets[attack_type] += packets
        action_packets[action] += packets

    stats["packets_by_type"] = dict(type_packets)
    stats["packets_by_action"] = dict(action_packets)
    return stats
