from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from metrics.run_artifacts import (
    DETECTOR_STATE_EVENTS,
    detector_delta_path,
    detector_event_counter,
    load_json,
    load_jsonl,
    mean_or_none,
    parse_iperf_mbps,
    parse_time,
    parse_traffic_windows,
)
from scenarios.definitions import (
    MAIN_SCENARIOS,
    SCENARIO_ATTACK_TYPES,
    SCENARIO_LABELS,
)

RESTORATION_EVENTS = {
    "gateway_mac_restored",
    "single_gateway_mac_restored",
    "domain_resolution_restored",
}

COMPOSITION_SERIES = {
    "gateway_mac_changed": "Gateway MAC Changed",
    "multiple_gateway_macs_seen": "Multiple Gateway MACs",
    "icmp_redirects_seen": "ICMP Redirects",
    "rogue_dhcp_server_seen": "DHCP Spoof Server Seen",
    "dhcp_reply_from_untrusted_switch_port_seen": "DHCP Reply From Untrusted Port",
    "dhcp_binding_conflict_seen": "DHCP Binding Conflict",
    "domain_resolution_changed": "Domain Resolution Changed",
}

TOOL_LABELS = {
    "detector": "Detector",
    "zeek": "Zeek",
    "suricata": "Suricata",
}

TOOL_ORDER = ["detector", "zeek", "suricata"]

def path_rel(path: Path, output_dir: Path) -> str:
    return str(path.relative_to(output_dir))


def tool_alert_field(tool: str) -> str:
    return "detector_alerts_native" if tool == "detector" else f"{tool}_alerts"


def first_record_timestamp(
    records: list[dict[str, Any]],
    event_names: set[str],
    *,
    start: datetime | None = None,
    stop: datetime | None = None,
    spoofed_domains: set[str] | None = None,
) -> str | None:
    candidates: list[str] = []
    for record in records:
        event_name = record.get("event")
        if event_name not in event_names:
            continue
        if spoofed_domains and event_name in {"domain_resolution_changed", "domain_resolution_restored"}:
            if record.get("domain") not in spoofed_domains:
                continue
        ts = parse_time(record.get("ts"))
        if ts is None:
            continue
        if start is not None and ts < start:
            continue
        if stop is not None and ts > stop:
            continue
        candidates.append(record["ts"])
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda value: (parse_time(value).timestamp() if parse_time(value) is not None else float("inf")),
    )


def count_detector_events(
    records: list[dict[str, Any]],
    event_names: set[str],
    *,
    spoofed_domains: set[str] | None = None,
) -> int:
    total = 0
    for record in records:
        event_name = record.get("event")
        if event_name not in event_names:
            continue
        if spoofed_domains and event_name in {"domain_resolution_changed", "domain_resolution_restored"}:
            if record.get("domain") not in spoofed_domains:
                continue
        total += 1
    return total


def seconds_between(start_value: str | None, end_value: str | None) -> float | None:
    start = parse_time(start_value)
    end = parse_time(end_value)
    if start is None or end is None:
        return None
    return (end - start).total_seconds()


def row_mean(values: list[float | None]) -> float | None:
    return mean_or_none(values)


def format_float(value: float | None, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def run_dir_for_row(row: dict[str, Any]) -> Path:
    return Path(str(row["run_dir"]))


def attack_window_offsets(row: dict[str, Any]) -> list[tuple[float, float]]:
    start_offset = seconds_between(row.get("started_at"), row.get("attack_started_at"))
    stop_offset = seconds_between(row.get("started_at"), row.get("attack_stopped_at"))
    if start_offset is None or stop_offset is None:
        return []
    return [(start_offset, stop_offset)]


def detector_marker_offsets(row: dict[str, Any]) -> list[tuple[str, float]]:
    markers: list[tuple[str, float]] = []
    for label, timestamp in [
        ("Attack start", row.get("attack_started_at")),
        ("First detector alert", row.get("detector_first_alert_at")),
        ("First DNS alert", row.get("detector_first_dns_alert_at")),
        ("Attack stop", row.get("attack_stopped_at")),
    ]:
        offset = seconds_between(row.get("started_at"), timestamp)
        if offset is not None:
            markers.append((label, offset))
    return markers


def representative_row(
    rows: list[dict[str, Any]],
    preferred_scenarios: list[str],
    predicate: Any,
) -> dict[str, Any] | None:
    for scenario in preferred_scenarios:
        candidates = [row for row in rows_for_scenario(rows, scenario) if predicate(row)]
        if candidates:
            return sorted(candidates, key=lambda row: row["run_id"])[0]
    return None


def detector_alert_composition_totals(rows: list[dict[str, Any]]) -> dict[str, float]:
    return {
        "Gateway MAC Changed": float(sum(row["gateway_mac_changed"] for row in rows)),
        "Multiple Gateway MACs": float(sum(row["multiple_gateway_macs_seen"] for row in rows)),
        "ICMP Redirects": float(sum(row["icmp_redirects_seen"] for row in rows)),
        "Domain Resolution Changed": float(sum(row["domain_resolution_changed"] for row in rows)),
    }


def representative_probe_series(row: dict[str, Any]) -> tuple[list[float], dict[str, list[float]]] | None:
    meta = load_json(run_dir_for_row(row) / "run-meta.json")
    windows = parse_traffic_windows(
        run_dir_for_row(row) / "victim" / "traffic-window.txt",
        gateway_ip=meta.get("gateway_lab_ip"),
        attacker_ip=meta.get("attacker_ip"),
    )
    x_values: list[float] = []
    gateway_ping: list[float] = []
    attacker_ping: list[float] = []
    for window in windows:
        offset = seconds_between(row.get("started_at"), window.ts)
        if offset is None:
            continue
        x_values.append(offset)
        gateway_ping.append(window.ping_gateway_avg_ms if window.ping_gateway_avg_ms is not None else float("nan"))
        attacker_ping.append(window.ping_attacker_avg_ms if window.ping_attacker_avg_ms is not None else float("nan"))

    if not x_values:
        return None
    series = {
        "Gateway ping": gateway_ping,
        "Attacker ping": attacker_ping,
    }
    return x_values, series


def cumulative_detector_alert_series(row: dict[str, Any]) -> tuple[list[float], dict[str, list[float]]] | None:
    records = load_jsonl(detector_delta_path(run_dir_for_row(row)))
    offsets: list[float] = []
    for record in records:
        if record.get("event") not in DETECTOR_STATE_EVENTS:
            continue
        offset = seconds_between(row.get("started_at"), record.get("ts"))
        if offset is None:
            continue
        offsets.append(offset)
    offsets.sort()

    x_values = [0.0]
    cumulative_values = [0.0]
    count = 0.0
    for offset in offsets:
        count += 1.0
        x_values.append(offset)
        cumulative_values.append(count)

    duration = row.get("duration_seconds")
    if duration is not None:
        x_values.append(float(duration))
        cumulative_values.append(count)

    if len(x_values) <= 1:
        return None
    return x_values, {"Cumulative semantic alerts": cumulative_values}


def rows_for_scenario(rows: list[dict[str, Any]], scenario: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["scenario"] == scenario]


def available_scenarios(
    rows: list[dict[str, Any]],
    *,
    scenario_order: list[str],
    include_baseline: bool = True,
) -> list[str]:
    scenarios = [scenario for scenario in scenario_order if rows_for_scenario(rows, scenario)]
    if not include_baseline:
        scenarios = [scenario for scenario in scenarios if scenario != "baseline"]
    return scenarios
