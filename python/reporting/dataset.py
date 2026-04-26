from __future__ import annotations

import csv
import json
from pathlib import Path
from datetime import timedelta
from typing import Any

from metrics.core import load_or_evaluate_single_run
from metrics.aggregate import event_recall
from metrics.parsers import find_run_dirs
from metrics.run_artifacts import (
    DETECTOR_STATE_EVENTS,
    detector_delta_path,
    detector_event_counter,
    load_json,
    load_jsonl,
    parse_iperf_mbps,
    parse_time,
    parse_traffic_windows,
)
from reporting.common import (
    RESTORATION_EVENTS,
    TOOL_LABELS,
    count_detector_events,
    first_record_timestamp,
    row_mean,
    rows_for_scenario,
    seconds_between,
)
from scenarios.definitions import (
    DETECTOR_DETECTION_EVENTS,
    SCENARIO_ATTACK_TYPES,
    scenario_sort_key,
    selected_scenarios,
)

def limit_rows_per_scenario(rows: list[dict[str, Any]], max_runs_per_scenario: int | None) -> list[dict[str, Any]]:
    if max_runs_per_scenario is None or max_runs_per_scenario <= 0:
        return rows

    limited: list[dict[str, Any]] = []
    for scenario in sorted({row["scenario"] for row in rows}, key=scenario_sort_key):
        scenario_rows = sorted(rows_for_scenario(rows, scenario), key=lambda row: row["run_id"], reverse=True)
        limited.extend(reversed(scenario_rows[:max_runs_per_scenario]))
    return limited


def _safe_load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = load_json(path)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _dhcp_lease_observations(run_dir: Path) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for path in [
        run_dir / "gateway" / "dhcp-leases-before.json",
        run_dir / "gateway" / "dhcp-leases-before-cleanup.json",
        run_dir / "gateway" / "dhcp-leases-after-cleanup.json",
    ]:
        payload = _safe_load_json(path)
        if payload:
            observations.append(payload)
    observations.extend(load_jsonl(run_dir / "gateway" / "dhcp-lease-monitor.stdout"))
    return [item for item in observations if isinstance(item.get("pool_total"), int)]


def _first_timestamp(records: list[dict[str, Any]], event_names: set[str]) -> str | None:
    values = [str(record["ts"]) for record in records if record.get("event") in event_names and record.get("ts")]
    return min(values) if values else None


def _timestamp_at_offset(started_at: str | None, offset: Any) -> str | None:
    started = parse_time(started_at)
    if started is None or offset in (None, ""):
        return None
    try:
        return (started + timedelta(seconds=float(offset))).isoformat()
    except (TypeError, ValueError):
        return None


def _dhcp_campaign_metrics(run_dir: Path, meta: dict[str, Any]) -> dict[str, Any]:
    observations = _dhcp_lease_observations(run_dir)
    pool_total = max((int(item.get("pool_total") or 0) for item in observations), default=None)
    max_taken = max((int(item.get("taken") or 0) for item in observations), default=None)
    max_attack_taken = max((int(item.get("attack_taken") or 0) for item in observations), default=None)
    min_free = min((int(item.get("free") or 0) for item in observations), default=None)
    pool_full_at = None
    for item in sorted(observations, key=lambda record: str(record.get("ts", ""))):
        total = int(item.get("pool_total") or 0)
        taken = int(item.get("taken") or 0)
        free = int(item.get("free") or total)
        if total > 0 and (free <= 0 or taken >= total):
            pool_full_at = str(item.get("ts"))
            break

    rogue_records = load_jsonl(run_dir / "attacker" / "dhcp-spoof.stdout")
    takeover_records = load_jsonl(run_dir / "victim" / "dhcp-takeover-probe.stdout")
    first_rogue_at = _first_timestamp(rogue_records, {"rogue_dhcp_offer", "rogue_dhcp_ack"})
    takeover_started_at = _first_timestamp(takeover_records, {"dhcp_takeover_renew_started"})
    rogue_started_at = _timestamp_at_offset(meta.get("started_at"), meta.get("rogue_dhcp_start_offset_seconds"))
    if rogue_started_at is None and meta.get("takeover_start_mode") == "pool-full":
        rogue_started_at = pool_full_at
    takeover_success_records = [
        record
        for record in takeover_records
        if record.get("event") == "dhcp_takeover_renew_finished"
        and bool(record.get("takeover_observed"))
        and record.get("ts")
    ]
    takeover_finished_records = [
        record
        for record in takeover_records
        if record.get("event") == "dhcp_takeover_renew_finished"
        and record.get("ts")
    ]
    takeover_success_at = min((str(record["ts"]) for record in takeover_success_records), default=None)
    takeover_finished_at = takeover_success_at or min((str(record["ts"]) for record in takeover_finished_records), default=None)
    takeover_success = takeover_success_at is not None

    return {
        "dhcp_pool_total": pool_total,
        "dhcp_pool_taken_max": max_taken,
        "dhcp_attack_leases_max": max_attack_taken,
        "dhcp_pool_free_min": min_free,
        "dhcp_pool_full_at": pool_full_at,
        "dhcp_pool_full_seconds_from_run_start": seconds_between(meta.get("started_at"), pool_full_at),
        "dhcp_pool_full_seconds_from_attack_start": seconds_between(meta.get("attack_started_at"), pool_full_at),
        "dhcp_rogue_started_at": rogue_started_at,
        "dhcp_rogue_first_event_at": first_rogue_at,
        "dhcp_rogue_first_event_seconds_from_rogue_start": seconds_between(rogue_started_at, first_rogue_at),
        "dhcp_takeover_renew_started_at": takeover_started_at,
        "dhcp_takeover_finished_at": takeover_finished_at,
        "dhcp_takeover_success_at": takeover_success_at,
        "dhcp_takeover_success": takeover_success,
        "dhcp_takeover_seconds_from_rogue_start": seconds_between(rogue_started_at, takeover_finished_at),
        "dhcp_takeover_seconds_from_pool_full": seconds_between(pool_full_at, takeover_finished_at),
    }


def build_rows(target: Path, include_warmups: bool, *, use_cache: bool = True, profile: str = "main") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    allowed_scenarios = set(selected_scenarios(profile))
    for run_dir in find_run_dirs(target):
        meta_path = run_dir / "run-meta.json"
        if not meta_path.exists():
            continue
        meta = load_json(meta_path)
        scenario = str(meta.get("scenario", run_dir.name))
        if scenario not in allowed_scenarios:
            continue
        if bool(meta.get("warmup", False)) and not include_warmups:
            continue

        evaluation = load_or_evaluate_single_run(run_dir, use_cache=use_cache)
        detector_records = load_jsonl(detector_delta_path(run_dir))
        detector_counts = detector_event_counter(detector_records)
        spoofed_domains = {str(domain) for domain in meta.get("spoofed_domains", []) if domain}
        attack_start = parse_time(meta.get("attack_started_at"))
        attack_stop = parse_time(meta.get("attack_stopped_at"))
        mitigation_start = parse_time(meta.get("mitigation_started_at"))

        detector_first_alert_at = first_record_timestamp(
            detector_records,
            DETECTOR_DETECTION_EVENTS.get(scenario, set()),
            start=attack_start,
            stop=attack_stop,
            spoofed_domains=spoofed_domains or None,
        )
        detector_first_arp_alert_at = first_record_timestamp(
            detector_records,
            {"gateway_mac_changed", "multiple_gateway_macs_seen", "icmp_redirects_seen"},
            start=attack_start,
            stop=attack_stop,
        )
        detector_first_dns_alert_at = first_record_timestamp(
            detector_records,
            {"domain_resolution_changed"},
            start=attack_start,
            stop=attack_stop,
            spoofed_domains=spoofed_domains or None,
        )
        detector_first_recovery_at = first_record_timestamp(
            detector_records,
            RESTORATION_EVENTS,
            start=mitigation_start,
            spoofed_domains=spoofed_domains or None,
        )

        probe_windows = parse_traffic_windows(
            run_dir / "victim" / "traffic-window.txt",
            gateway_ip=meta.get("gateway_lab_ip"),
            attacker_ip=meta.get("attacker_ip"),
        )
        ping_gateway_avg = row_mean([window.ping_gateway_avg_ms for window in probe_windows])
        ping_attacker_avg = row_mean([window.ping_attacker_avg_ms for window in probe_windows])
        curl_total_avg = row_mean([window.curl_total_s for window in probe_windows])
        iperf_mbps = parse_iperf_mbps(run_dir / "victim" / "iperf3.json")
        dhcp_metrics = _dhcp_campaign_metrics(run_dir, meta)

        detector_total_semantic_alerts = count_detector_events(
            detector_records,
            DETECTOR_STATE_EVENTS,
            spoofed_domains=spoofed_domains or None,
        )
        detector_event_recall = event_recall(evaluation, "detector_attack_type_counts", evaluation.detector_coverage)
        zeek_event_recall = event_recall(evaluation, "zeek_attack_type_counts", evaluation.zeek_coverage)
        suricata_event_recall = event_recall(evaluation, "suricata_attack_type_counts", evaluation.suricata_coverage)

        row: dict[str, Any] = {
            "run_id": str(meta.get("run_id", run_dir.name)),
            "run_dir": str(run_dir),
            "scenario": scenario,
            "warmup": bool(meta.get("warmup", False)),
            "duration_seconds": meta.get("duration_seconds"),
            "started_at": meta.get("started_at"),
            "ended_at": meta.get("ended_at"),
            "attack_started_at": meta.get("attack_started_at"),
            "attack_stopped_at": meta.get("attack_stopped_at"),
            "mitigation_started_at": meta.get("mitigation_started_at"),
            "forwarding_enabled": bool(meta.get("forwarding_enabled", False)),
            "dns_spoof_enabled": bool(meta.get("dns_spoof_enabled", False)),
            "spoofed_domains": sorted(spoofed_domains),
            "sensor_visibility_percent": meta.get("sensor_visibility_percent", 100),
            "sensor_visibility_active": bool(meta.get("sensor_visibility_active", False)),
            "sensor_visibility_model": meta.get("sensor_visibility_model"),
            "dhcp_starvation_workers": meta.get("dhcp_starvation_workers"),
            "dhcp_starvation_worker_model": meta.get("dhcp_starvation_worker_model"),
            "rogue_dhcp_start_offset_seconds": meta.get("rogue_dhcp_start_offset_seconds"),
            "rogue_dhcp_offered_ip": meta.get("rogue_dhcp_offered_ip"),
            "takeover_enabled": meta.get("takeover_enabled"),
            "takeover_start_mode": meta.get("takeover_start_mode"),
            "takeover_renew_delay_seconds": meta.get("takeover_renew_delay_seconds"),
            **dhcp_metrics,
            "detector_first_alert_at": evaluation.detector_first_alert_at,
            "ground_truth_attack_events": evaluation.ground_truth_attack_events,
            "ground_truth_attacker_action_events": evaluation.ground_truth_attacker_action_events,
            "ground_truth_attack_started_at": evaluation.ground_truth_attack_started_at,
            "ground_truth_attack_ended_at": evaluation.ground_truth_attack_ended_at,
            "ground_truth_capture_duration_seconds": evaluation.ground_truth_capture_duration_seconds,
            "ground_truth_attack_duration_seconds": evaluation.ground_truth_attack_duration_seconds,
            "ground_truth_dns_query_count": evaluation.ground_truth_dns_query_count,
            "ground_truth_dns_spoof_success_ratio": evaluation.ground_truth_dns_spoof_success_ratio,
            "ground_truth_attack_types": dict(evaluation.ground_truth_attack_types),
            "ground_truth_attacker_action_types": dict(evaluation.ground_truth_attacker_action_types),
            "ground_truth_attack_type_packet_rates_pps": dict(evaluation.ground_truth_attack_type_packet_rates_pps),
            "ground_truth_arp_spoof_direction_counts": dict(evaluation.ground_truth_arp_spoof_direction_counts),
            "ground_truth_control_plane_packet_counts": dict(evaluation.ground_truth_control_plane_packet_counts),
            "detector_first_arp_alert_at": detector_first_arp_alert_at,
            "detector_first_dns_alert_at": detector_first_dns_alert_at,
            "detector_first_recovery_at": detector_first_recovery_at,
            "detector_ttd_seconds": evaluation.detector_ttd_seconds,
            "detector_raw_ttd_seconds": evaluation.detector_ttd_seconds,
            "detector_arp_ttd_seconds": seconds_between(meta.get("started_at"), detector_first_arp_alert_at),
            "detector_dns_ttd_seconds": seconds_between(meta.get("started_at"), detector_first_dns_alert_at),
            "detector_recovery_seconds": seconds_between(meta.get("mitigation_started_at"), detector_first_recovery_at),
            "detector_total_semantic_alerts": detector_total_semantic_alerts,
            "gateway_mac_changed": detector_counts.get("gateway_mac_changed", 0),
            "multiple_gateway_macs_seen": detector_counts.get("multiple_gateway_macs_seen", 0),
            "icmp_redirects_seen": detector_counts.get("icmp_redirects_seen", 0),
            "rogue_dhcp_server_seen": detector_counts.get("rogue_dhcp_server_seen", 0),
            "dhcp_binding_conflict_seen": detector_counts.get("dhcp_binding_conflict_seen", 0),
            "domain_resolution_changed": count_detector_events(
                detector_records,
                {"domain_resolution_changed"},
                spoofed_domains=spoofed_domains or None,
            ),
            "restoration_events": count_detector_events(
                detector_records,
                RESTORATION_EVENTS,
                spoofed_domains=spoofed_domains or None,
            ),
            "ping_gateway_avg_ms": ping_gateway_avg,
            "ping_attacker_avg_ms": ping_attacker_avg,
            "curl_total_s": curl_total_avg,
            "iperf_mbps": iperf_mbps,
            "detector_alerts_native": evaluation.detector_alert_events,
            "zeek_alerts": evaluation.zeek_alert_events,
            "suricata_alerts": evaluation.suricata_alert_events,
            "detector_event_recall": detector_event_recall,
            "zeek_event_recall": zeek_event_recall,
            "suricata_event_recall": suricata_event_recall,
            "detector_first_alert_at_native": evaluation.detector_first_alert_at,
            "zeek_first_alert_at": evaluation.zeek_first_alert_at,
            "suricata_first_alert_at": evaluation.suricata_first_alert_at,
            "detector_attack_type_counts": dict(evaluation.detector_attack_type_counts),
            "zeek_attack_type_counts": dict(evaluation.zeek_attack_type_counts),
            "suricata_attack_type_counts": dict(evaluation.suricata_attack_type_counts),
        }

        relevant_attack_types = SCENARIO_ATTACK_TYPES.get(scenario, set())
        for sensor in TOOL_LABELS:
            if not relevant_attack_types:
                detected = bool(getattr(evaluation, f"{sensor}_first_alert_at"))
                ttd = None
            elif sensor == "detector":
                detected = evaluation.detector_first_alert_at is not None
                ttd = row["detector_ttd_seconds"]
            else:
                counts = getattr(evaluation, f"{sensor}_attack_type_counts")
                detected = any(counts.get(attack_type, 0) > 0 for attack_type in relevant_attack_types)
                ttd = getattr(evaluation, f"{sensor}_ttd_seconds") if detected else None
            row[f"{sensor}_detected"] = detected
            row[f"{sensor}_ttd_seconds"] = ttd

        rows.append(row)
    return rows


def write_dataset(rows: list[dict[str, Any]], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "experiment-dataset.csv"
    json_path = output_dir / "experiment-dataset.json"

    fieldnames = list(rows[0]) if rows else []
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    json_path.write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    return csv_path, json_path


def clear_report_outputs(output_dir: Path) -> None:
    if not output_dir.exists():
        return
    for pattern in ("*.png", "table-*.csv", "experiment-report.md"):
        for path in output_dir.glob(pattern):
            path.unlink()
