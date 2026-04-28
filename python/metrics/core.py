from __future__ import annotations

from collections import Counter
from dataclasses import fields
import json
from pathlib import Path
from typing import Any

from metrics.model import (
    ATTACK_TYPE_ORDER,
    DETECTOR_ALERT_EVENTS,
    EVALUATION_CACHE_VERSION,
    EVALUATION_DEPENDENCY_PATHS,
    GROUND_TRUTH_ATTACK_EVENTS,
    REPO_ROOT,
    SENSOR_COVERAGE,
    SURICATA_ALERT_TYPES,
    ZEEK_ALERT_TYPES,
    RunEvaluation,
    SensorResult,
)
from metrics.parsers import (
    canonical_attack_type,
    canonical_counter_from_records,
    canonical_ground_truth_counts,
    find_attack_stdout_files,
    first_timestamp,
    load_json,
    load_jsonl,
    merge_first_seen_maps,
    normalize_ground_truth_event,
    normalize_timestamp,
    observed_wire_attack_records,
    observed_wire_attack_epochs_by_type,
    observed_wire_source_label,
    observed_wire_attack_type_first_seen_at,
    observed_wire_attack_start_candidates,
    observed_wire_capture_duration_seconds,
    observed_wire_control_plane_packet_counts,
    observed_wire_dns_query_count,
    parse_timestamp,
    parse_concatenated_json,
    supported_attack_started_at,
    untrusted_switch_port_pcap_paths,
)
from metrics.primitives import time_to_detection_seconds
from metrics.run_artifacts import (
    detector_delta_path,
    parse_ovs_dhcp_snooping_stats,
    suricata_eve_path,
    suricata_stats_path,
    zeek_notice_path,
    zeek_stats_path,
)
from metrics.truth_db import truth_db_path


def last_timestamp(values: list[str | None]) -> str | None:
    normalized = [value for value in values if value]
    return next(
        (
            value
            for value in sorted(
                normalized,
                key=lambda candidate: parse_timestamp(candidate) or parse_timestamp("9999-12-31T23:59:59+00:00"),
                reverse=True,
            )
        ),
        None,
    )


def seconds_between_timestamps(started_at: str | None, ended_at: str | None) -> float | None:
    started = parse_timestamp(started_at)
    ended = parse_timestamp(ended_at)
    if started is None or ended is None:
        return None
    return max((ended - started).total_seconds(), 0.0)


def attack_type_durations_seconds(epochs_by_type: dict[str, list[str]]) -> dict[str, float | None]:
    durations: dict[str, float | None] = {}
    for attack_type in ATTACK_TYPE_ORDER:
        epochs = epochs_by_type.get(attack_type, [])
        if not epochs:
            continue
        try:
            start = float(epochs[0])
            end = float(epochs[-1])
        except (TypeError, ValueError):
            durations[attack_type] = None
            continue
        durations[attack_type] = max(end - start, 0.0)
    return dict(sorted(durations.items()))


def attack_type_packet_rates_pps(
    counts: dict[str, int],
    durations: dict[str, float | None],
) -> dict[str, float | None]:
    rates: dict[str, float | None] = {}
    for attack_type, count in counts.items():
        duration = durations.get(attack_type)
        if duration is None or duration <= 0:
            rates[attack_type] = None
            continue
        rates[attack_type] = count / duration
    return dict(sorted(rates.items()))


def action_counts_from_wire_epochs(epochs_by_type: dict[str, list[str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    arp_total = len(epochs_by_type.get("arp_spoof", []))
    arp_gateway_to_victim = len(epochs_by_type.get("arp_spoof_gateway_to_victim", []))
    arp_victim_to_gateway = len(epochs_by_type.get("arp_spoof_victim_to_gateway", []))
    if arp_gateway_to_victim and arp_victim_to_gateway:
        counts["arp_spoof"] = min(arp_gateway_to_victim, arp_victim_to_gateway)
    elif arp_total:
        counts["arp_spoof"] = (arp_total + 1) // 2

    for attack_type in ATTACK_TYPE_ORDER:
        if attack_type == "arp_spoof":
            continue
        total = len(epochs_by_type.get(attack_type, []))
        if total:
            counts[attack_type] = total
    return dict(sorted(counts.items()))


def evaluation_input_paths(run_dir: Path) -> list[Path]:
    paths = [
        run_dir / "run-meta.json",
        detector_delta_path(run_dir),
        run_dir / "pcap" / "sensor.pcap",
        run_dir / "pcap" / "victim.pcap",
        run_dir / "pcap" / "wire-truth.json",
        truth_db_path(run_dir),
        run_dir / "detector" / "ovs-dhcp-snooping.txt",
        run_dir / "detector" / "ovs-switch-truth-snooping.txt",
        zeek_notice_path(run_dir),
        zeek_stats_path(run_dir),
        suricata_eve_path(run_dir),
        suricata_stats_path(run_dir),
    ]
    paths.extend(find_attack_stdout_files(run_dir))
    return sorted(path for path in paths if path.exists())


def cache_input_mtimes(run_dir: Path) -> dict[str, int]:
    return {
        str(path.relative_to(run_dir)): path.stat().st_mtime_ns
        for path in evaluation_input_paths(run_dir)
    }


def dependency_mtimes() -> dict[str, int]:
    return {
        str(path.relative_to(REPO_ROOT)): path.stat().st_mtime_ns
        for path in EVALUATION_DEPENDENCY_PATHS
    }


def cached_metadata(run_dir: Path) -> dict[str, Any]:
    return {
        "cache_version": EVALUATION_CACHE_VERSION,
        "dependency_mtimes_ns": dependency_mtimes(),
        "input_mtimes_ns": cache_input_mtimes(run_dir),
    }


def hydrate_run_evaluation(payload: dict[str, Any]) -> RunEvaluation:
    for tool in ("detector", "zeek", "suricata"):
        payload.setdefault(f"{tool}_supported_attack_started_at", payload.get("ground_truth_attack_started_at"))
        payload.setdefault(f"{tool}_supported_ttd_seconds", payload.get(f"{tool}_ttd_seconds"))
        payload.setdefault(f"{tool}_coverage", dict(SENSOR_COVERAGE[tool]))
    payload.setdefault("ground_truth_source", "switch_pcap")
    payload.setdefault("ground_truth_observed_wire_events", payload.get("ground_truth_attack_events", 0))
    payload.setdefault("ground_truth_observed_wire_types", payload.get("ground_truth_attack_types", {}))
    run_fields = {field.name for field in fields(RunEvaluation)}
    return RunEvaluation(**{name: payload[name] for name in run_fields})


def load_cached_run_evaluation(run_dir: Path) -> RunEvaluation | None:
    evaluation_path = run_dir / "evaluation.json"
    if not evaluation_path.exists():
        return None

    try:
        payload = load_json(evaluation_path)
    except json.JSONDecodeError:
        return None

    metadata = payload.get("_evaluation_cache")
    if not isinstance(metadata, dict):
        return None
    if metadata.get("cache_version") != EVALUATION_CACHE_VERSION:
        return None
    if metadata.get("input_mtimes_ns") != cache_input_mtimes(run_dir):
        return None

    try:
        return hydrate_run_evaluation(payload)
    except KeyError:
        return None


def write_evaluation_cache(run_dir: Path, evaluation: RunEvaluation) -> None:
    payload = evaluation.as_dict()
    payload["_evaluation_cache"] = cached_metadata(run_dir)
    (run_dir / "evaluation.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_detector_result(
    records: list[dict[str, Any]],
    attack_started_at: str | None,
    ground_truth_first_seen_at: dict[str, str],
    coverage: dict[str, bool] | None = None,
) -> SensorResult:
    alert_records = [record for record in records if record.get("event") in DETECTOR_ALERT_EVENTS]
    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        alert_records,
        raw_type_key="event",
        type_map=DETECTOR_ALERT_EVENTS,
        timestamp_key="ts",
    )
    first_alert_at = first_timestamp(record.get("ts") for record in alert_records if record.get("ts"))
    coverage = coverage or SENSOR_COVERAGE["detector"]
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, coverage)
    supported_first_alert_at = supported_sensor_first_alert_at(canonical_first_alert_at, ground_truth_first_seen_at, coverage)
    return SensorResult(
        alert_events=len(alert_records),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, supported_first_alert_at),
        coverage=coverage,
    )


def supported_sensor_first_alert_at(
    canonical_first_alert_at: dict[str, str],
    ground_truth_first_seen_at: dict[str, str],
    coverage: dict[str, bool],
) -> str | None:
    return first_timestamp(
        canonical_first_alert_at.get(attack_type)
        for attack_type in ground_truth_first_seen_at
        if coverage.get(attack_type, False)
    )


def load_zeek_result(
    run_dir: Path,
    attack_started_at: str | None,
    ground_truth_first_seen_at: dict[str, str],
) -> SensorResult:
    records = load_jsonl(zeek_notice_path(run_dir))
    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        records,
        raw_type_key="note",
        type_map=ZEEK_ALERT_TYPES,
        timestamp_key="ts",
    )
    first_alert_at = first_timestamp(normalize_timestamp(record.get("ts")) for record in records if record.get("note"))
    coverage = SENSOR_COVERAGE["zeek"]
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, coverage)
    supported_first_alert_at = supported_sensor_first_alert_at(canonical_first_alert_at, ground_truth_first_seen_at, coverage)
    return SensorResult(
        alert_events=sum(raw_counter.values()),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, supported_first_alert_at),
        coverage=coverage,
    )


def load_suricata_result(
    run_dir: Path,
    meta: dict[str, Any],
    attack_started_at: str | None,
    ground_truth_first_seen_at: dict[str, str],
    coverage: dict[str, bool],
) -> SensorResult:
    records = load_jsonl(suricata_eve_path(run_dir))
    alerts: list[dict[str, Any]] = [
        {
            "signature": record.get("alert", {}).get("signature"),
            "timestamp": record.get("timestamp"),
        }
        for record in records
        if record.get("event_type") == "alert"
    ]

    attacker_mac = str(meta.get("attacker_mac", "")).lower() or None
    gateway_ip = meta.get("gateway_lab_ip")
    victim_ip = meta.get("victim_ip")
    arp_eve_matches = 0
    for record in records:
        if record.get("event_type") != "arp":
            continue
        arp = record.get("arp", {})
        opcode = str(arp.get("opcode", "")).lower()
        src_mac = str(arp.get("src_mac", "")).lower()
        src_ip = arp.get("src_ip")
        dest_ip = arp.get("dest_ip")
        if opcode not in {"reply", "response", "2"}:
            continue
        if attacker_mac and src_mac != attacker_mac:
            continue
        if gateway_ip and src_ip != gateway_ip:
            continue
        if victim_ip and dest_ip != victim_ip:
            continue
        arp_eve_matches += 1
        alerts.append(
            {
                "signature": "MITM-LAB Suricata EVE ARP reply from attacker claims gateway IP to victim",
                "timestamp": record.get("timestamp"),
            }
        )

    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        alerts,
        raw_type_key="signature",
        type_map=SURICATA_ALERT_TYPES,
        timestamp_key="timestamp",
    )
    raw_counter = dict(sorted(Counter(record.get("signature", "unknown") for record in alerts if record.get("signature")).items()))
    first_alert_at = first_timestamp(normalize_timestamp(record.get("timestamp")) for record in alerts)
    effective_coverage = dict(coverage)
    if "arp_spoof" in ground_truth_first_seen_at or arp_eve_matches > 0:
        effective_coverage["arp_spoof"] = True
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, effective_coverage)
    supported_first_alert_at = supported_sensor_first_alert_at(canonical_first_alert_at, ground_truth_first_seen_at, effective_coverage)
    return SensorResult(
        alert_events=len(alerts),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, supported_first_alert_at),
        coverage=effective_coverage,
    )


def evaluate_single_run(run_dir: Path) -> RunEvaluation:
    meta = load_json(run_dir / "run-meta.json")
    detector_records = load_jsonl(detector_delta_path(run_dir))

    attack_records: list[dict[str, Any]] = []
    for path in find_attack_stdout_files(run_dir):
        attack_records.extend(normalize_ground_truth_event(payload) for payload in parse_concatenated_json(path))

    attacker_action_records = [
        record for record in attack_records
        if record.get("event") in GROUND_TRUTH_ATTACK_EVENTS
    ]
    observed_records = observed_wire_attack_records(run_dir, meta)
    observed_counter, _ = canonical_ground_truth_counts(observed_records)
    if observed_records:
        observed_types = set(observed_counter)
        supplemental_action_records = [
            record for record in attacker_action_records
            if canonical_attack_type(record.get("event")) not in observed_types
        ]
        relevant_attack_records = [*observed_records, *supplemental_action_records]
    else:
        relevant_attack_records = attacker_action_records
    control_records = [
        record for record in attack_records
        if record.get("event") not in GROUND_TRUTH_ATTACK_EVENTS
    ]

    attack_counter, attack_first_seen_at = canonical_ground_truth_counts(relevant_attack_records)
    attacker_stdout_action_counter, _ = canonical_ground_truth_counts(attacker_action_records)
    control_counter = Counter(record.get("event", "unknown") for record in control_records)
    wire_epochs_by_type = observed_wire_attack_epochs_by_type(run_dir, meta, attack_records)
    wire_attack_first_seen_at = observed_wire_attack_type_first_seen_at(run_dir, meta, attack_records)
    attack_first_seen_at = merge_first_seen_maps(attack_first_seen_at, wire_attack_first_seen_at)
    attack_start_candidates = [record.get("ts") for record in relevant_attack_records if record.get("ts")]
    attack_start_candidates.extend(observed_wire_attack_start_candidates(run_dir, meta, attack_records))
    attack_started_at = first_timestamp(attack_start_candidates)
    attack_ended_at = last_timestamp([record.get("ts") for record in relevant_attack_records if record.get("ts")])
    attack_duration_seconds = seconds_between_timestamps(attack_started_at, attack_ended_at)
    attack_type_durations = attack_type_durations_seconds(wire_epochs_by_type)
    attack_type_rates = attack_type_packet_rates_pps(attack_counter, attack_type_durations)
    dns_query_count = observed_wire_dns_query_count(run_dir, meta)
    dns_spoof_success_ratio = (
        attack_counter.get("dns_spoof", 0) / dns_query_count
        if dns_query_count > 0 and attack_counter.get("dns_spoof", 0) > 0
        else None
    )
    arp_direction_counts = {
        "gateway_to_victim": len(wire_epochs_by_type.get("arp_spoof_gateway_to_victim", [])),
        "victim_to_gateway": len(wire_epochs_by_type.get("arp_spoof_victim_to_gateway", [])),
    }
    wire_action_counter = action_counts_from_wire_epochs(wire_epochs_by_type)
    attacker_action_counter = wire_action_counter if observed_records else attacker_stdout_action_counter
    control_plane_counts = observed_wire_control_plane_packet_counts(run_dir)
    capture_duration_seconds = observed_wire_capture_duration_seconds(run_dir)
    wire_truth_label = observed_wire_source_label(run_dir)

    if observed_records:
        dhcp_snooping_stats = parse_ovs_dhcp_snooping_stats(run_dir / "detector" / "ovs-dhcp-snooping.txt")
        dhcp_snooping_packets = int(dhcp_snooping_stats.get("packets") or 0)
        if wire_truth_label == "trusted_observation_db":
            ground_truth_source = "trusted_observation_db"
        elif wire_epochs_by_type.get("dhcp_untrusted_switch_port") and (untrusted_switch_port_pcap_paths(run_dir) or dhcp_snooping_packets > 0):
            ground_truth_source = "switch_port_snooping"
        elif wire_truth_label == "switch_snooping":
            ground_truth_source = "switch_port_snooping"
        else:
            ground_truth_source = wire_truth_label or "wire_truth_summary"
    elif attack_records:
        ground_truth_source = "attacker_stdout"
    elif meta.get("scenario") == "baseline":
        ground_truth_source = "baseline_inferred"
    else:
        ground_truth_source = "scenario_inferred"
    attack_present = bool(relevant_attack_records) or meta.get("scenario") != "baseline"

    detector_coverage = dict(SENSOR_COVERAGE["detector"])
    if not bool(meta.get("detector_ovs_dhcp_snooping_enabled", True)):
        detector_coverage["dhcp_untrusted_switch_port"] = False
    detector_result = load_detector_result(detector_records, attack_started_at, attack_first_seen_at, detector_coverage)
    zeek_result = load_zeek_result(run_dir, attack_started_at, attack_first_seen_at)
    suricata_coverage = dict(SENSOR_COVERAGE["suricata"])
    suricata_coverage["arp_spoof"] = bool(meta.get("suricata_arp_rule_enabled", False))
    suricata_result = load_suricata_result(run_dir, meta, attack_started_at, attack_first_seen_at, suricata_coverage)

    return RunEvaluation(
        run_id=meta.get("run_id", run_dir.name),
        scenario=meta.get("scenario", run_dir.name),
        attack_present=attack_present,
        ground_truth_source=ground_truth_source,
        ground_truth_total_events=len(relevant_attack_records) + len(control_records),
        ground_truth_attack_events=len(relevant_attack_records),
        ground_truth_attacker_action_events=sum(attacker_action_counter.values()),
        ground_truth_observed_wire_events=len(observed_records),
        ground_truth_control_events=len(control_records),
        ground_truth_attack_started_at=attack_started_at,
        ground_truth_attack_ended_at=attack_ended_at,
        ground_truth_capture_duration_seconds=capture_duration_seconds,
        ground_truth_attack_duration_seconds=attack_duration_seconds,
        ground_truth_attack_types=attack_counter,
        ground_truth_attack_type_first_seen_at=attack_first_seen_at,
        ground_truth_attack_type_durations_seconds=attack_type_durations,
        ground_truth_attack_type_packet_rates_pps=attack_type_rates,
        ground_truth_attacker_action_types=attacker_action_counter,
        ground_truth_observed_wire_types=observed_counter,
        ground_truth_control_types=dict(sorted(control_counter.items())),
        ground_truth_dns_query_count=dns_query_count,
        ground_truth_dns_spoof_success_ratio=dns_spoof_success_ratio,
        ground_truth_arp_spoof_direction_counts=arp_direction_counts,
        ground_truth_control_plane_packet_counts=dict(sorted(control_plane_counts.items())),
        detector_alert_events=detector_result.alert_events,
        detector_alert_types=detector_result.alert_types,
        detector_unique_alert_type_count=detector_result.unique_alert_type_count,
        detector_attack_type_counts=detector_result.canonical_alert_types,
        detector_attack_type_first_alert_at=detector_result.canonical_first_alert_at,
        detector_first_alert_at=detector_result.first_alert_at,
        detector_ttd_seconds=detector_result.ttd_seconds,
        detector_supported_attack_started_at=detector_result.supported_attack_started_at,
        detector_supported_ttd_seconds=detector_result.supported_ttd_seconds,
        detector_coverage=detector_result.coverage,
        zeek_alert_events=zeek_result.alert_events,
        zeek_alert_types=zeek_result.alert_types,
        zeek_unique_alert_type_count=zeek_result.unique_alert_type_count,
        zeek_attack_type_counts=zeek_result.canonical_alert_types,
        zeek_attack_type_first_alert_at=zeek_result.canonical_first_alert_at,
        zeek_first_alert_at=zeek_result.first_alert_at,
        zeek_ttd_seconds=zeek_result.ttd_seconds,
        zeek_supported_attack_started_at=zeek_result.supported_attack_started_at,
        zeek_supported_ttd_seconds=zeek_result.supported_ttd_seconds,
        zeek_coverage=zeek_result.coverage,
        suricata_alert_events=suricata_result.alert_events,
        suricata_alert_types=suricata_result.alert_types,
        suricata_unique_alert_type_count=suricata_result.unique_alert_type_count,
        suricata_attack_type_counts=suricata_result.canonical_alert_types,
        suricata_attack_type_first_alert_at=suricata_result.canonical_first_alert_at,
        suricata_first_alert_at=suricata_result.first_alert_at,
        suricata_ttd_seconds=suricata_result.ttd_seconds,
        suricata_supported_attack_started_at=suricata_result.supported_attack_started_at,
        suricata_supported_ttd_seconds=suricata_result.supported_ttd_seconds,
        suricata_coverage=suricata_result.coverage,
    )


def load_or_evaluate_single_run(run_dir: Path, *, use_cache: bool = True, write_cache: bool = True) -> RunEvaluation:
    if use_cache:
        cached = load_cached_run_evaluation(run_dir)
        if cached is not None:
            return cached

    evaluation = evaluate_single_run(run_dir)
    if write_cache:
        write_evaluation_cache(run_dir, evaluation)
    return evaluation
