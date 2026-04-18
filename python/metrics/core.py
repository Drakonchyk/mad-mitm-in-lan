from __future__ import annotations

from collections import Counter
from dataclasses import fields
import json
from pathlib import Path
from typing import Any

from metrics.model import (
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
    observed_wire_attack_type_first_seen_at,
    observed_wire_attack_start_candidates,
    parse_concatenated_json,
    supported_attack_started_at,
)
from metrics.primitives import time_to_detection_seconds


def evaluation_input_paths(run_dir: Path) -> list[Path]:
    paths = [
        run_dir / "run-meta.json",
        run_dir / "victim" / "detector.delta.jsonl",
        run_dir / "pcap" / "victim.pcap",
        run_dir / "zeek" / "victim" / "notice.log",
        run_dir / "suricata" / "victim" / "eve.json",
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
    if metadata.get("dependency_mtimes_ns") != dependency_mtimes():
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
) -> SensorResult:
    alert_records = [record for record in records if record.get("event") in DETECTOR_ALERT_EVENTS]
    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        alert_records,
        raw_type_key="event",
        type_map=DETECTOR_ALERT_EVENTS,
        timestamp_key="ts",
    )
    first_alert_at = first_timestamp(record.get("ts") for record in alert_records if record.get("ts"))
    coverage = SENSOR_COVERAGE["detector"]
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, coverage)
    return SensorResult(
        alert_events=len(alert_records),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, first_alert_at),
        coverage=coverage,
    )


def load_zeek_result(
    run_dir: Path,
    attack_started_at: str | None,
    ground_truth_first_seen_at: dict[str, str],
) -> SensorResult:
    records = load_jsonl(run_dir / "zeek" / "victim" / "notice.log")
    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        records,
        raw_type_key="note",
        type_map=ZEEK_ALERT_TYPES,
        timestamp_key="ts",
    )
    first_alert_at = first_timestamp(normalize_timestamp(record.get("ts")) for record in records if record.get("note"))
    coverage = SENSOR_COVERAGE["zeek"]
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, coverage)
    return SensorResult(
        alert_events=sum(raw_counter.values()),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, first_alert_at),
        coverage=coverage,
    )


def load_suricata_result(
    run_dir: Path,
    attack_started_at: str | None,
    ground_truth_first_seen_at: dict[str, str],
    coverage: dict[str, bool],
) -> SensorResult:
    records = load_jsonl(run_dir / "suricata" / "victim" / "eve.json")
    alerts = [
        {
            "signature": record.get("alert", {}).get("signature"),
            "timestamp": record.get("timestamp"),
        }
        for record in records
        if record.get("event_type") == "alert"
    ]
    canonical_alert_types, canonical_first_alert_at, raw_counter = canonical_counter_from_records(
        alerts,
        raw_type_key="signature",
        type_map=SURICATA_ALERT_TYPES,
        timestamp_key="timestamp",
    )
    raw_counter = dict(sorted(Counter(record.get("signature", "unknown") for record in alerts if record.get("signature")).items()))
    first_alert_at = first_timestamp(normalize_timestamp(record.get("timestamp")) for record in alerts)
    supported_started_at = supported_attack_started_at(ground_truth_first_seen_at, coverage)
    return SensorResult(
        alert_events=len(alerts),
        alert_types=raw_counter,
        unique_alert_type_count=len(raw_counter),
        canonical_alert_types=canonical_alert_types,
        canonical_first_alert_at=canonical_first_alert_at,
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        supported_attack_started_at=supported_started_at,
        supported_ttd_seconds=time_to_detection_seconds(supported_started_at, first_alert_at),
        coverage=coverage,
    )


def evaluate_single_run(run_dir: Path) -> RunEvaluation:
    meta = load_json(run_dir / "run-meta.json")
    detector_records = load_jsonl(run_dir / "victim" / "detector.delta.jsonl")

    attack_records: list[dict[str, Any]] = []
    for path in find_attack_stdout_files(run_dir):
        attack_records.extend(normalize_ground_truth_event(payload) for payload in parse_concatenated_json(path))

    attacker_action_records = [
        record for record in attack_records
        if record.get("event") in GROUND_TRUTH_ATTACK_EVENTS
    ]
    observed_records = observed_wire_attack_records(run_dir, meta)
    relevant_attack_records = [*attacker_action_records, *observed_records]
    control_records = [
        record for record in attack_records
        if record.get("event") not in GROUND_TRUTH_ATTACK_EVENTS
    ]

    attack_counter, attack_first_seen_at = canonical_ground_truth_counts(relevant_attack_records)
    attacker_action_counter, _ = canonical_ground_truth_counts(attacker_action_records)
    observed_counter, _ = canonical_ground_truth_counts(observed_records)
    control_counter = Counter(record.get("event", "unknown") for record in control_records)
    wire_attack_first_seen_at = observed_wire_attack_type_first_seen_at(run_dir, meta, attack_records)
    attack_first_seen_at = merge_first_seen_maps(attack_first_seen_at, wire_attack_first_seen_at)
    attack_start_candidates = [record.get("ts") for record in relevant_attack_records if record.get("ts")]
    attack_start_candidates.extend(observed_wire_attack_start_candidates(run_dir, meta, attack_records))
    attack_started_at = first_timestamp(attack_start_candidates)

    if attack_records and observed_records:
        ground_truth_source = "attacker_stdout+victim_pcap"
    elif attack_records:
        ground_truth_source = "attacker_stdout"
    elif observed_records:
        ground_truth_source = "victim_pcap"
    elif meta.get("scenario") == "baseline":
        ground_truth_source = "baseline_inferred"
    else:
        ground_truth_source = "scenario_inferred"
    attack_present = bool(relevant_attack_records) or meta.get("scenario") != "baseline"

    detector_result = load_detector_result(detector_records, attack_started_at, attack_first_seen_at)
    zeek_result = load_zeek_result(run_dir, attack_started_at, attack_first_seen_at)
    suricata_coverage = dict(SENSOR_COVERAGE["suricata"])
    suricata_coverage["arp_spoof"] = bool(meta.get("suricata_arp_rule_enabled", False))
    suricata_result = load_suricata_result(run_dir, attack_started_at, attack_first_seen_at, suricata_coverage)

    return RunEvaluation(
        run_id=meta.get("run_id", run_dir.name),
        scenario=meta.get("scenario", run_dir.name),
        attack_present=attack_present,
        ground_truth_source=ground_truth_source,
        ground_truth_total_events=len(relevant_attack_records) + len(control_records),
        ground_truth_attack_events=len(relevant_attack_records),
        ground_truth_attacker_action_events=len(attacker_action_records),
        ground_truth_observed_wire_events=len(observed_records),
        ground_truth_control_events=len(control_records),
        ground_truth_attack_started_at=attack_started_at,
        ground_truth_attack_types=attack_counter,
        ground_truth_attack_type_first_seen_at=attack_first_seen_at,
        ground_truth_attacker_action_types=attacker_action_counter,
        ground_truth_observed_wire_types=observed_counter,
        ground_truth_control_types=dict(sorted(control_counter.items())),
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
