from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from metrics.core import load_or_evaluate_single_run
from metrics.model import ATTACK_TYPE_ORDER, RunEvaluation
from metrics.primitives import ConfusionCounts, confusion_from_binary, safe_divide


def attack_type_presence_confusion(
    evaluations: list[RunEvaluation],
    sensor_field: str,
    coverage_field: str,
) -> ConfusionCounts:
    ground_truth: list[bool] = []
    predictions: list[bool] = []
    for evaluation in evaluations:
        sensor_counts = getattr(evaluation, sensor_field)
        coverage = getattr(evaluation, coverage_field)
        for attack_type in ATTACK_TYPE_ORDER:
            if not coverage.get(attack_type, False):
                continue
            ground_truth.append(evaluation.ground_truth_attack_types.get(attack_type, 0) > 0)
            predictions.append(sensor_counts.get(attack_type, 0) > 0)
    return confusion_from_binary(ground_truth, predictions)


def matched_events(
    ground_truth_counts: dict[str, int],
    predicted_counts: dict[str, int],
    *,
    allowed_types: Iterable[str] | None = None,
) -> int:
    attack_types = ATTACK_TYPE_ORDER if allowed_types is None else list(allowed_types)
    return sum(min(ground_truth_counts.get(attack_type, 0), predicted_counts.get(attack_type, 0)) for attack_type in attack_types)


def total_events(
    counts: dict[str, int],
    *,
    allowed_types: Iterable[str] | None = None,
) -> int:
    attack_types = ATTACK_TYPE_ORDER if allowed_types is None else list(allowed_types)
    return sum(counts.get(attack_type, 0) for attack_type in attack_types)


def comparable_truth_counts(evaluation: RunEvaluation) -> dict[str, int]:
    return {
        attack_type: (
            evaluation.ground_truth_attacker_action_types.get(attack_type)
            or evaluation.ground_truth_attack_types.get(attack_type, 0)
        )
        for attack_type in ATTACK_TYPE_ORDER
    }


def event_recall_summary(
    evaluations: list[RunEvaluation],
    sensor_field: str,
    coverage_field: str,
) -> dict[str, Any]:
    all_truth = 0
    all_matched = 0
    for evaluation in evaluations:
        coverage = getattr(evaluation, coverage_field)
        allowed_types = [attack_type for attack_type in ATTACK_TYPE_ORDER if coverage.get(attack_type, False)]
        truth_counts = comparable_truth_counts(evaluation)
        all_truth += total_events(truth_counts, allowed_types=allowed_types)
        all_matched += matched_events(truth_counts, getattr(evaluation, sensor_field), allowed_types=allowed_types)
    by_attack_type: dict[str, dict[str, float | int]] = {}
    for attack_type in ATTACK_TYPE_ORDER:
        truth = 0
        matched = 0
        for evaluation in evaluations:
            coverage = getattr(evaluation, coverage_field)
            if not coverage.get(attack_type, False):
                continue
            truth_counts = comparable_truth_counts(evaluation)
            truth_count = truth_counts.get(attack_type, 0)
            truth += truth_count
            matched += min(truth_count, getattr(evaluation, sensor_field).get(attack_type, 0))
        by_attack_type[attack_type] = {
            "matched_events": matched,
            "ground_truth_events": truth,
            "recall": safe_divide(matched, truth),
        }
    return {
        "matched_events": all_matched,
        "ground_truth_events": all_truth,
        "recall": safe_divide(all_matched, all_truth),
        "by_attack_type": by_attack_type,
    }


def aggregate_runs(run_dirs: list[Path], *, use_cache: bool = True) -> dict[str, Any]:
    evaluations = [load_or_evaluate_single_run(run_dir, use_cache=use_cache) for run_dir in run_dirs]
    ground_truth = [item.attack_present for item in evaluations]
    detector_predictions = [item.detector_alert_events > 0 for item in evaluations]
    zeek_predictions = [item.zeek_alert_events > 0 for item in evaluations]
    suricata_predictions = [item.suricata_alert_events > 0 for item in evaluations]
    combined_predictions = [item.zeek_alert_events > 0 or item.suricata_alert_events > 0 for item in evaluations]

    detector_run_confusion = confusion_from_binary(ground_truth, detector_predictions)
    zeek_run_confusion = confusion_from_binary(ground_truth, zeek_predictions)
    suricata_run_confusion = confusion_from_binary(ground_truth, suricata_predictions)
    combined_run_confusion = confusion_from_binary(ground_truth, combined_predictions)

    detector_type_confusion = attack_type_presence_confusion(evaluations, "detector_attack_type_counts", "detector_coverage")
    zeek_type_confusion = attack_type_presence_confusion(evaluations, "zeek_attack_type_counts", "zeek_coverage")
    suricata_type_confusion = attack_type_presence_confusion(evaluations, "suricata_attack_type_counts", "suricata_coverage")

    combined_type_truth: list[bool] = []
    combined_type_predictions: list[bool] = []
    for evaluation in evaluations:
        for attack_type in ATTACK_TYPE_ORDER:
            if not (evaluation.zeek_coverage.get(attack_type, False) or evaluation.suricata_coverage.get(attack_type, False)):
                continue
            combined_type_truth.append(evaluation.ground_truth_attack_types.get(attack_type, 0) > 0)
            combined_type_predictions.append(
                evaluation.zeek_attack_type_counts.get(attack_type, 0) > 0
                or evaluation.suricata_attack_type_counts.get(attack_type, 0) > 0
            )
    combined_type_confusion = confusion_from_binary(combined_type_truth, combined_type_predictions)

    return {
        "runs": [item.as_dict() for item in evaluations],
        "detector_confusion": detector_run_confusion.as_dict(),
        "zeek_confusion": zeek_run_confusion.as_dict(),
        "suricata_confusion": suricata_run_confusion.as_dict(),
        "combined_confusion": combined_run_confusion.as_dict(),
        "run_level_detection_confusion": {
            "detector": detector_run_confusion.as_dict(),
            "zeek": zeek_run_confusion.as_dict(),
            "suricata": suricata_run_confusion.as_dict(),
            "combined_zeek_or_suricata": combined_run_confusion.as_dict(),
        },
        "attack_type_presence_confusion": {
            "detector": detector_type_confusion.as_dict(),
            "zeek": zeek_type_confusion.as_dict(),
            "suricata": suricata_type_confusion.as_dict(),
            "combined_zeek_or_suricata": combined_type_confusion.as_dict(),
        },
        "event_recall": {
            "detector": event_recall_summary(evaluations, "detector_attack_type_counts", "detector_coverage"),
            "zeek": event_recall_summary(evaluations, "zeek_attack_type_counts", "zeek_coverage"),
            "suricata": event_recall_summary(evaluations, "suricata_attack_type_counts", "suricata_coverage"),
        },
    }


def type_recall(evaluation: RunEvaluation, sensor_field: str) -> float | None:
    sensor_counts = getattr(evaluation, sensor_field)
    matched_types = sum(
        1
        for attack_type in ATTACK_TYPE_ORDER
        if evaluation.ground_truth_attack_types.get(attack_type, 0) > 0 and sensor_counts.get(attack_type, 0) > 0
    )
    truth_types = sum(1 for attack_type in ATTACK_TYPE_ORDER if evaluation.ground_truth_attack_types.get(attack_type, 0) > 0)
    if truth_types == 0:
        return None
    return safe_divide(matched_types, truth_types)


def supported_type_recall(evaluation: RunEvaluation, sensor_field: str, coverage: dict[str, bool]) -> float | None:
    sensor_counts = getattr(evaluation, sensor_field)
    allowed_types = [attack_type for attack_type in ATTACK_TYPE_ORDER if coverage.get(attack_type, False)]
    truth_types = sum(1 for attack_type in allowed_types if evaluation.ground_truth_attack_types.get(attack_type, 0) > 0)
    if truth_types == 0:
        return None
    matched_types = sum(
        1
        for attack_type in allowed_types
        if evaluation.ground_truth_attack_types.get(attack_type, 0) > 0 and sensor_counts.get(attack_type, 0) > 0
    )
    return safe_divide(matched_types, truth_types)


def event_recall(
    evaluation: RunEvaluation,
    sensor_field: str,
    coverage: dict[str, bool],
    supported_only: bool = True,
) -> float | None:
    sensor_counts = getattr(evaluation, sensor_field)
    allowed_types = [attack_type for attack_type in ATTACK_TYPE_ORDER if (coverage.get(attack_type, False) or not supported_only)]
    comparable_truth = comparable_truth_counts(evaluation)
    truth = total_events(comparable_truth, allowed_types=allowed_types)
    if truth == 0:
        return None
    matched = matched_events(comparable_truth, sensor_counts, allowed_types=allowed_types)
    return safe_divide(matched, truth)


def render_single(evaluation: RunEvaluation) -> str:
    lines = [
        f"Run: {evaluation.run_id}",
        f"Scenario: {evaluation.scenario}",
        f"Ground truth attack present: {evaluation.attack_present}",
        f"Ground truth total events: {evaluation.ground_truth_total_events}",
        f"Ground truth attack packets: {evaluation.ground_truth_attack_events}",
        f"Ground truth attacker action events: {evaluation.ground_truth_attacker_action_events}",
        f"Ground truth control events: {evaluation.ground_truth_control_events}",
        f"Ground truth attack types: {json.dumps(evaluation.ground_truth_attack_types, sort_keys=True)}",
        f"Ground truth attack type first seen at: {json.dumps(evaluation.ground_truth_attack_type_first_seen_at, sort_keys=True)}",
        f"Ground truth attack ended at: {evaluation.ground_truth_attack_ended_at or 'n/a'}",
        f"Ground truth capture duration (s): {evaluation.ground_truth_capture_duration_seconds if evaluation.ground_truth_capture_duration_seconds is not None else 'n/a'}",
        f"Ground truth attack duration (s): {evaluation.ground_truth_attack_duration_seconds if evaluation.ground_truth_attack_duration_seconds is not None else 'n/a'}",
        f"Ground truth attack type durations (s): {json.dumps(evaluation.ground_truth_attack_type_durations_seconds, sort_keys=True)}",
        f"Ground truth attack type packet rates (pps): {json.dumps(evaluation.ground_truth_attack_type_packet_rates_pps, sort_keys=True)}",
        f"Ground truth attacker action types: {json.dumps(evaluation.ground_truth_attacker_action_types, sort_keys=True)}",
        f"Ground truth control types: {json.dumps(evaluation.ground_truth_control_types, sort_keys=True)}",
        f"Ground truth DNS query count: {evaluation.ground_truth_dns_query_count}",
        f"Ground truth DNS spoof success ratio: {evaluation.ground_truth_dns_spoof_success_ratio if evaluation.ground_truth_dns_spoof_success_ratio is not None else 'n/a'}",
        f"Ground truth ARP spoof direction counts: {json.dumps(evaluation.ground_truth_arp_spoof_direction_counts, sort_keys=True)}",
        f"Ground truth control-plane packet counts: {json.dumps(evaluation.ground_truth_control_plane_packet_counts, sort_keys=True)}",
        f"Ground truth attack started at: {evaluation.ground_truth_attack_started_at or 'n/a'}",
        f"Detector alert events: {evaluation.detector_alert_events}",
        f"Detector unique alert types: {evaluation.detector_unique_alert_type_count}",
        f"Detector alert types: {json.dumps(evaluation.detector_alert_types, sort_keys=True)}",
        f"Detector canonical attack types: {json.dumps(evaluation.detector_attack_type_counts, sort_keys=True)}",
        f"Detector first alert at: {evaluation.detector_first_alert_at or 'n/a'}",
        f"Detector raw first signal offset from attack start (s): {evaluation.detector_ttd_seconds if evaluation.detector_ttd_seconds is not None else 'n/a'}",
        f"Detector type recall: {supported_type_recall(evaluation, 'detector_attack_type_counts', evaluation.detector_coverage)}",
        f"Detector event recall: {event_recall(evaluation, 'detector_attack_type_counts', evaluation.detector_coverage)}",
        f"Zeek alert events: {evaluation.zeek_alert_events}",
        f"Zeek unique alert types: {evaluation.zeek_unique_alert_type_count}",
        f"Zeek alert types: {json.dumps(evaluation.zeek_alert_types, sort_keys=True)}",
        f"Zeek canonical attack types: {json.dumps(evaluation.zeek_attack_type_counts, sort_keys=True)}",
        f"Zeek first alert at: {evaluation.zeek_first_alert_at or 'n/a'}",
        f"Zeek raw first signal offset from attack start (s): {evaluation.zeek_ttd_seconds if evaluation.zeek_ttd_seconds is not None else 'n/a'}",
        f"Zeek type recall: {supported_type_recall(evaluation, 'zeek_attack_type_counts', evaluation.zeek_coverage)}",
        f"Zeek event recall: {event_recall(evaluation, 'zeek_attack_type_counts', evaluation.zeek_coverage)}",
        f"Suricata alert events: {evaluation.suricata_alert_events}",
        f"Suricata unique alert signatures: {evaluation.suricata_unique_alert_type_count}",
        f"Suricata alert signatures: {json.dumps(evaluation.suricata_alert_types, sort_keys=True)}",
        f"Suricata canonical attack types: {json.dumps(evaluation.suricata_attack_type_counts, sort_keys=True)}",
        f"Suricata first alert at: {evaluation.suricata_first_alert_at or 'n/a'}",
        f"Suricata raw first signal offset from attack start (s): {evaluation.suricata_ttd_seconds if evaluation.suricata_ttd_seconds is not None else 'n/a'}",
        f"Suricata type recall: {supported_type_recall(evaluation, 'suricata_attack_type_counts', evaluation.suricata_coverage)}",
        f"Suricata event recall: {event_recall(evaluation, 'suricata_attack_type_counts', evaluation.suricata_coverage)}",
    ]
    return "\n".join(lines)


def render_multi(payload: dict[str, Any]) -> str:
    def item_type_recall(item: dict[str, Any], sensor: str) -> float:
        coverage = item.get(f"{sensor}_coverage", {})
        counts = item.get(f"{sensor}_attack_type_counts", {})
        allowed_types = [attack_type for attack_type in ATTACK_TYPE_ORDER if coverage.get(attack_type, False)]
        truth = sum(1 for attack_type in allowed_types if item["ground_truth_attack_types"].get(attack_type, 0) > 0)
        matched = sum(
            1
            for attack_type in allowed_types
            if item["ground_truth_attack_types"].get(attack_type, 0) > 0 and counts.get(attack_type, 0) > 0
        )
        return safe_divide(matched, truth) if truth else 0.0

    lines = [
        "Run | Scenario | Truth | GT Action Events | Detector Alerts | Zeek Alerts | Suricata Alerts | Detector Type Recall | Zeek Type Recall | Suricata Type Recall | Detector TTD(s) | Zeek TTD(s) | Suricata TTD(s)",
        "--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---",
    ]
    for item in payload["runs"]:
        detector_type_recall = item_type_recall(item, "detector") if item["attack_present"] else 0.0
        zeek_type_recall = item_type_recall(item, "zeek") if item["attack_present"] else 0.0
        suricata_type_recall = item_type_recall(item, "suricata") if item["attack_present"] else 0.0
        lines.append(
            f"{item['run_id']} | {item['scenario']} | {item['attack_present']} | "
            f"{item['ground_truth_attacker_action_events']} | {item['detector_alert_events']} | {item['zeek_alert_events']} | "
            f"{item['suricata_alert_events']} | {detector_type_recall:.3f} | {zeek_type_recall:.3f} | {suricata_type_recall:.3f} | "
            f"{item['detector_ttd_seconds']} | {item['zeek_ttd_seconds']} | {item['suricata_ttd_seconds']}"
        )

    lines.extend(
        [
            "",
            "Run-level detection confusion:",
            "Detector:",
            json.dumps(payload["run_level_detection_confusion"]["detector"], sort_keys=True),
            "Zeek:",
            json.dumps(payload["run_level_detection_confusion"]["zeek"], sort_keys=True),
            "Suricata:",
            json.dumps(payload["run_level_detection_confusion"]["suricata"], sort_keys=True),
            "Combined Zeek-or-Suricata:",
            json.dumps(payload["run_level_detection_confusion"]["combined_zeek_or_suricata"], sort_keys=True),
            "",
            "Attack-type presence confusion:",
            "Detector:",
            json.dumps(payload["attack_type_presence_confusion"]["detector"], sort_keys=True),
            "Zeek:",
            json.dumps(payload["attack_type_presence_confusion"]["zeek"], sort_keys=True),
            "Suricata:",
            json.dumps(payload["attack_type_presence_confusion"]["suricata"], sort_keys=True),
            "Combined Zeek-or-Suricata:",
            json.dumps(payload["attack_type_presence_confusion"]["combined_zeek_or_suricata"], sort_keys=True),
            "",
            "Event recall:",
            "Detector:",
            json.dumps(payload["event_recall"]["detector"], sort_keys=True),
            "Zeek:",
            json.dumps(payload["event_recall"]["zeek"], sort_keys=True),
            "Suricata:",
            json.dumps(payload["event_recall"]["suricata"], sort_keys=True),
        ]
    )
    return "\n".join(lines)
