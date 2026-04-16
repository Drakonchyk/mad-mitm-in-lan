#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatch
import json
from pathlib import Path
from typing import Any

from evaluation_metrics import ConfusionCounts, confusion_from_binary, time_to_detection_seconds


DETECTOR_ALERT_EVENTS = {
    "gateway_mac_changed",
    "multiple_gateway_macs_seen",
    "icmp_redirects_seen",
    "domain_resolution_changed",
}


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
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_concatenated_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    index = 0
    records: list[dict[str, Any]] = []

    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            payload, next_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(payload, dict):
            records.append(payload)
        index = next_index
    return records


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class RunEvaluation:
    run_id: str
    scenario: str
    attack_present: bool
    ground_truth_source: str
    ground_truth_attack_events: int
    ground_truth_attack_started_at: str | None
    ground_truth_attack_types: dict[str, int]
    detector_alert_events: int
    detector_alert_types: dict[str, int]
    detector_unique_alert_type_count: int
    detector_first_alert_at: str | None
    detector_ttd_seconds: float | None
    suricata_alert_events: int
    suricata_alert_signatures: dict[str, int]
    suricata_unique_signature_count: int
    suricata_first_alert_at: str | None
    suricata_ttd_seconds: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "attack_present": self.attack_present,
            "ground_truth_source": self.ground_truth_source,
            "ground_truth_attack_events": self.ground_truth_attack_events,
            "ground_truth_attack_started_at": self.ground_truth_attack_started_at,
            "ground_truth_attack_types": self.ground_truth_attack_types,
            "detector_alert_events": self.detector_alert_events,
            "detector_alert_types": self.detector_alert_types,
            "detector_unique_alert_type_count": self.detector_unique_alert_type_count,
            "detector_first_alert_at": self.detector_first_alert_at,
            "detector_ttd_seconds": self.detector_ttd_seconds,
            "suricata_alert_events": self.suricata_alert_events,
            "suricata_alert_signatures": self.suricata_alert_signatures,
            "suricata_unique_signature_count": self.suricata_unique_signature_count,
            "suricata_first_alert_at": self.suricata_first_alert_at,
            "suricata_ttd_seconds": self.suricata_ttd_seconds,
        }


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def filter_run_dirs(run_dirs: list[Path], patterns: list[str] | None) -> list[Path]:
    if not patterns:
        return run_dirs
    return [
        run_dir for run_dir in run_dirs
        if any(fnmatch(run_dir.name, pattern) for pattern in patterns)
    ]


def find_attack_stdout_files(run_dir: Path) -> list[Path]:
    files = sorted(run_dir.glob("attacker/*.stdout"))
    return [path for path in files if path.name not in {"versions.txt"}]


def normalize_ground_truth_event(payload: dict[str, Any]) -> dict[str, Any]:
    if "event" in payload:
        return payload
    if {"answer_ip", "client_ip", "query_name"} <= payload.keys():
        return {
            "event": "dns_spoof",
            "answer_ip": payload["answer_ip"],
            "client_ip": payload["client_ip"],
            "query_name": payload["query_name"],
        }
    return payload


def evaluate_single_run(run_dir: Path) -> RunEvaluation:
    meta = load_json(run_dir / "run-meta.json")
    detector_records = load_jsonl(run_dir / "victim" / "detector.delta.jsonl")
    suricata_records = load_jsonl(run_dir / "suricata" / "victim" / "eve.json")

    attack_records: list[dict[str, Any]] = []
    for path in find_attack_stdout_files(run_dir):
        attack_records.extend(normalize_ground_truth_event(payload) for payload in parse_concatenated_json(path))

    attack_counter = Counter(record.get("event", "unknown") for record in attack_records)
    attack_started_at = next((record.get("ts") for record in attack_records if record.get("ts")), None)
    if attack_records:
        ground_truth_source = "attacker_stdout"
    elif meta.get("scenario") == "baseline":
        ground_truth_source = "baseline_inferred"
    else:
        ground_truth_source = "scenario_inferred"
    attack_present = bool(attack_records) or meta.get("scenario") != "baseline"

    detector_alert_records = [
        record for record in detector_records
        if record.get("event") in DETECTOR_ALERT_EVENTS
    ]
    detector_counter = Counter(record.get("event", "unknown") for record in detector_alert_records)
    detector_first_alert_at = next((record.get("ts") for record in detector_alert_records if record.get("ts")), None)

    suricata_alert_records = [
        record for record in suricata_records
        if record.get("event_type") == "alert"
    ]
    suricata_counter = Counter(
        record.get("alert", {}).get("signature", "unknown")
        for record in suricata_alert_records
    )
    suricata_first_alert_at = next((record.get("timestamp") for record in suricata_alert_records if record.get("timestamp")), None)

    return RunEvaluation(
        run_id=meta.get("run_id", run_dir.name),
        scenario=meta.get("scenario", run_dir.name),
        attack_present=attack_present,
        ground_truth_source=ground_truth_source,
        ground_truth_attack_events=len(attack_records),
        ground_truth_attack_started_at=attack_started_at,
        ground_truth_attack_types=dict(sorted(attack_counter.items())),
        detector_alert_events=len(detector_alert_records),
        detector_alert_types=dict(sorted(detector_counter.items())),
        detector_unique_alert_type_count=len(detector_counter),
        detector_first_alert_at=detector_first_alert_at,
        detector_ttd_seconds=time_to_detection_seconds(attack_started_at, detector_first_alert_at),
        suricata_alert_events=len(suricata_alert_records),
        suricata_alert_signatures=dict(sorted(suricata_counter.items())),
        suricata_unique_signature_count=len(suricata_counter),
        suricata_first_alert_at=suricata_first_alert_at,
        suricata_ttd_seconds=time_to_detection_seconds(attack_started_at, suricata_first_alert_at),
    )


def aggregate_runs(run_dirs: list[Path]) -> dict[str, Any]:
    evaluations = [evaluate_single_run(run_dir) for run_dir in run_dirs]
    ground_truth = [item.attack_present for item in evaluations]
    detector_predictions = [item.detector_alert_events > 0 for item in evaluations]
    suricata_predictions = [item.suricata_alert_events > 0 for item in evaluations]

    detector_confusion: ConfusionCounts = confusion_from_binary(ground_truth, detector_predictions)
    suricata_confusion: ConfusionCounts = confusion_from_binary(ground_truth, suricata_predictions)

    return {
        "runs": [item.as_dict() for item in evaluations],
        "detector_confusion": detector_confusion.as_dict(),
        "suricata_confusion": suricata_confusion.as_dict(),
    }


def render_single(evaluation: RunEvaluation) -> str:
    lines = [
        f"Run: {evaluation.run_id}",
        f"Scenario: {evaluation.scenario}",
        f"Ground truth attack present: {evaluation.attack_present}",
        f"Ground truth source: {evaluation.ground_truth_source}",
        f"Ground truth attack events: {evaluation.ground_truth_attack_events}",
        f"Ground truth attack types: {json.dumps(evaluation.ground_truth_attack_types, sort_keys=True)}",
        f"Ground truth attack started at: {evaluation.ground_truth_attack_started_at or 'n/a'}",
        f"Detector alert events: {evaluation.detector_alert_events}",
        f"Detector unique alert types: {evaluation.detector_unique_alert_type_count}",
        f"Detector alert types: {json.dumps(evaluation.detector_alert_types, sort_keys=True)}",
        f"Detector first alert at: {evaluation.detector_first_alert_at or 'n/a'}",
        f"Detector time to detection (s): {evaluation.detector_ttd_seconds if evaluation.detector_ttd_seconds is not None else 'n/a'}",
        f"Suricata alert events: {evaluation.suricata_alert_events}",
        f"Suricata unique alert signatures: {evaluation.suricata_unique_signature_count}",
        f"Suricata alert signatures: {json.dumps(evaluation.suricata_alert_signatures, sort_keys=True)}",
        f"Suricata first alert at: {evaluation.suricata_first_alert_at or 'n/a'}",
        f"Suricata time to detection (s): {evaluation.suricata_ttd_seconds if evaluation.suricata_ttd_seconds is not None else 'n/a'}",
        "Note: detector alerts are mostly state-transition alerts, while Suricata alerts are packet-level signature matches.",
    ]
    return "\n".join(lines)


def render_multi(payload: dict[str, Any]) -> str:
    lines = [
        "Run | Scenario | Truth | GT Events | Detector Alerts | Suricata Alerts | Detector TTD(s) | Suricata TTD(s)",
        "--- | --- | --- | --- | --- | --- | --- | ---",
    ]
    for item in payload["runs"]:
        lines.append(
            f"{item['run_id']} | {item['scenario']} | {item['attack_present']} | "
            f"{item['ground_truth_attack_events']} | {item['detector_alert_events']} | "
            f"{item['suricata_alert_events']} | {item['detector_ttd_seconds']} | {item['suricata_ttd_seconds']}"
        )

    lines.extend(
        [
            "",
            "Note: detector counts are transition-level, while Suricata counts are packet/signature-level.",
            "",
            "Detector confusion:",
            json.dumps(payload["detector_confusion"], sort_keys=True),
            "Suricata confusion:",
            json.dumps(payload["suricata_confusion"], sort_keys=True),
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate lab runs against ground truth, detector alerts, and Suricata alerts.")
    parser.add_argument("target", nargs="?", default="results", help="Run directory or results root")
    parser.add_argument("--glob", action="append", help="Optional glob pattern for run directory names, for example '20260416T20*'")
    parser.add_argument("--json-out", help="Optional path to write JSON output")
    parser.add_argument("--text-out", help="Optional path to write text output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    run_dirs = filter_run_dirs(find_run_dirs(target), args.glob)
    if not run_dirs:
        raise SystemExit(f"No run-meta.json files found under {target}")

    if len(run_dirs) == 1:
        evaluation = evaluate_single_run(run_dirs[0])
        json_payload: dict[str, Any] = evaluation.as_dict()
        text_payload = render_single(evaluation)
    else:
        json_payload = aggregate_runs(run_dirs)
        text_payload = render_multi(json_payload)

    print(text_payload)

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(json_payload, indent=2, sort_keys=True), encoding="utf-8")

    if args.text_out:
        text_path = Path(args.text_out)
        text_path.parent.mkdir(parents=True, exist_ok=True)
        text_path.write_text(text_payload + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
