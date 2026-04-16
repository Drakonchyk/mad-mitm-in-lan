#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from evaluation_metrics import ConfusionCounts, confusion_from_binary, time_to_detection_seconds


DETECTOR_ALERT_EVENTS = {
    "arp_spoof_packet_seen",
    "icmp_redirect_packet_seen",
    "dns_spoof_packet_seen",
}

GROUND_TRUTH_ATTACK_EVENTS = {
    "arp_poison_cycle",
    "dns_spoof",
}

ZEEK_COVERAGE = {
    "arp_spoof": True,
    "icmp_redirect": True,
    "dns_spoof": True,
}

SURICATA_COVERAGE = {
    "arp_spoof": False,
    "icmp_redirect": True,
    "dns_spoof": True,
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
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
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


def normalize_timestamp(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            return value
    return None


def run_tshark_fields(pcap_path: Path, display_filter: str, field: str) -> list[str]:
    if not pcap_path.exists() or shutil.which("tshark") is None:
        return []

    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            field,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def observed_wire_attack_records(run_dir: Path, meta: dict[str, Any]) -> list[dict[str, Any]]:
    pcap_path = run_dir / "pcap" / "victim.pcap"
    victim_ip = meta.get("victim_ip")
    attacker_ip = meta.get("attacker_ip")
    if not victim_ip or not attacker_ip:
        return []

    icmp_epochs = run_tshark_fields(
        pcap_path,
        f"icmp.type==5 && ip.src=={attacker_ip} && ip.dst=={victim_ip}",
        "frame.time_epoch",
    )

    records: list[dict[str, Any]] = []
    for value in icmp_epochs:
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "icmp_redirect_observed", "ts": ts})
    return records


def observed_wire_attack_start_candidates(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> list[str]:
    pcap_path = run_dir / "pcap" / "victim.pcap"
    victim_ip = meta.get("victim_ip")
    attacker_ip = meta.get("attacker_ip")
    gateway_ip = meta.get("gateway_lab_ip")
    attacker_mac = next((record.get("attacker_mac") for record in attack_records if record.get("attacker_mac")), None)
    if not pcap_path.exists():
        return []

    filters: list[str] = []
    if attacker_ip and victim_ip:
        filters.append(f"icmp.type==5 && ip.src=={attacker_ip} && ip.dst=={victim_ip}")
    if attacker_mac and gateway_ip:
        filters.append(f"arp.opcode==2 && eth.src=={attacker_mac} && arp.src.proto_ipv4=={gateway_ip}")
    if attacker_ip and victim_ip and gateway_ip:
        filters.append(
            f"ip.src=={gateway_ip} && ip.dst=={victim_ip} && dns.flags.response==1 && dns.a=={attacker_ip}"
        )

    candidates: list[str] = []
    for display_filter in filters:
        epochs = run_tshark_fields(pcap_path, display_filter, "frame.time_epoch")
        if not epochs:
            continue
        try:
            candidates.append(datetime.fromtimestamp(float(epochs[0]), timezone.utc).isoformat())
        except ValueError:
            continue
    return candidates


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


@dataclass(frozen=True)
class SensorResult:
    alert_events: int
    alert_types: dict[str, int]
    unique_alert_type_count: int
    first_alert_at: str | None
    ttd_seconds: float | None
    coverage: dict[str, bool]


@dataclass(frozen=True)
class RunEvaluation:
    run_id: str
    scenario: str
    attack_present: bool
    ground_truth_source: str
    ground_truth_total_events: int
    ground_truth_attack_events: int
    ground_truth_attacker_action_events: int
    ground_truth_observed_wire_events: int
    ground_truth_control_events: int
    ground_truth_attack_started_at: str | None
    ground_truth_attack_types: dict[str, int]
    ground_truth_attacker_action_types: dict[str, int]
    ground_truth_observed_wire_types: dict[str, int]
    ground_truth_control_types: dict[str, int]
    detector_alert_events: int
    detector_alert_types: dict[str, int]
    detector_unique_alert_type_count: int
    detector_first_alert_at: str | None
    detector_ttd_seconds: float | None
    zeek_alert_events: int
    zeek_alert_types: dict[str, int]
    zeek_unique_alert_type_count: int
    zeek_first_alert_at: str | None
    zeek_ttd_seconds: float | None
    zeek_coverage: dict[str, bool]
    suricata_alert_events: int
    suricata_alert_types: dict[str, int]
    suricata_unique_alert_type_count: int
    suricata_first_alert_at: str | None
    suricata_ttd_seconds: float | None
    suricata_coverage: dict[str, bool]

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "attack_present": self.attack_present,
            "ground_truth_source": self.ground_truth_source,
            "ground_truth_total_events": self.ground_truth_total_events,
            "ground_truth_attack_events": self.ground_truth_attack_events,
            "ground_truth_attacker_action_events": self.ground_truth_attacker_action_events,
            "ground_truth_observed_wire_events": self.ground_truth_observed_wire_events,
            "ground_truth_control_events": self.ground_truth_control_events,
            "ground_truth_attack_started_at": self.ground_truth_attack_started_at,
            "ground_truth_attack_types": self.ground_truth_attack_types,
            "ground_truth_attacker_action_types": self.ground_truth_attacker_action_types,
            "ground_truth_observed_wire_types": self.ground_truth_observed_wire_types,
            "ground_truth_control_types": self.ground_truth_control_types,
            "detector_alert_events": self.detector_alert_events,
            "detector_alert_types": self.detector_alert_types,
            "detector_unique_alert_type_count": self.detector_unique_alert_type_count,
            "detector_first_alert_at": self.detector_first_alert_at,
            "detector_ttd_seconds": self.detector_ttd_seconds,
            "zeek_alert_events": self.zeek_alert_events,
            "zeek_alert_types": self.zeek_alert_types,
            "zeek_unique_alert_type_count": self.zeek_unique_alert_type_count,
            "zeek_first_alert_at": self.zeek_first_alert_at,
            "zeek_ttd_seconds": self.zeek_ttd_seconds,
            "zeek_coverage": self.zeek_coverage,
            "suricata_alert_events": self.suricata_alert_events,
            "suricata_alert_types": self.suricata_alert_types,
            "suricata_unique_alert_type_count": self.suricata_unique_alert_type_count,
            "suricata_first_alert_at": self.suricata_first_alert_at,
            "suricata_ttd_seconds": self.suricata_ttd_seconds,
            "suricata_coverage": self.suricata_coverage,
            "combined_sensor_detected": (self.zeek_alert_events > 0 or self.suricata_alert_events > 0),
        }


def load_zeek_result(run_dir: Path, attack_started_at: str | None) -> SensorResult:
    records = load_jsonl(run_dir / "zeek" / "victim" / "notice.log")
    alerts = [
        {
            "type": record.get("note", "unknown"),
            "ts": normalize_timestamp(record.get("ts")),
        }
        for record in records
        if record.get("note")
    ]
    counter = Counter(record["type"] for record in alerts)
    first_alert_at = next((record["ts"] for record in alerts if record.get("ts")), None)
    return SensorResult(
        alert_events=len(alerts),
        alert_types=dict(sorted(counter.items())),
        unique_alert_type_count=len(counter),
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        coverage=ZEEK_COVERAGE,
    )


def load_suricata_result(run_dir: Path, attack_started_at: str | None) -> SensorResult:
    records = load_jsonl(run_dir / "suricata" / "victim" / "eve.json")
    alerts = [
        {
            "type": record.get("alert", {}).get("signature", "unknown"),
            "ts": normalize_timestamp(record.get("timestamp")),
        }
        for record in records
        if record.get("event_type") == "alert"
    ]
    counter = Counter(record["type"] for record in alerts)
    first_alert_at = next((record["ts"] for record in alerts if record.get("ts")), None)
    return SensorResult(
        alert_events=len(alerts),
        alert_types=dict(sorted(counter.items())),
        unique_alert_type_count=len(counter),
        first_alert_at=first_alert_at,
        ttd_seconds=time_to_detection_seconds(attack_started_at, first_alert_at),
        coverage=SURICATA_COVERAGE,
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

    attack_counter = Counter(record.get("event", "unknown") for record in relevant_attack_records)
    attacker_action_counter = Counter(record.get("event", "unknown") for record in attacker_action_records)
    observed_counter = Counter(record.get("event", "unknown") for record in observed_records)
    control_counter = Counter(record.get("event", "unknown") for record in control_records)
    attack_start_candidates = [
        record.get("ts")
        for record in relevant_attack_records
        if record.get("ts")
    ]
    attack_start_candidates.extend(observed_wire_attack_start_candidates(run_dir, meta, attack_records))
    attack_started_at = next(
        (
            value
            for value in sorted(
                attack_start_candidates,
                key=lambda candidate: parse_timestamp(candidate) or datetime.max.replace(tzinfo=timezone.utc),
            )
            if value
        ),
        None,
    )
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

    detector_alert_records = [
        record for record in detector_records
        if record.get("event") in DETECTOR_ALERT_EVENTS
    ]
    detector_counter = Counter(record.get("event", "unknown") for record in detector_alert_records)
    detector_first_alert_at = next((record.get("ts") for record in detector_alert_records if record.get("ts")), None)

    zeek_result = load_zeek_result(run_dir, attack_started_at)
    suricata_result = load_suricata_result(run_dir, attack_started_at)

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
        ground_truth_attack_types=dict(sorted(attack_counter.items())),
        ground_truth_attacker_action_types=dict(sorted(attacker_action_counter.items())),
        ground_truth_observed_wire_types=dict(sorted(observed_counter.items())),
        ground_truth_control_types=dict(sorted(control_counter.items())),
        detector_alert_events=len(detector_alert_records),
        detector_alert_types=dict(sorted(detector_counter.items())),
        detector_unique_alert_type_count=len(detector_counter),
        detector_first_alert_at=detector_first_alert_at,
        detector_ttd_seconds=time_to_detection_seconds(attack_started_at, detector_first_alert_at),
        zeek_alert_events=zeek_result.alert_events,
        zeek_alert_types=zeek_result.alert_types,
        zeek_unique_alert_type_count=zeek_result.unique_alert_type_count,
        zeek_first_alert_at=zeek_result.first_alert_at,
        zeek_ttd_seconds=zeek_result.ttd_seconds,
        zeek_coverage=zeek_result.coverage,
        suricata_alert_events=suricata_result.alert_events,
        suricata_alert_types=suricata_result.alert_types,
        suricata_unique_alert_type_count=suricata_result.unique_alert_type_count,
        suricata_first_alert_at=suricata_result.first_alert_at,
        suricata_ttd_seconds=suricata_result.ttd_seconds,
        suricata_coverage=suricata_result.coverage,
    )


def aggregate_runs(run_dirs: list[Path]) -> dict[str, Any]:
    evaluations = [evaluate_single_run(run_dir) for run_dir in run_dirs]
    ground_truth = [item.attack_present for item in evaluations]
    detector_predictions = [item.detector_alert_events > 0 for item in evaluations]
    zeek_predictions = [item.zeek_alert_events > 0 for item in evaluations]
    suricata_predictions = [item.suricata_alert_events > 0 for item in evaluations]
    combined_predictions = [item.zeek_alert_events > 0 or item.suricata_alert_events > 0 for item in evaluations]

    detector_confusion: ConfusionCounts = confusion_from_binary(ground_truth, detector_predictions)
    zeek_confusion: ConfusionCounts = confusion_from_binary(ground_truth, zeek_predictions)
    suricata_confusion: ConfusionCounts = confusion_from_binary(ground_truth, suricata_predictions)
    combined_confusion: ConfusionCounts = confusion_from_binary(ground_truth, combined_predictions)

    return {
        "runs": [item.as_dict() for item in evaluations],
        "detector_confusion": detector_confusion.as_dict(),
        "zeek_confusion": zeek_confusion.as_dict(),
        "suricata_confusion": suricata_confusion.as_dict(),
        "combined_confusion": combined_confusion.as_dict(),
    }


def render_single(evaluation: RunEvaluation) -> str:
    lines = [
        f"Run: {evaluation.run_id}",
        f"Scenario: {evaluation.scenario}",
        f"Ground truth attack present: {evaluation.attack_present}",
        f"Ground truth source: {evaluation.ground_truth_source}",
        f"Ground truth total events: {evaluation.ground_truth_total_events}",
        f"Ground truth attack events: {evaluation.ground_truth_attack_events}",
        f"Ground truth attacker action events: {evaluation.ground_truth_attacker_action_events}",
        f"Ground truth observed wire events: {evaluation.ground_truth_observed_wire_events}",
        f"Ground truth control events: {evaluation.ground_truth_control_events}",
        f"Ground truth attack types: {json.dumps(evaluation.ground_truth_attack_types, sort_keys=True)}",
        f"Ground truth attacker action types: {json.dumps(evaluation.ground_truth_attacker_action_types, sort_keys=True)}",
        f"Ground truth observed wire types: {json.dumps(evaluation.ground_truth_observed_wire_types, sort_keys=True)}",
        f"Ground truth control types: {json.dumps(evaluation.ground_truth_control_types, sort_keys=True)}",
        f"Ground truth attack started at: {evaluation.ground_truth_attack_started_at or 'n/a'}",
        f"Detector alert events: {evaluation.detector_alert_events}",
        f"Detector unique alert types: {evaluation.detector_unique_alert_type_count}",
        f"Detector alert types: {json.dumps(evaluation.detector_alert_types, sort_keys=True)}",
        f"Detector first alert at: {evaluation.detector_first_alert_at or 'n/a'}",
        f"Detector first signal offset from attack start (s): {evaluation.detector_ttd_seconds if evaluation.detector_ttd_seconds is not None else 'n/a'}",
        f"Zeek alert events: {evaluation.zeek_alert_events}",
        f"Zeek unique alert types: {evaluation.zeek_unique_alert_type_count}",
        f"Zeek alert types: {json.dumps(evaluation.zeek_alert_types, sort_keys=True)}",
        f"Zeek first alert at: {evaluation.zeek_first_alert_at or 'n/a'}",
        f"Zeek first signal offset from attack start (s): {evaluation.zeek_ttd_seconds if evaluation.zeek_ttd_seconds is not None else 'n/a'}",
        f"Zeek coverage: {json.dumps(evaluation.zeek_coverage, sort_keys=True)}",
        f"Suricata alert events: {evaluation.suricata_alert_events}",
        f"Suricata unique alert signatures: {evaluation.suricata_unique_alert_type_count}",
        f"Suricata alert signatures: {json.dumps(evaluation.suricata_alert_types, sort_keys=True)}",
        f"Suricata first alert at: {evaluation.suricata_first_alert_at or 'n/a'}",
        f"Suricata first signal offset from attack start (s): {evaluation.suricata_ttd_seconds if evaluation.suricata_ttd_seconds is not None else 'n/a'}",
        f"Suricata coverage: {json.dumps(evaluation.suricata_coverage, sort_keys=True)}",
        "Note: ground truth attack events merge attacker actions with wire-observed ICMP redirects, because redirects are side effects that the attacker automation does not log directly.",
        "Timing note: detector, Zeek, and Suricata are all collected live on the victim, so these offsets are much more comparable than offline replay, but they still measure first logged signal rather than complete end-to-end alert pipeline latency.",
    ]
    return "\n".join(lines)


def render_multi(payload: dict[str, Any]) -> str:
    lines = [
        "Run | Scenario | Truth | GT Attack Events | Detector Alerts | Zeek Alerts | Suricata Alerts | Detector TTD(s) | Zeek TTD(s) | Suricata TTD(s)",
        "--- | --- | --- | --- | --- | --- | --- | --- | --- | ---",
    ]
    for item in payload["runs"]:
        lines.append(
            f"{item['run_id']} | {item['scenario']} | {item['attack_present']} | "
            f"{item['ground_truth_attack_events']} | {item['detector_alert_events']} | {item['zeek_alert_events']} | "
            f"{item['suricata_alert_events']} | {item['detector_ttd_seconds']} | {item['zeek_ttd_seconds']} | {item['suricata_ttd_seconds']}"
        )

    lines.extend(
        [
            "",
            "Note: detector counts are packet-level suspicious events, while ground truth attack events merge attacker actions with wire-observed ICMP redirects.",
            "",
            "Detector confusion:",
            json.dumps(payload["detector_confusion"], sort_keys=True),
            "Zeek confusion:",
            json.dumps(payload["zeek_confusion"], sort_keys=True),
            "Suricata confusion:",
            json.dumps(payload["suricata_confusion"], sort_keys=True),
            "Combined Zeek-or-Suricata confusion:",
            json.dumps(payload["combined_confusion"], sort_keys=True),
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate lab runs against ground truth, detector alerts, Zeek alerts, and Suricata alerts.")
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
