#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from statistics import mean
from typing import Any

from evaluation_metrics import plot_grouped_bars


SCENARIO_ORDER = [
    "baseline",
    "arp-poison-no-forward",
    "arp-mitm-forward",
    "arp-mitm-dns",
    "mitigation-recovery",
]

RESTORE_EVENTS = {
    "gateway_mac_restored",
    "single_gateway_mac_restored",
    "domain_resolution_restored",
}


@dataclass(frozen=True)
class RunRow:
    run_id: str
    scenario: str
    warmup: bool
    attack_present: bool
    detector_alerts: int
    detector_ttd: float | None
    zeek_alerts: int
    zeek_ttd: float | None
    suricata_alerts: int
    suricata_ttd: float | None
    combined_detected: bool
    mitigation_started_at: str | None
    detector_recovery_seconds: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "warmup": self.warmup,
            "attack_present": self.attack_present,
            "detector_alerts": self.detector_alerts,
            "detector_ttd": self.detector_ttd,
            "zeek_alerts": self.zeek_alerts,
            "zeek_ttd": self.zeek_ttd,
            "suricata_alerts": self.suricata_alerts,
            "suricata_ttd": self.suricata_ttd,
            "combined_detected": self.combined_detected,
            "mitigation_started_at": self.mitigation_started_at,
            "detector_recovery_seconds": self.detector_recovery_seconds,
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


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detector_recovery_seconds(run_dir: Path, mitigation_started_at: str | None) -> float | None:
    mitigation_time = parse_time(mitigation_started_at)
    if mitigation_time is None:
        return None

    candidates: list[datetime] = []
    for record in load_jsonl(run_dir / "victim" / "detector.delta.jsonl"):
        if record.get("event") not in RESTORE_EVENTS:
            continue
        ts = parse_time(record.get("ts"))
        if ts is None or ts < mitigation_time:
            continue
        candidates.append(ts)

    if not candidates:
        return None
    return min((candidate - mitigation_time).total_seconds() for candidate in candidates)


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def build_rows(target: Path, include_warmups: bool) -> list[RunRow]:
    rows: list[RunRow] = []
    for run_dir in find_run_dirs(target):
        meta_path = run_dir / "run-meta.json"
        evaluation_path = run_dir / "evaluation.json"
        if not meta_path.exists() or not evaluation_path.exists():
            continue
        meta = load_json(meta_path)
        evaluation = load_json(evaluation_path)
        warmup = bool(meta.get("warmup", False))
        if warmup and not include_warmups:
            continue
        rows.append(
            RunRow(
                run_id=meta.get("run_id", run_dir.name),
                scenario=meta.get("scenario", run_dir.name),
                warmup=warmup,
                attack_present=bool(evaluation.get("attack_present", False)),
                detector_alerts=int(evaluation.get("detector_alert_events", 0)),
                detector_ttd=evaluation.get("detector_ttd_seconds"),
                zeek_alerts=int(evaluation.get("zeek_alert_events", 0)),
                zeek_ttd=evaluation.get("zeek_ttd_seconds"),
                suricata_alerts=int(evaluation.get("suricata_alert_events", 0)),
                suricata_ttd=evaluation.get("suricata_ttd_seconds"),
                combined_detected=bool(evaluation.get("zeek_alert_events", 0) or evaluation.get("suricata_alert_events", 0)),
                mitigation_started_at=meta.get("mitigation_started_at"),
                detector_recovery_seconds=detector_recovery_seconds(run_dir, meta.get("mitigation_started_at")),
            )
        )
    return rows


def mean_or_zero(values: list[float | int | None]) -> float:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return 0.0
    return mean(clean)


def rate_for(rows: list[RunRow], predicate) -> float:
    if not rows:
        return 0.0
    return sum(1 for row in rows if predicate(row)) / len(rows)


def scenario_rows(rows: list[RunRow], scenario: str) -> list[RunRow]:
    return [row for row in rows if row.scenario == scenario]


def write_dataset(rows: list[RunRow], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "experiment-dataset.csv"
    json_path = output_dir / "experiment-dataset.json"

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].as_dict()) if rows else [
            "run_id",
            "scenario",
            "warmup",
            "attack_present",
            "detector_alerts",
            "detector_ttd",
            "zeek_alerts",
            "zeek_ttd",
            "suricata_alerts",
            "suricata_ttd",
            "combined_detected",
            "mitigation_started_at",
            "detector_recovery_seconds",
        ])
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_dict())

    json_path.write_text(
        json.dumps([row.as_dict() for row in rows], indent=2, sort_keys=True),
        encoding="utf-8",
    )


def build_plots(rows: list[RunRow], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    attack_scenarios = [scenario for scenario in SCENARIO_ORDER if scenario != "baseline"]

    detection_series = {
        "Detector": [],
        "Zeek": [],
        "Suricata": [],
        "Zeek or Suricata": [],
    }
    alert_series = {
        "Detector": [],
        "Zeek": [],
        "Suricata": [],
    }
    ttd_series = {
        "Detector": [],
        "Zeek": [],
        "Suricata": [],
    }

    for scenario in attack_scenarios:
        subset = [row for row in scenario_rows(rows, scenario) if row.attack_present]
        detection_series["Detector"].append(rate_for(subset, lambda row: row.detector_alerts > 0) * 100.0)
        detection_series["Zeek"].append(rate_for(subset, lambda row: row.zeek_alerts > 0) * 100.0)
        detection_series["Suricata"].append(rate_for(subset, lambda row: row.suricata_alerts > 0) * 100.0)
        detection_series["Zeek or Suricata"].append(rate_for(subset, lambda row: row.combined_detected) * 100.0)
        alert_series["Detector"].append(mean_or_zero([row.detector_alerts for row in subset]))
        alert_series["Zeek"].append(mean_or_zero([row.zeek_alerts for row in subset]))
        alert_series["Suricata"].append(mean_or_zero([row.suricata_alerts for row in subset]))
        ttd_series["Detector"].append(mean_or_zero([row.detector_ttd for row in subset]))
        ttd_series["Zeek"].append(mean_or_zero([row.zeek_ttd for row in subset]))
        ttd_series["Suricata"].append(mean_or_zero([row.suricata_ttd for row in subset]))

    baseline_rows = scenario_rows(rows, "baseline")
    baseline_fp_series = {
        "Detector": [rate_for(baseline_rows, lambda row: row.detector_alerts > 0) * 100.0],
        "Zeek": [rate_for(baseline_rows, lambda row: row.zeek_alerts > 0) * 100.0],
        "Suricata": [rate_for(baseline_rows, lambda row: row.suricata_alerts > 0) * 100.0],
    }

    mitigation_rows = [row for row in scenario_rows(rows, "mitigation-recovery") if row.attack_present]
    recovery_series = {
        "Detector": [mean_or_zero([row.detector_recovery_seconds for row in mitigation_rows])],
    }

    outputs = {
        "detection_rate": plot_grouped_bars(
            attack_scenarios,
            detection_series,
            output_dir / "scenario-detection-rate.png",
            "Detection Rate by Scenario",
            "Detection rate (%)",
        ),
        "mean_alerts": plot_grouped_bars(
            attack_scenarios,
            alert_series,
            output_dir / "scenario-mean-alert-counts.png",
            "Mean Alert Counts by Scenario",
            "Alerts per run",
        ),
        "mean_ttd": plot_grouped_bars(
            attack_scenarios,
            ttd_series,
            output_dir / "scenario-mean-ttd.png",
            "Mean Time to Detection by Scenario",
            "Seconds",
        ),
        "baseline_fp": plot_grouped_bars(
            ["baseline"],
            baseline_fp_series,
            output_dir / "baseline-false-positive-rate.png",
            "Baseline False Positive Rate",
            "False positive rate (%)",
        ),
        "detector_recovery": plot_grouped_bars(
            ["mitigation-recovery"],
            recovery_series,
            output_dir / "mitigation-detector-recovery.png",
            "Detector Recovery Time",
            "Seconds",
        ),
    }
    return outputs


def write_markdown_summary(rows: list[RunRow], plot_paths: dict[str, Path], output_dir: Path, plot_error: str | None) -> Path:
    output_path = output_dir / "experiment-report.md"
    measured_rows = len(rows)
    lines = [
        "# Experiment Report",
        "",
        f"Measured runs included: {measured_rows}",
        "",
    ]
    if plot_paths:
        lines.extend(
            [
                "## Generated Plots",
                "",
                f"- Detection rate: {plot_paths['detection_rate'].name}",
                f"- Mean alert counts: {plot_paths['mean_alerts'].name}",
                f"- Mean time to detection: {plot_paths['mean_ttd'].name}",
                f"- Baseline false positive rate: {plot_paths['baseline_fp'].name}",
                f"- Detector recovery time: {plot_paths['detector_recovery'].name}",
                "",
            ]
        )
    if plot_error:
        lines.extend(
            [
                "## Plot Status",
                "",
                f"- Plot generation skipped: {plot_error}",
                "- Install matplotlib on the host to render PNG charts.",
                "",
            ]
        )
    lines.extend(
        [
            "## Notes",
            "",
            "- Zeek and Suricata are both treated as live victim-side comparators.",
            "- The combined Zeek-or-Suricata detection rate is useful when discussing layered monitoring.",
            "- Recovery timing is currently computed from detector restoration events, because Zeek and Suricata do not emit direct restoration semantics in this lab.",
        ]
    )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build dataset exports and plots for the diploma experiment plan.")
    parser.add_argument("target", nargs="?", default="results", help="Run directory or results root")
    parser.add_argument("--output-dir", default="results/experiment-report", help="Directory for CSV, JSON, plots, and markdown")
    parser.add_argument("--include-warmups", action="store_true", help="Include warm-up runs in exports and plots")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    output_dir = Path(args.output_dir)

    rows = build_rows(target, include_warmups=args.include_warmups)
    if not rows:
        raise SystemExit(f"No evaluated runs found under {target}")

    write_dataset(rows, output_dir)
    plot_paths: dict[str, Path] = {}
    plot_error: str | None = None
    try:
      plot_paths = build_plots(rows, output_dir)
    except RuntimeError as exc:
      plot_error = str(exc)

    write_markdown_summary(rows, plot_paths, output_dir, plot_error)
    if plot_error:
        print(f"Wrote experiment dataset to {output_dir} (plots skipped: {plot_error})")
    else:
        print(f"Wrote experiment dataset and plots to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
