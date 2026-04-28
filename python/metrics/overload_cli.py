#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
from typing import Any

from metrics.core import load_or_evaluate_single_run
from metrics.run_artifacts import detector_delta_path, detector_throughput_summary, load_json, load_jsonl


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def overload_rows(target: Path) -> list[dict[str, Any]]:
    db_path = target if target.is_file() else target / "experiment-results.sqlite"
    if db_path.exists():
        return overload_rows_from_db(db_path)

    rows: list[dict[str, Any]] = []
    for run_dir in find_run_dirs(target):
        meta = load_json(run_dir / "run-meta.json")
        scenario = str(meta.get("scenario", ""))
        if not scenario.startswith("overload-"):
            continue
        evaluation = load_or_evaluate_single_run(run_dir, use_cache=False, write_cache=True)
        throughput = detector_throughput_summary(load_jsonl(detector_delta_path(run_dir)))
        truth_types = set(evaluation.ground_truth_attack_types)
        detector_types = set(evaluation.detector_attack_type_counts)
        rows.append(
            {
                "run_id": meta.get("run_id", run_dir.name),
                "scenario": scenario,
                "requested_pps": meta.get("overload_total_pps"),
                "pps_per_source": meta.get("overload_pps_per_source"),
                "sources": ",".join(meta.get("overload_sources", [])),
                "truth_types": ",".join(sorted(truth_types)) or "-",
                "detector_types": ",".join(sorted(detector_types)) or "-",
                "detected_all_truth": truth_types <= detector_types if truth_types else evaluation.detector_alert_events > 0,
                "detector_alerts": evaluation.detector_alert_events,
                "max_seen_pps": throughput.get("max_interval_seen_pps"),
                "max_processed_pps": throughput.get("max_interval_processed_pps"),
                "path": str(run_dir),
            }
        )
    return sorted(rows, key=lambda row: (row["scenario"], int(row.get("requested_pps") or 0), row["run_id"]))


def overload_rows_from_db(db_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with sqlite3.connect(db_path) as connection:
        for row in connection.execute(
            """
            SELECT run_id, scenario, overload_total_pps, overload_pps_per_source,
                   detector_max_seen_pps, detector_max_processed_pps, run_dir
            FROM runs
            WHERE scenario LIKE 'overload-%'
            ORDER BY scenario, overload_total_pps, run_id
            """
        ):
            run_id, scenario, requested_pps, pps_per_source, max_seen, max_processed, run_dir = row
            truth_types = {
                value
                for (value,) in connection.execute(
                    "SELECT attack_type FROM truth_counts WHERE run_id = ? AND truth_count > 0",
                    (run_id,),
                )
            }
            detector_types = {
                value
                for (value,) in connection.execute(
                    """
                    SELECT attack_type FROM sensor_counts
                    WHERE run_id = ? AND sensor = 'detector' AND alert_count > 0
                    """,
                    (run_id,),
                )
            }
            rows.append(
                {
                    "run_id": run_id,
                    "scenario": scenario,
                    "requested_pps": requested_pps,
                    "pps_per_source": pps_per_source,
                    "sources": "-",
                    "truth_types": ",".join(sorted(truth_types)) or "-",
                    "detector_types": ",".join(sorted(detector_types)) or "-",
                    "detected_all_truth": truth_types <= detector_types if truth_types else False,
                    "detector_alerts": sum(
                        value
                        for (value,) in connection.execute(
                            "SELECT alert_count FROM sensor_counts WHERE run_id = ? AND sensor = 'detector'",
                            (run_id,),
                        )
                    ),
                    "max_seen_pps": max_seen,
                    "max_processed_pps": max_processed,
                    "path": run_dir,
                }
            )
    return rows


def print_summary(rows: list[dict[str, Any]]) -> None:
    headers = [
        "scenario",
        "requested_pps",
        "pps_per_source",
        "sources",
        "truth_types",
        "detector_types",
        "detected_all_truth",
        "max_seen_pps",
        "max_processed_pps",
        "path",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(fmt(row.get(header)) for header in headers) + " |")

    print()
    for scenario in sorted({str(row["scenario"]) for row in rows}):
        scenario_rows = [row for row in rows if row["scenario"] == scenario]
        passing = [row for row in scenario_rows if row.get("detected_all_truth")]
        if not passing:
            print(f"{scenario}: no passing overload level found")
            continue
        ceiling = max(int(row.get("requested_pps") or 0) for row in passing)
        observed = max(float(row.get("max_processed_pps") or 0.0) for row in passing)
        print(f"{scenario}: estimated requested-pps ceiling={ceiling}, observed detector processed pps={observed:.1f}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize detector overload calibration runs.")
    parser.add_argument("target", nargs="?", default="results")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        parser.error(f"{target} does not exist")
    rows = overload_rows(target)
    if not rows:
        print(f"No overload runs found under {target}")
        return 0
    print_summary(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
