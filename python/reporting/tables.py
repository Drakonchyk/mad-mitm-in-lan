from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from metrics.primitives import confusion_from_binary, safe_divide
from metrics.run_artifacts import stddev_or_zero
from reporting.common import TOOL_LABELS, available_scenarios, row_mean, rows_for_scenario
from scenarios.definitions import SUPPLEMENTARY_SCENARIOS, selected_scenarios

def build_table_a(output_dir: Path) -> Path:
    path = output_dir / "table-a-scenario-design.csv"
    rows = [
        {
            "scenario": "baseline",
            "duration_seconds": 90,
            "forwarding_enabled": False,
            "dns_spoof_enabled": False,
            "mitigation_enabled": False,
            "repetitions": 10,
        },
        {
            "scenario": "arp-poison-no-forward",
            "duration_seconds": 90,
            "forwarding_enabled": False,
            "dns_spoof_enabled": False,
            "mitigation_enabled": False,
            "repetitions": 10,
        },
        {
            "scenario": "arp-mitm-forward",
            "duration_seconds": 90,
            "forwarding_enabled": True,
            "dns_spoof_enabled": False,
            "mitigation_enabled": False,
            "repetitions": 10,
        },
        {
            "scenario": "arp-mitm-dns",
            "duration_seconds": 90,
            "forwarding_enabled": True,
            "dns_spoof_enabled": True,
            "mitigation_enabled": False,
            "repetitions": 10,
        },
        {
            "scenario": "mitigation-recovery",
            "duration_seconds": 120,
            "forwarding_enabled": True,
            "dns_spoof_enabled": True,
            "mitigation_enabled": True,
            "repetitions": 10,
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def build_table_b(rows: list[dict[str, Any]], output_dir: Path) -> Path:
    path = output_dir / "table-b-tool-summary.csv"
    attack_rows = [row for row in rows if row["scenario"] != "baseline"]
    shared_ping = row_mean([row["ping_gateway_avg_ms"] for row in rows])
    shared_curl = row_mean([row["curl_total_s"] for row in rows])
    shared_iperf = row_mean([row["iperf_mbps"] for row in rows])

    table_rows: list[dict[str, Any]] = []
    for sensor, label in TOOL_LABELS.items():
        comparison_scope = "all modeled attack types" if sensor != "suricata" else "supported attack types only (ICMP redirect, DNS spoof)"
        ground_truth = [row["scenario"] != "baseline" for row in rows]
        predictions = [bool(row[f"{sensor}_detected"]) for row in rows]
        confusion = confusion_from_binary(ground_truth, predictions)
        if sensor == "detector":
            mean_alert_count = row_mean([row["detector_total_semantic_alerts"] for row in rows])
        else:
            mean_alert_count = row_mean([row[f"{sensor}_alerts"] for row in rows])
        mean_ttd = row_mean([row[f"{sensor}_ttd_seconds"] for row in attack_rows])
        table_rows.append(
            {
                "scenario": "overall",
                "tool": label,
                "comparison_scope": comparison_scope,
                "tp": confusion.tp,
                "fp": confusion.fp,
                "tn": confusion.tn,
                "fn": confusion.fn,
                "tpr": confusion.true_positive_rate(),
                "fpr": confusion.false_positive_rate(),
                "precision": confusion.precision(),
                "f1": confusion.f1(),
                "mean_time_to_first_alert_s": mean_ttd,
                "mean_alert_count": mean_alert_count,
                "mean_ping_gateway_latency_ms": shared_ping,
                "mean_curl_time_s": shared_curl,
                "mean_iperf_throughput_mbps": shared_iperf,
            }
        )

        for scenario in sorted({row["scenario"] for row in rows}, key=lambda item: selected_scenarios("all").index(item) if item in selected_scenarios("all") else 999):
            scenario_rows = rows_for_scenario(rows, scenario)
            scenario_predictions = [bool(row[f"{sensor}_detected"]) for row in scenario_rows]
            scenario_truth = [row["scenario"] != "baseline" for row in scenario_rows]
            scenario_confusion = confusion_from_binary(scenario_truth, scenario_predictions)
            if scenario == "baseline":
                tpr = None
                fpr = safe_divide(sum(1 for predicted in scenario_predictions if predicted), len(scenario_predictions))
                precision = None
                f1 = None
            else:
                tpr = safe_divide(sum(1 for predicted in scenario_predictions if predicted), len(scenario_predictions))
                fpr = None
                precision = None
                f1 = None
            if sensor == "detector":
                mean_alert_count = row_mean([row["detector_total_semantic_alerts"] for row in scenario_rows])
            else:
                mean_alert_count = row_mean([row[f"{sensor}_alerts"] for row in scenario_rows])
            table_rows.append(
                {
                    "scenario": scenario,
                    "tool": label,
                    "comparison_scope": comparison_scope,
                    "tp": scenario_confusion.tp,
                    "fp": scenario_confusion.fp,
                    "tn": scenario_confusion.tn,
                    "fn": scenario_confusion.fn,
                    "tpr": tpr,
                    "fpr": fpr,
                    "precision": precision,
                    "f1": f1,
                    "mean_time_to_first_alert_s": row_mean([row[f"{sensor}_ttd_seconds"] for row in scenario_rows]),
                    "mean_alert_count": mean_alert_count,
                    "mean_ping_gateway_latency_ms": row_mean([row["ping_gateway_avg_ms"] for row in scenario_rows]),
                    "mean_curl_time_s": row_mean([row["curl_total_s"] for row in scenario_rows]),
                    "mean_iperf_throughput_mbps": row_mean([row["iperf_mbps"] for row in scenario_rows]),
                }
            )

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(table_rows[0]))
        writer.writeheader()
        writer.writerows(table_rows)
    return path


def build_table_c(rows: list[dict[str, Any]], output_dir: Path) -> Path:
    path = output_dir / "table-c-recovery-summary.csv"
    mitigation_rows = rows_for_scenario(rows, "mitigation-recovery")
    recovery_values = [row["detector_recovery_seconds"] for row in mitigation_rows]
    clean_recovery_values = [value for value in recovery_values if value is not None]
    table_rows = [
        {
            "scenario_or_method": "mitigation-recovery",
            "tool": "Detector",
            "restoration_success_rate": safe_divide(len(clean_recovery_values), len(mitigation_rows)),
            "mean_recovery_time_s": row_mean(recovery_values),
            "stddev_recovery_time_s": stddev_or_zero(recovery_values),
        },
        {
            "scenario_or_method": "mitigation-recovery",
            "tool": "Zeek",
            "restoration_success_rate": None,
            "mean_recovery_time_s": None,
            "stddev_recovery_time_s": None,
        },
        {
            "scenario_or_method": "mitigation-recovery",
            "tool": "Suricata",
            "restoration_success_rate": None,
            "mean_recovery_time_s": None,
            "stddev_recovery_time_s": None,
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(table_rows[0]))
        writer.writeheader()
        writer.writerows(table_rows)
    return path


def build_table_s1(rows: list[dict[str, Any]], output_dir: Path) -> Path:
    path = output_dir / "table-s1-supplementary-scenario-summary.csv"
    scenario_rows_summary: list[dict[str, Any]] = []
    for scenario in available_scenarios(rows, scenario_order=SUPPLEMENTARY_SCENARIOS):
        scenario_rows = rows_for_scenario(rows, scenario)
        scenario_rows_summary.append(
            {
                "scenario": scenario,
                "runs": len(scenario_rows),
                "detector_detection_rate": safe_divide(sum(1 for row in scenario_rows if row["detector_detected"]), len(scenario_rows)),
                "detector_mean_ttd_s": row_mean([row["detector_ttd_seconds"] for row in scenario_rows]),
                "detector_mean_alerts": row_mean([row["detector_total_semantic_alerts"] for row in scenario_rows]),
                "mean_ping_gateway_latency_ms": row_mean([row["ping_gateway_avg_ms"] for row in scenario_rows]),
                "mean_curl_time_s": row_mean([row["curl_total_s"] for row in scenario_rows]),
                "mean_iperf_throughput_mbps": row_mean([row["iperf_mbps"] for row in scenario_rows]),
            }
        )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scenario_rows_summary[0]))
        writer.writeheader()
        writer.writerows(scenario_rows_summary)
    return path
