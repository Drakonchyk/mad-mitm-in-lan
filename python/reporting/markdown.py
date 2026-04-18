from __future__ import annotations

from pathlib import Path
from typing import Any

from metrics.primitives import confusion_from_binary
from reporting.common import format_float, path_rel, row_mean, rows_for_scenario
from reporting.common import TOOL_LABELS
from scenarios.definitions import MAIN_SCENARIOS, SCENARIO_ATTACK_TYPES, SUPPLEMENTARY_SCENARIOS


def overall_confusion_lines(rows: list[dict[str, Any]]) -> list[str]:
    ground_truth = [row["scenario"] != "baseline" for row in rows]
    lines: list[str] = []
    for sensor, label in TOOL_LABELS.items():
        confusion = confusion_from_binary(ground_truth, [bool(row[f"{sensor}_detected"]) for row in rows])
        lines.append(
            f"- {label}: TP={confusion.tp}, FP={confusion.fp}, TN={confusion.tn}, FN={confusion.fn}, "
            f"TPR={format_float(confusion.true_positive_rate())}, FPR={format_float(confusion.false_positive_rate())}, "
            f"Precision={format_float(confusion.precision())}, F1={format_float(confusion.f1())}."
        )
    return lines

def write_markdown_summary(
    rows: list[dict[str, Any]],
    plots: dict[str, Path],
    plot_notes: list[str],
    tables: dict[str, Path],
    output_dir: Path,
    plot_error: str | None,
    *,
    profile: str,
) -> Path:
    output_path = output_dir / "experiment-report.md"
    scenario_order = MAIN_SCENARIOS if profile == "main" else SUPPLEMENTARY_SCENARIOS if profile == "supplementary" else [*MAIN_SCENARIOS, *SUPPLEMENTARY_SCENARIOS]
    scenario_counts = {
        scenario: len(rows_for_scenario(rows, scenario))
        for scenario in scenario_order
        if rows_for_scenario(rows, scenario)
    }
    profile_label = "Main evaluation" if profile == "main" else "Supplementary evaluation" if profile == "supplementary" else "Combined evaluation"
    lines = [
        "# Experiment Report",
        "",
        "## Scope",
        "",
        f"- Profile: {profile_label}",
        f"- Measured runs included: {len(rows)}",
    ]
    for scenario, count in scenario_counts.items():
        lines.append(f"- {scenario}: {count} runs")

    lines.extend(
        [
            "",
            "## Figures",
            "",
        ]
    )
    if plots:
        for key, path in plots.items():
            lines.append(f"- {key}: {path_rel(path, output_dir)}")
    else:
        lines.append("- No figures were generated.")

    if plot_notes:
        lines.extend(
            [
                "",
                "## Plot Notes",
                "",
            ]
        )
        for note in plot_notes:
            lines.append(f"- {note}")

    lines.extend(
        [
            "",
            "## Tables",
            "",
        ]
    )
    for key, path in tables.items():
        lines.append(f"- {key}: {path_rel(path, output_dir)}")

    lines.extend(
        [
            "",
            "## Detection Summary",
            "",
            "- Run-level confusion below answers whether a run produced any alert at all. Scenario-specific timing and alert-volume differences still matter, so this summary is paired with the detailed figures and CSV tables.",
            "- Capability-aware comparison rule: Suricata is evaluated only on the attack types it supports in the current IDS setup, which excludes ARP spoof and keeps the tool comparison fair.",
        ]
    )
    lines.extend(overall_confusion_lines(rows))

    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(row["scenario"], set())]
    heading = "Main Findings" if profile == "main" else "Supplementary Findings" if profile == "supplementary" else "Findings"
    dataset_label = "main dataset" if profile == "main" else "supplementary dataset" if profile == "supplementary" else "combined dataset"
    lines.extend(
        [
            "",
            f"## {heading}",
            "",
            "- Time-to-detection values in this report use the first supported ground-truth attack evidence for each tool, so detector, Zeek, and Suricata are compared on the same timing basis.",
            "- Suricata comparison excludes ARP spoof coverage in the current IDS deployment, so Suricata timing and recall reflect ICMP redirect and DNS spoof only.",
            f"- Detector mean time to first alert across attack scenarios: {format_float(row_mean([row['detector_ttd_seconds'] for row in attack_rows]))} s.",
            f"- Detector mean semantic alert count per run: {format_float(row_mean([row['detector_total_semantic_alerts'] for row in rows]))}.",
            f"- Mean gateway ping latency across the current {dataset_label}: {format_float(row_mean([row['ping_gateway_avg_ms'] for row in rows]))} ms.",
            f"- Mean curl time_total across the current {dataset_label}: {format_float(row_mean([row['curl_total_s'] for row in rows]))} s.",
            f"- Mean iperf throughput across the current {dataset_label}: {format_float(row_mean([row['iperf_mbps'] for row in rows]))} Mbps.",
        ]
    )

    if plot_error:
        lines.extend(
            [
                "",
                "## Plot Status",
                "",
                f"- Plot generation skipped: {plot_error}",
                "- Install matplotlib on the host to render PNG charts.",
            ]
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path
