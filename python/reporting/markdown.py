from __future__ import annotations

import csv
from pathlib import Path

from metrics.primitives import confusion_from_binary
from reporting.common import (
    TOOL_LABELS,
    TOOL_ORDER,
    attack_relative_ttd,
    format_float,
    path_rel,
    row_mean,
    rows_for_scenario,
    tool_alert_field,
)
from scenarios.definitions import MAIN_SCENARIOS, SCENARIO_ATTACK_TYPES, SUPPLEMENTARY_SCENARIOS

SCENARIO_ORDER_ALL = [*MAIN_SCENARIOS, *SUPPLEMENTARY_SCENARIOS]


def _overall_confusion_lines(rows: list[dict[str, object]]) -> list[str]:
    ground_truth = [bool(SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))) for row in rows]
    lines: list[str] = []
    for tool in TOOL_ORDER:
        confusion = confusion_from_binary(ground_truth, [bool(row.get(f"{tool}_detected")) for row in rows])
        lines.append(
            f"- {TOOL_LABELS[tool]}: TP={confusion.tp}, FP={confusion.fp}, TN={confusion.tn}, FN={confusion.fn}, "
            f"TPR={format_float(confusion.true_positive_rate())}, FPR={format_float(confusion.false_positive_rate())}, "
            f"Precision={format_float(confusion.precision())}, F1={format_float(confusion.f1())}."
        )
    return lines


def _sectioned(items: dict[str, Path]) -> list[tuple[str, list[tuple[str, Path]]]]:
    groups: list[tuple[str, list[tuple[str, Path]]]] = []
    for title, path in items.items():
        if " / " in title:
            section, label = title.split(" / ", 1)
        else:
            section, label = "Other", title
        if not groups or groups[-1][0] != section:
            groups.append((section, []))
        groups[-1][1].append((label, path))
    return groups


def _csv_to_markdown(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fields = reader.fieldnames or []
    if not fields:
        return ["No rows."]

    def esc(value: object) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ").strip()

    lines = [
        "| " + " | ".join(esc(field) for field in fields) + " |",
        "| " + " | ".join("---" for _ in fields) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(esc(row.get(field, "")) for field in fields) + " |")
    return lines


def write_markdown_summary(
    rows: list[dict[str, object]],
    plots: dict[str, Path],
    plot_notes: list[str],
    tables: dict[str, Path],
    output_dir: Path,
    plot_error: str | None,
    *,
    profile: str,
) -> Path:
    output_path = output_dir / "experiment-report.md"
    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]
    benign_rows = [row for row in rows if not SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]

    lines = [
        "# Experiment Report",
        "",
        "## Scope",
        "",
        f"- Dataset scope: {profile}",
        f"- Measured non-warmup runs included: {len(rows)}",
        f"- Attack runs: {len(attack_rows)}",
        f"- Benign runs: {len(benign_rows)}",
    ]
    for scenario in SCENARIO_ORDER_ALL:
        count = len(rows_for_scenario(rows, scenario))
        if count:
            lines.append(f"- {scenario}: {count} runs")

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "- This report now mirrors the checked-in analysis notebook rather than a smaller report-only subset.",
            f"- Detector mean attack-relative first-alert time: {format_float(row_mean([attack_relative_ttd(row, 'detector') for row in attack_rows]))} s.",
            f"- Zeek mean attack-relative first-alert time: {format_float(row_mean([attack_relative_ttd(row, 'zeek') for row in attack_rows]))} s.",
            f"- Suricata mean attack-relative first-alert time: {format_float(row_mean([attack_relative_ttd(row, 'suricata') for row in attack_rows]))} s.",
            f"- Detector mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('detector')) for row in rows]))}.",
            f"- Zeek mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('zeek')) for row in rows]))}.",
            f"- Suricata mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('suricata')) for row in rows]))}.",
        ]
    )

    lines.extend(["", "## Detection Summary", ""])
    lines.extend(_overall_confusion_lines(rows))

    lines.extend(["", "## Figures", ""])
    if plots:
        for section, entries in _sectioned(plots):
            lines.extend([f"### {section}", ""])
            for label, path in entries:
                rel = path_rel(path, output_dir)
                lines.extend([f"#### {label}", "", f"![{label}]({rel})", ""])
    else:
        lines.append("No figures were generated.")
        lines.append("")

    if plot_notes:
        lines.extend(["## Plot Notes", ""])
        for note in plot_notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.extend(["## Tables", ""])
    if tables:
        for section, entries in _sectioned(tables):
            lines.extend([f"### {section}", ""])
            for label, path in entries:
                rel = path_rel(path, output_dir)
                lines.extend([f"#### {label}", "", f"`{rel}`", ""])
                lines.extend(_csv_to_markdown(path))
                lines.append("")
    else:
        lines.append("No tables were generated.")
        lines.append("")

    if plot_error:
        lines.extend(["## Plot Status", "", f"- Plot generation skipped: {plot_error}", ""])

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path
