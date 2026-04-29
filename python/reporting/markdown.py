from __future__ import annotations

import csv
from pathlib import Path

from reporting.common import (
    TOOL_LABELS,
    TOOL_ORDER,
    format_float,
    path_rel,
    row_mean,
    rows_for_scenario,
    tool_alert_field,
)
from scenarios.definitions import MAIN_SCENARIOS, RELIABILITY_SCENARIOS, SCENARIO_ATTACK_TYPES

SCENARIO_ORDER_ALL = [*MAIN_SCENARIOS, *RELIABILITY_SCENARIOS]


def _overall_detection_lines(rows: list[dict[str, object]]) -> list[str]:
    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]
    baseline_rows = [row for row in rows if str(row["scenario"]) == "baseline"]
    lines: list[str] = []
    for tool in TOOL_ORDER:
        attack_detected = sum(1 for row in attack_rows if bool(row.get(f"{tool}_detected")))
        baseline_alerts = sum(1 for row in baseline_rows if int(row.get(tool_alert_field(tool)) or 0) > 0)
        lines.append(
            f"- {TOOL_LABELS[tool]}: attack runs with alerts={attack_detected}/{len(attack_rows)}, "
            f"baseline runs with alerts={baseline_alerts}/{len(baseline_rows)}."
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
        f"- Runs included: {len(rows)}",
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
            "- The generated tables are limited to thesis-facing summaries; packet-forensics details remain in the raw run artifacts and dataset export.",
            f"- Detector mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('detector')) for row in rows]))}.",
            f"- Zeek mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('zeek')) for row in rows]))}.",
            f"- Suricata mean alert count per run: {format_float(row_mean([row.get(tool_alert_field('suricata')) for row in rows]))}.",
        ]
    )

    lines.extend(["", "## Run-Level Detection Summary", ""])
    lines.extend(_overall_detection_lines(rows))

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
