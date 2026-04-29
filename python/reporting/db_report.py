from __future__ import annotations

import csv
import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any

import numpy as np

from reporting.dataset import clear_report_outputs
from reporting.plots import TOOL_COLORS, _apply_style, _require_matplotlib

TOOL_ORDER = ["detector", "zeek", "suricata"]
TOOL_LABELS = {"detector": "Detector", "zeek": "Zeek", "suricata": "Suricata"}
CSV_PACKET_RECALL = "reliability-packet-recall.csv"
CSV_DETECTION_SURVIVAL = "reliability-detection-survival.csv"
CSV_RELIABILITY_SUMMARY = "reliability-summary.csv"
CSV_BASIC_SCENARIOS = "basic-scenario-summary.csv"
FIG_DNS_RECALL = "dns-packet-recall.png"
FIG_DHCP_RECALL = "dhcp-packet-recall.png"
FIG_DETECTION_SURVIVAL = "detection-survival.png"
FIG_DETECTOR_PPS = "detector-processed-pps.png"
SCENARIO_LABELS = {
    "reliability-arp-mitm-dns": "ARP MITM + DNS",
    "reliability-dhcp-spoof": "DHCP spoof",
}
BASIC_SCENARIO_LABELS = {
    "baseline": "Baseline",
    "arp-poison-no-forward": "ARP poison",
    "arp-mitm-forward": "ARP MITM",
    "arp-mitm-dns": "ARP MITM + DNS",
    "dhcp-spoof": "DHCP spoof",
}
NORMAL_SCENARIOS = tuple(BASIC_SCENARIO_LABELS)
COMPARABLE_ATTACK = {
    "reliability-arp-mitm-dns": "dns_spoof",
    "reliability-dhcp-spoof": "dhcp_rogue_server",
}
COMPARABLE_ATTACK_LABELS = {
    "dns_spoof": "DNS spoof packets",
    "dhcp_rogue_server": "DHCP spoof packets",
}
ATTACK_TYPE_LABELS = {
    "arp_spoof": "ARP spoof",
    "dns_spoof": "DNS spoof",
    "dns_source_violation": "DNS source violation",
    "dhcp_rogue_server": "DHCP spoof",
    "dhcp_untrusted_switch_port": "DHCP untrusted port",
}


def _save_db(fig: Any, output_path: Path, plt: Any, *, reserve_title: bool = False) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if reserve_title:
        fig.tight_layout(rect=(0, 0, 1, 0.94))
    else:
        fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)
    return output_path


@dataclass(frozen=True)
class DbRunMetric:
    run_id: str
    scenario: str
    loss_percent: int
    truth_count: int
    detector_alerts: int
    zeek_alerts: int
    suricata_alerts: int
    detector_processed_pps: float | None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _int_loss(value: Any) -> int:
    numeric = _float_or_none(value)
    if numeric is None:
        return 0
    return int(round(numeric))


def _mean_or_none(values: list[float | None]) -> float | None:
    clean = [float(value) for value in values if value is not None and math.isfinite(float(value))]
    return mean(clean) if clean else None


def _fmt(value: Any, digits: int = 3) -> str:
    numeric = _float_or_none(value)
    if numeric is None or not math.isfinite(numeric):
        return ""
    return f"{numeric:.{digits}f}"


def _metric_rows(db_path: Path) -> list[DbRunMetric]:
    rows: list[DbRunMetric] = []
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        run_rows = db.execute(
            """
            SELECT run_id, scenario, reliability_loss_percent, detector_max_processed_pps, ground_truth_source
            FROM runs
            WHERE scenario IN ('reliability-arp-mitm-dns', 'reliability-dhcp-spoof')
              AND reliability_loss_percent IS NOT NULL
            ORDER BY scenario, reliability_loss_percent, started_at, run_id
            """
        ).fetchall()
        for run in run_rows:
            scenario = str(run["scenario"])
            attack_type = COMPARABLE_ATTACK.get(scenario)
            if not attack_type:
                continue
            truth = db.execute(
                """
                SELECT COALESCE(SUM(truth_count), 0)
                FROM truth_counts
                WHERE run_id = ? AND attack_type = ?
                """,
                (run["run_id"], attack_type),
            ).fetchone()[0]
            sensor_rows = db.execute(
                """
                SELECT sensor, alert_count
                FROM sensor_counts
                WHERE run_id = ? AND attack_type = ?
                """,
                (run["run_id"], attack_type),
            ).fetchall()
            sensors = {str(row["sensor"]): row for row in sensor_rows}

            def alerts(tool: str) -> int:
                row = sensors.get(tool)
                return int(row["alert_count"] or 0) if row is not None else 0

            rows.append(
                DbRunMetric(
                    run_id=str(run["run_id"]),
                    scenario=scenario,
                    loss_percent=_int_loss(run["reliability_loss_percent"]),
                    truth_count=int(truth or 0),
                    detector_alerts=alerts("detector"),
                    zeek_alerts=alerts("zeek"),
                    suricata_alerts=alerts("suricata"),
                    detector_processed_pps=_float_or_none(run["detector_max_processed_pps"]),
                )
            )
    return rows


def _grouped(rows: list[DbRunMetric]) -> dict[tuple[str, int], list[DbRunMetric]]:
    groups: dict[tuple[str, int], list[DbRunMetric]] = {}
    for row in rows:
        groups.setdefault((row.scenario, row.loss_percent), []).append(row)
    return dict(sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])))


def _tool_alerts(row: DbRunMetric, tool: str) -> int:
    return int(getattr(row, f"{tool}_alerts"))


def _recall(row: DbRunMetric, tool: str) -> float | None:
    if row.truth_count <= 0:
        return None
    return min(_tool_alerts(row, tool), row.truth_count) / row.truth_count


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return path


def _coverage_rows(rows: list[DbRunMetric]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for (scenario, loss), group in _grouped(rows).items():
        output.append(
            {
                "scenario": scenario,
                "loss_percent": loss,
                "runs": len(group),
                "mean_truth_packets": _mean_or_none([float(row.truth_count) for row in group]),
                "detector_detection_pct": sum(1 for row in group if row.detector_alerts > 0) / len(group) * 100.0,
                "zeek_detection_pct": sum(1 for row in group if row.zeek_alerts > 0) / len(group) * 100.0,
                "suricata_detection_pct": sum(1 for row in group if row.suricata_alerts > 0) / len(group) * 100.0,
                "detector_recall_pct": (_mean_or_none([_recall(row, "detector") for row in group]) or 0.0) * 100.0,
                "zeek_recall_pct": (_mean_or_none([_recall(row, "zeek") for row in group]) or 0.0) * 100.0,
                "suricata_recall_pct": (_mean_or_none([_recall(row, "suricata") for row in group]) or 0.0) * 100.0,
                "detector_processed_pps": _mean_or_none([row.detector_processed_pps for row in group]),
            }
        )
    return output


def _summary_lookup(summary_rows: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (str(row["scenario"]), int(row["loss_percent"])): row
        for row in summary_rows
    }


def _loss_levels(summary_rows: list[dict[str, Any]]) -> list[int]:
    return sorted({int(row["loss_percent"]) for row in summary_rows})


def _wide_reliability_rows(summary_rows: list[dict[str, Any]], metric_suffix: str) -> list[dict[str, Any]]:
    lookup = _summary_lookup(summary_rows)
    output: list[dict[str, Any]] = []
    for loss in _loss_levels(summary_rows):
        row: dict[str, Any] = {"loss_percent": loss}
        for scenario, prefix in [
            ("reliability-arp-mitm-dns", "dns"),
            ("reliability-dhcp-spoof", "dhcp"),
        ]:
            source = lookup.get((scenario, loss), {})
            for tool in TOOL_ORDER:
                row[f"{prefix}_{tool}"] = source.get(f"{tool}_{metric_suffix}")
        output.append(row)
    return output


def _thesis_reliability_table_rows(summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lookup = _summary_lookup(summary_rows)
    output: list[dict[str, Any]] = []
    for loss in _loss_levels(summary_rows):
        dns = lookup.get(("reliability-arp-mitm-dns", loss), {})
        dhcp = lookup.get(("reliability-dhcp-spoof", loss), {})
        output.append(
            {
                "loss_percent": loss,
                "dns_detector_recall_pct": dns.get("detector_recall_pct"),
                "dns_zeek_recall_pct": dns.get("zeek_recall_pct"),
                "dns_suricata_recall_pct": dns.get("suricata_recall_pct"),
                "dhcp_detector_recall_pct": dhcp.get("detector_recall_pct"),
                "dhcp_zeek_recall_pct": dhcp.get("zeek_recall_pct"),
                "dhcp_suricata_recall_pct": dhcp.get("suricata_recall_pct"),
                "dns_detector_survival_pct": dns.get("detector_detection_pct"),
                "dns_zeek_survival_pct": dns.get("zeek_detection_pct"),
                "dns_suricata_survival_pct": dns.get("suricata_detection_pct"),
                "dhcp_detector_survival_pct": dhcp.get("detector_detection_pct"),
                "dhcp_zeek_survival_pct": dhcp.get("zeek_detection_pct"),
                "dhcp_suricata_survival_pct": dhcp.get("suricata_detection_pct"),
            }
        )
    return output


def _basic_scenario_summary_rows(db_path: Path) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in NORMAL_SCENARIOS)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            f"""
            WITH truth_per_run AS (
                SELECT run_id, SUM(truth_count) AS trusted_attack_observations
                FROM truth_counts
                GROUP BY run_id
            )
            SELECT r.scenario,
                   COUNT(*) AS runs,
                   AVG(r.duration_seconds) AS duration_s,
                   SUM(COALESCE(t.trusted_attack_observations, 0)) AS trusted_attack_observations_total,
                   AVG(COALESCE(t.trusted_attack_observations, 0)) AS trusted_attack_observations_per_run,
                   SUM(r.detector_alert_events) AS detector_alerts_total,
                   SUM(r.zeek_alert_events) AS zeek_alerts_total,
                   SUM(r.suricata_alert_events) AS suricata_alerts_total,
                   AVG(r.detector_alert_events) AS detector_alerts_per_run,
                   AVG(r.zeek_alert_events) AS zeek_alerts_per_run,
                   AVG(r.suricata_alert_events) AS suricata_alerts_per_run
            FROM runs r
            LEFT JOIN truth_per_run t ON t.run_id = r.run_id
            WHERE r.scenario IN ({placeholders})
            GROUP BY r.scenario
            ORDER BY CASE r.scenario
                WHEN 'baseline' THEN 1
                WHEN 'arp-poison-no-forward' THEN 2
                WHEN 'arp-mitm-forward' THEN 3
                WHEN 'arp-mitm-dns' THEN 4
                WHEN 'dhcp-spoof' THEN 5
                ELSE 99
            END
            """,
            NORMAL_SCENARIOS,
        ).fetchall()
    return [dict(row) for row in rows]


def _plot_packet_recall_for_scenario(
    summary_rows: list[dict[str, Any]],
    output_dir: Path,
    plt: Any,
    scenario: str,
    filename: str,
) -> Path | None:
    scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
    if not scenario_rows:
        return None
    losses = sorted(int(row["loss_percent"]) for row in scenario_rows)
    fig, axes = plt.subplots(1, 3, figsize=(15.2, 4.8), sharey=True)
    for ax, tool in zip(axes, TOOL_ORDER):
        values = [
            next(float(row[f"{tool}_recall_pct"]) for row in scenario_rows if int(row["loss_percent"]) == loss)
            for loss in losses
        ]
        ax.plot(losses, values, marker="o", linewidth=2.4, color=TOOL_COLORS[tool])
        ax.fill_between(losses, values, 0, color=TOOL_COLORS[tool], alpha=0.10)
        for threshold in range(10, 100, 10):
            ax.axhline(threshold, color="#a8a29e", linewidth=0.75, linestyle="--", alpha=0.35)
        ax.set_title(TOOL_LABELS[tool], fontsize=16, fontweight="bold")
        ax.set_xlabel("NetEm packet loss (%)")
        ax.set_ylim(-4, 104)
        ax.axhline(100, color="#78716c", linewidth=1.0, linestyle="--", alpha=0.55)
        ax.set_xticks(losses)
        ax.tick_params(axis="x", rotation=45)
    axes[0].set_ylabel("Packet recall (%)")
    attack_label = COMPARABLE_ATTACK_LABELS[COMPARABLE_ATTACK[scenario]]
    fig.suptitle(
        f"{SCENARIO_LABELS[scenario]} packet-loss recall: {attack_label}",
        y=0.985,
        fontsize=20,
        fontweight="bold",
    )
    return _save_db(fig, output_dir / filename, plt, reserve_title=True)


def _plot_packet_recall_dns(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    return _plot_packet_recall_for_scenario(
        summary_rows,
        output_dir,
        plt,
        "reliability-arp-mitm-dns",
        FIG_DNS_RECALL,
    )


def _plot_packet_recall_dhcp(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    return _plot_packet_recall_for_scenario(
        summary_rows,
        output_dir,
        plt,
        "reliability-dhcp-spoof",
        FIG_DHCP_RECALL,
    )


def _plot_detection_survival(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = [scenario for scenario in SCENARIO_LABELS if any(row["scenario"] == scenario for row in summary_rows)]
    if not scenarios:
        return None
    fig, axes = plt.subplots(len(scenarios), 3, figsize=(15.2, max(4.8, 3.8 * len(scenarios))), sharex=True, sharey=True)
    if len(scenarios) == 1:
        axes = np.array([axes])
    for row_index, scenario in enumerate(scenarios):
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        losses = sorted(int(row["loss_percent"]) for row in scenario_rows)
        for col_index, tool in enumerate(TOOL_ORDER):
            ax = axes[row_index][col_index]
            values = [
                next(float(row[f"{tool}_detection_pct"]) for row in scenario_rows if int(row["loss_percent"]) == loss)
                for loss in losses
            ]
            ax.plot(losses, values, marker="o", linewidth=2.4, color=TOOL_COLORS[tool])
            ax.fill_between(losses, values, 0, color=TOOL_COLORS[tool], alpha=0.10)
            ax.set_ylim(-4, 104)
            for threshold in range(10, 100, 10):
                ax.axhline(threshold, color="#a8a29e", linewidth=0.75, linestyle="--", alpha=0.35)
            ax.axhline(100, color="#78716c", linewidth=1.0, linestyle="--", alpha=0.55)
            if row_index == 0:
                ax.set_title(TOOL_LABELS[tool], fontsize=16, fontweight="bold")
            if col_index == 0:
                ax.set_ylabel(f"{SCENARIO_LABELS[scenario]}\nDetected runs (%)")
            if row_index == len(scenarios) - 1:
                ax.set_xlabel("NetEm packet loss (%)")
            ax.set_xticks(losses)
            ax.tick_params(axis="x", rotation=45)
    fig.suptitle("Detection Survival By Tool", y=0.985, fontsize=20, fontweight="bold")
    return _save_db(fig, output_dir / FIG_DETECTION_SURVIVAL, plt, reserve_title=True)


def _plot_detector_pps(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = [scenario for scenario in SCENARIO_LABELS if any(row["scenario"] == scenario for row in summary_rows)]
    if not scenarios:
        return None
    fig, ax = plt.subplots(figsize=(10.6, 4.8))
    for scenario in scenarios:
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        losses = sorted(int(row["loss_percent"]) for row in scenario_rows)
        values = [
            next(row["detector_processed_pps"] for row in scenario_rows if int(row["loss_percent"]) == loss)
            for loss in losses
        ]
        ax.plot(losses, [math.nan if value is None else float(value) for value in values], marker="o", linewidth=2.2, label=SCENARIO_LABELS[scenario])
    ax.set_xlabel("NetEm packet loss (%)")
    ax.set_ylabel("Detector max processed pps")
    ax.set_title("Detector Throughput Telemetry Only")
    ax.legend()
    return _save_db(fig, output_dir / FIG_DETECTOR_PPS, plt)


def _write_markdown(
    output_dir: Path,
    db_path: Path,
    plots: dict[str, Path],
    notes: list[str],
    summary_rows: list[dict[str, Any]],
    basic_rows: list[dict[str, Any]],
) -> Path:
    lines = [
        "# Experiment Report",
        "",
        f"Result source: `{db_path}`",
        "",
        "## Tables",
        "",
        f"- Reliability packet recall: `{CSV_PACKET_RECALL}`",
        f"- Reliability detection survival: `{CSV_DETECTION_SURVIVAL}`",
        f"- Reliability summary: `{CSV_RELIABILITY_SUMMARY}`",
        f"- Basic scenario summary: `{CSV_BASIC_SCENARIOS}`",
        "",
        "## Figures",
        "",
    ]
    for title, path in plots.items():
        lines.append(f"- {title}: `{path.name}`")
    lines.extend(["", "## Notes", ""])
    for note in notes:
        lines.append(f"- {note}")
    lines.extend(["", "## Run Coverage", ""])
    for scenario in SCENARIO_LABELS:
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        if not scenario_rows:
            continue
        counts = ", ".join(f"{int(row['loss_percent'])}%={int(row['runs'])}" for row in scenario_rows)
        lines.append(f"- {SCENARIO_LABELS[scenario]}: {counts}")
    if basic_rows:
        lines.extend(["", "## Basic Scenario Coverage", ""])
        for row in basic_rows:
            lines.append(f"- {BASIC_SCENARIO_LABELS.get(row['scenario'], row['scenario'])}: {int(row['runs'])} runs")
    path = output_dir / "experiment-report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_db_report(db_path: Path, output_dir: Path) -> Path:
    if db_path.is_dir():
        db_path = db_path / "experiment-results.sqlite"
    if not db_path.exists():
        raise SystemExit(f"Results database does not exist: {db_path}")

    rows = _metric_rows(db_path)
    if not rows:
        raise SystemExit(f"No reliability rows found in {db_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    clear_report_outputs(output_dir)
    summary_rows = _coverage_rows(rows)
    basic_summary_rows = _basic_scenario_summary_rows(db_path)
    # Keep only thesis-facing CSVs in the report directory. Raw run-level and
    # internal coverage tables stay in SQLite, where they are easier to query.
    _write_csv(output_dir / CSV_PACKET_RECALL, _wide_reliability_rows(summary_rows, "recall_pct"))
    _write_csv(output_dir / CSV_DETECTION_SURVIVAL, _wide_reliability_rows(summary_rows, "detection_pct"))
    _write_csv(output_dir / CSV_RELIABILITY_SUMMARY, _thesis_reliability_table_rows(summary_rows))
    _write_csv(output_dir / CSV_BASIC_SCENARIOS, basic_summary_rows)

    plt = _require_matplotlib()
    _apply_style(plt)
    plots: dict[str, Path] = {}
    for title, builder in [
        ("DNS packet recall by detector", _plot_packet_recall_dns),
        ("DHCP packet recall by detector", _plot_packet_recall_dhcp),
        ("Detection survival", _plot_detection_survival),
        ("Detector processed pps", _plot_detector_pps),
    ]:
        path = builder(summary_rows, output_dir, plt)
        if path is not None:
            plots[title] = path
    run_counts = {(row["scenario"], int(row["loss_percent"])): int(row["runs"]) for row in summary_rows}
    dhcp_low = [run_counts.get(("reliability-dhcp-spoof", loss), 0) for loss in range(0, 70, 10)]
    dhcp_high = [run_counts.get(("reliability-dhcp-spoof", loss), 0) for loss in range(70, 101, 10)]
    notes = [
        "ARP packet-level recall is intentionally excluded: OVS ARP counters prove attack presence, but their unit is a switch-level trust violation rather than a one-to-one semantic alert.",
        "DHCP untrusted-switch-port evidence is intentionally excluded from equal detector comparison because it uses OVS ingress-port context unavailable to Zeek and Suricata on the packet-only feed.",
        "Zeek and Suricata pps telemetry is intentionally not plotted because their pps values are derived from tool log/stat intervals and are not measured on the same packet-processing loop as Detector telemetry.",
        "Detector pps is shown only as detector telemetry, not as a cross-tool throughput comparison.",
    ]
    if dhcp_low and dhcp_high and max(dhcp_low) != min(dhcp_high):
        notes.append(
            "DHCP has extra repetitions at lower packet-loss levels after an earlier command used the default loss sweep; the run-coverage counts below show the resulting sample size imbalance."
        )
    report_path = _write_markdown(output_dir, db_path, plots, notes, summary_rows, basic_summary_rows)
    print(f"Wrote SQLite report figures, tables, and markdown to {output_dir}")
    return report_path
