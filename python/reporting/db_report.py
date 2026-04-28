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
SCENARIO_LABELS = {
    "reliability-arp-mitm-dns": "ARP MITM + DNS",
    "reliability-dhcp-spoof": "Rogue DHCP",
}
BASIC_SCENARIO_LABELS = {
    "baseline": "Baseline",
    "arp-poison-no-forward": "ARP poison",
    "arp-mitm-forward": "ARP MITM",
    "arp-mitm-dns": "ARP MITM + DNS",
    "dhcp-spoof": "Rogue DHCP",
}
NORMAL_SCENARIOS = tuple(BASIC_SCENARIO_LABELS)
COMPARABLE_ATTACK = {
    "reliability-arp-mitm-dns": "dns_spoof",
    "reliability-dhcp-spoof": "dhcp_rogue_server",
}
COMPARABLE_ATTACK_LABELS = {
    "dns_spoof": "DNS spoof packets",
    "dhcp_rogue_server": "Rogue DHCP packets",
}
ATTACK_TYPE_LABELS = {
    "arp_spoof": "ARP spoof",
    "dns_spoof": "DNS spoof",
    "dns_source_violation": "DNS source violation",
    "dhcp_rogue_server": "Rogue DHCP",
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
    detector_ttd: float | None
    zeek_ttd: float | None
    suricata_ttd: float | None
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
            SELECT run_id, scenario, reliability_loss_percent, detector_max_processed_pps
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
                SELECT sensor, alert_count, supported_ttd_seconds
                FROM sensor_counts
                WHERE run_id = ? AND attack_type = ?
                """,
                (run["run_id"], attack_type),
            ).fetchall()
            sensors = {str(row["sensor"]): row for row in sensor_rows}

            def alerts(tool: str) -> int:
                row = sensors.get(tool)
                return int(row["alert_count"] or 0) if row is not None else 0

            def ttd(tool: str) -> float | None:
                row = sensors.get(tool)
                return _float_or_none(row["supported_ttd_seconds"]) if row is not None else None

            rows.append(
                DbRunMetric(
                    run_id=str(run["run_id"]),
                    scenario=scenario,
                    loss_percent=_int_loss(run["reliability_loss_percent"]),
                    truth_count=int(truth or 0),
                    detector_alerts=alerts("detector"),
                    zeek_alerts=alerts("zeek"),
                    suricata_alerts=alerts("suricata"),
                    detector_ttd=ttd("detector"),
                    zeek_ttd=ttd("zeek"),
                    suricata_ttd=ttd("suricata"),
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


def _tool_ttd(row: DbRunMetric, tool: str) -> float | None:
    return getattr(row, f"{tool}_ttd")


def _recall(row: DbRunMetric, tool: str) -> float | None:
    if row.truth_count <= 0:
        return None
    return min(_tool_alerts(row, tool), row.truth_count) / row.truth_count


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
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
                "detector_ttd_s": _mean_or_none([_tool_ttd(row, "detector") for row in group if row.detector_alerts > 0]),
                "zeek_ttd_s": _mean_or_none([_tool_ttd(row, "zeek") for row in group if row.zeek_alerts > 0]),
                "suricata_ttd_s": _mean_or_none([_tool_ttd(row, "suricata") for row in group if row.suricata_alerts > 0]),
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


def _wide_run_coverage_rows(summary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lookup = _summary_lookup(summary_rows)
    output: list[dict[str, Any]] = []
    for loss in _loss_levels(summary_rows):
        dns = lookup.get(("reliability-arp-mitm-dns", loss), {})
        dhcp = lookup.get(("reliability-dhcp-spoof", loss), {})
        output.append(
            {
                "loss_percent": loss,
                "dns_runs": dns.get("runs"),
                "dhcp_runs": dhcp.get("runs"),
                "dns_mean_truth_packets": dns.get("mean_truth_packets"),
                "dhcp_mean_truth_packets": dhcp.get("mean_truth_packets"),
            }
        )
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


def _basic_ttd_rows(db_path: Path) -> list[dict[str, Any]]:
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT scenario,
                   COUNT(*) AS runs,
                   AVG(detector_supported_ttd_seconds) AS detector_ttd_s,
                   AVG(zeek_supported_ttd_seconds) AS zeek_ttd_s,
                   AVG(suricata_supported_ttd_seconds) AS suricata_ttd_s
            FROM runs
            WHERE scenario IN ('arp-poison-no-forward', 'arp-mitm-forward', 'arp-mitm-dns', 'dhcp-spoof')
            GROUP BY scenario
            ORDER BY CASE scenario
                WHEN 'arp-poison-no-forward' THEN 1
                WHEN 'arp-mitm-forward' THEN 2
                WHEN 'arp-mitm-dns' THEN 3
                WHEN 'dhcp-spoof' THEN 4
                ELSE 99
            END
            """
        ).fetchall()
    return [
        {
            "scenario": str(row["scenario"]),
            "runs": int(row["runs"] or 0),
            "detector_ttd_s": row["detector_ttd_s"],
            "zeek_ttd_s": row["zeek_ttd_s"],
            "suricata_ttd_s": row["suricata_ttd_s"],
        }
        for row in rows
    ]


def _normal_run_rows(db_path: Path) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in NORMAL_SCENARIOS)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            f"""
            SELECT run_id, scenario, mode, started_at, duration_seconds,
                   attack_present, detector_alert_events, zeek_alert_events,
                   suricata_alert_events, detector_supported_ttd_seconds,
                   zeek_supported_ttd_seconds, suricata_supported_ttd_seconds
            FROM runs
            WHERE scenario IN ({placeholders})
            ORDER BY CASE scenario
                WHEN 'baseline' THEN 1
                WHEN 'arp-poison-no-forward' THEN 2
                WHEN 'arp-mitm-forward' THEN 3
                WHEN 'arp-mitm-dns' THEN 4
                WHEN 'dhcp-spoof' THEN 5
                ELSE 99
            END, started_at, run_id
            """,
            NORMAL_SCENARIOS,
        ).fetchall()
    return [dict(row) for row in rows]


def _normal_attack_type_rows(db_path: Path) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in NORMAL_SCENARIOS)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        scenario_runs = {
            str(row["scenario"]): int(row["runs"] or 0)
            for row in db.execute(
                f"""
                SELECT scenario, COUNT(*) AS runs
                FROM runs
                WHERE scenario IN ({placeholders})
                GROUP BY scenario
                """,
                NORMAL_SCENARIOS,
            )
        }
        rows = db.execute(
            f"""
            SELECT r.scenario, t.attack_type,
                   COUNT(*) AS truth_runs,
                   SUM(t.truth_count) AS truth_count_total,
                   AVG(t.truth_count) AS mean_truth_count,
                   SUM(COALESCE(d.alert_count, 0)) AS detector_alerts_total,
                   SUM(COALESCE(z.alert_count, 0)) AS zeek_alerts_total,
                   SUM(COALESCE(s.alert_count, 0)) AS suricata_alerts_total,
                   SUM(CASE WHEN COALESCE(d.alert_count, 0) > 0 THEN 1 ELSE 0 END) AS detector_detected_runs,
                   SUM(CASE WHEN COALESCE(z.alert_count, 0) > 0 THEN 1 ELSE 0 END) AS zeek_detected_runs,
                   SUM(CASE WHEN COALESCE(s.alert_count, 0) > 0 THEN 1 ELSE 0 END) AS suricata_detected_runs,
                   AVG(d.supported_ttd_seconds) AS detector_ttd_s,
                   AVG(z.supported_ttd_seconds) AS zeek_ttd_s,
                   AVG(s.supported_ttd_seconds) AS suricata_ttd_s
            FROM runs r
            JOIN truth_counts t ON t.run_id = r.run_id
            LEFT JOIN sensor_counts d ON d.run_id = r.run_id AND d.attack_type = t.attack_type AND d.sensor = 'detector'
            LEFT JOIN sensor_counts z ON z.run_id = r.run_id AND z.attack_type = t.attack_type AND z.sensor = 'zeek'
            LEFT JOIN sensor_counts s ON s.run_id = r.run_id AND s.attack_type = t.attack_type AND s.sensor = 'suricata'
            WHERE r.scenario IN ({placeholders})
            GROUP BY r.scenario, t.attack_type
            ORDER BY CASE r.scenario
                WHEN 'baseline' THEN 1
                WHEN 'arp-poison-no-forward' THEN 2
                WHEN 'arp-mitm-forward' THEN 3
                WHEN 'arp-mitm-dns' THEN 4
                WHEN 'dhcp-spoof' THEN 5
                ELSE 99
            END, t.attack_type
            """,
            NORMAL_SCENARIOS,
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        scenario = str(row["scenario"])
        truth_runs = int(row["truth_runs"] or 0)
        item = dict(row)
        item["scenario_runs"] = scenario_runs.get(scenario, 0)
        for tool in TOOL_ORDER:
            detected = int(item.get(f"{tool}_detected_runs") or 0)
            item[f"{tool}_detection_pct"] = (detected / truth_runs * 100.0) if truth_runs else None
        output.append(item)
    return output


def _normal_ttd_wide_rows(attack_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "scenario": row["scenario"],
            "attack_type": row["attack_type"],
            "scenario_runs": row["scenario_runs"],
            "truth_runs": row["truth_runs"],
            "detector_ttd_s": row["detector_ttd_s"],
            "zeek_ttd_s": row["zeek_ttd_s"],
            "suricata_ttd_s": row["suricata_ttd_s"],
        }
        for row in attack_rows
    ]


def _baseline_clean_alert_rows(normal_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    baseline = [row for row in normal_rows if row["scenario"] == "baseline"]
    if not baseline:
        return []
    return [
        {
            "scenario": "baseline",
            "runs": len(baseline),
            "detector_runs_with_alerts": sum(1 for row in baseline if int(row["detector_alert_events"] or 0) > 0),
            "zeek_runs_with_alerts": sum(1 for row in baseline if int(row["zeek_alert_events"] or 0) > 0),
            "suricata_runs_with_alerts": sum(1 for row in baseline if int(row["suricata_alert_events"] or 0) > 0),
            "detector_alerts_total": sum(int(row["detector_alert_events"] or 0) for row in baseline),
            "zeek_alerts_total": sum(int(row["zeek_alert_events"] or 0) for row in baseline),
            "suricata_alerts_total": sum(int(row["suricata_alert_events"] or 0) for row in baseline),
        }
    ]


def _plot_run_coverage(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = [scenario for scenario in SCENARIO_LABELS if any(row["scenario"] == scenario for row in summary_rows)]
    if not scenarios:
        return None
    losses = sorted({int(row["loss_percent"]) for row in summary_rows})
    fig, axes = plt.subplots(len(scenarios), 1, figsize=(10.6, max(3.6, 2.8 * len(scenarios))), sharex=True)
    if len(scenarios) == 1:
        axes = [axes]
    for ax, scenario in zip(axes, scenarios):
        values = [
            next((int(row["runs"]) for row in summary_rows if row["scenario"] == scenario and int(row["loss_percent"]) == loss), 0)
            for loss in losses
        ]
        bars = ax.bar(losses, values, width=6.5, color="#2f7a78")
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.25, str(value), ha="center", fontsize=9)
        ax.set_ylabel("Runs")
        ax.set_title(f"{SCENARIO_LABELS[scenario]} sample coverage")
        ax.set_ylim(0, max(values or [1]) + 3)
    axes[-1].set_xlabel("NetEm packet loss (%)")
    return _save_db(fig, output_dir / "figure-db-01-reliability-run-coverage.png", plt)


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
        ax.set_title(TOOL_LABELS[tool])
        ax.set_xlabel("NetEm packet loss (%)")
        ax.set_ylim(-4, 104)
        ax.axhline(100, color="#78716c", linewidth=1.0, linestyle="--", alpha=0.55)
        ax.set_xticks(losses)
        ax.tick_params(axis="x", rotation=45)
    axes[0].set_ylabel("Packet recall (%)")
    attack_label = COMPARABLE_ATTACK_LABELS[COMPARABLE_ATTACK[scenario]]
    fig.suptitle(f"{SCENARIO_LABELS[scenario]} packet-loss recall: {attack_label}", y=0.98, fontweight="bold")
    return _save_db(fig, output_dir / filename, plt, reserve_title=True)


def _plot_packet_recall_dns(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    return _plot_packet_recall_for_scenario(
        summary_rows,
        output_dir,
        plt,
        "reliability-arp-mitm-dns",
        "figure-db-02a-dns-packet-recall-by-detector.png",
    )


def _plot_packet_recall_dhcp(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    return _plot_packet_recall_for_scenario(
        summary_rows,
        output_dir,
        plt,
        "reliability-dhcp-spoof",
        "figure-db-02b-dhcp-packet-recall-by-detector.png",
    )


def _plot_packet_recall(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = [scenario for scenario in SCENARIO_LABELS if any(row["scenario"] == scenario for row in summary_rows)]
    if not scenarios:
        return None
    fig, axes = plt.subplots(len(scenarios), 3, figsize=(15.2, max(4.8, 3.8 * len(scenarios))), sharex=True, sharey=True)
    if len(scenarios) == 1:
        axes = np.array([axes])
    for row_index, scenario in enumerate(scenarios):
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        losses = sorted(int(row["loss_percent"]) for row in scenario_rows)
        attack_label = COMPARABLE_ATTACK_LABELS[COMPARABLE_ATTACK[scenario]]
        for col_index, tool in enumerate(TOOL_ORDER):
            ax = axes[row_index][col_index]
            values = [
                next(float(row[f"{tool}_recall_pct"]) for row in scenario_rows if int(row["loss_percent"]) == loss)
                for loss in losses
            ]
            ax.plot(losses, values, marker="o", linewidth=2.2, color=TOOL_COLORS[tool])
            ax.fill_between(losses, values, 0, color=TOOL_COLORS[tool], alpha=0.10)
            ax.set_ylim(-4, 104)
            for threshold in range(10, 100, 10):
                ax.axhline(threshold, color="#a8a29e", linewidth=0.75, linestyle="--", alpha=0.35)
            ax.axhline(100, color="#78716c", linewidth=1.0, linestyle="--", alpha=0.55)
            if row_index == 0:
                ax.set_title(TOOL_LABELS[tool])
            if col_index == 0:
                ax.set_ylabel(f"{SCENARIO_LABELS[scenario]}\n{attack_label}\nRecall (%)")
            if row_index == len(scenarios) - 1:
                ax.set_xlabel("NetEm packet loss (%)")
            ax.set_xticks(losses)
            ax.tick_params(axis="x", rotation=45)
    fig.suptitle("Comparable Packet Recall By Tool", y=1.01, fontweight="bold")
    return _save_db(fig, output_dir / "figure-db-02-comparable-packet-recall.png", plt, reserve_title=True)


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
                ax.set_title(TOOL_LABELS[tool])
            if col_index == 0:
                ax.set_ylabel(f"{SCENARIO_LABELS[scenario]}\nDetected runs (%)")
            if row_index == len(scenarios) - 1:
                ax.set_xlabel("NetEm packet loss (%)")
            ax.set_xticks(losses)
            ax.tick_params(axis="x", rotation=45)
    fig.suptitle("Detection Survival By Tool", y=0.98, fontweight="bold")
    return _save_db(fig, output_dir / "figure-db-03-detection-survival.png", plt, reserve_title=True)


def _plot_ttd_heatmap(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row_labels: list[str] = []
    matrix: list[list[float]] = []
    losses = sorted({int(row["loss_percent"]) for row in summary_rows})
    for scenario in SCENARIO_LABELS:
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        if not scenario_rows:
            continue
        for tool in TOOL_ORDER:
            row_labels.append(f"{SCENARIO_LABELS[scenario]} / {TOOL_LABELS[tool]}")
            matrix.append(
                [
                    math.nan
                    if (value := next((row[f"{tool}_ttd_s"] for row in scenario_rows if int(row["loss_percent"]) == loss), None)) is None
                    else float(value)
                    for loss in losses
                ]
            )
    if not matrix:
        return None
    data = np.array(matrix, dtype=float)
    if np.isnan(data).all():
        return None
    finite = data[np.isfinite(data)]
    vmax = max(1.0, float(np.nanpercentile(finite, 95))) if finite.size else 1.0
    fig, ax = plt.subplots(figsize=(13.2, max(4.8, len(row_labels) * 0.48)))
    cmap = plt.cm.YlOrRd.copy()
    cmap.set_bad("#e7e5e4")
    image = ax.imshow(np.ma.masked_invalid(data), aspect="auto", cmap=cmap, vmin=0.0, vmax=vmax)
    ax.set_xticks(range(len(losses)))
    ax.set_xticklabels([str(loss) for loss in losses], rotation=45, ha="right")
    ax.set_yticks(range(len(row_labels)))
    ax.set_yticklabels(row_labels)
    ax.set_xlabel("NetEm packet loss (%)")
    ax.set_title("Mean Time To First Comparable Alert")
    ax.grid(False)
    for row_index in range(data.shape[0]):
        for col_index in range(data.shape[1]):
            value = data[row_index, col_index]
            if np.isnan(value):
                label = "miss"
                color = "#7f1d1d"
            else:
                label = f"{value:.1f}"
                color = "#1c1917"
            ax.text(col_index, row_index, label, ha="center", va="center", fontsize=8, color=color)
    cbar = fig.colorbar(image, ax=ax, fraction=0.026, pad=0.02)
    cbar.set_label("Seconds")
    return _save_db(fig, output_dir / "figure-db-04-time-to-detection.png", plt)


def _plot_basic_ttd_heatmap(basic_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    if not basic_rows:
        return None
    scenarios = [row["scenario"] for row in basic_rows]
    matrix = np.array(
        [
            [
                math.nan if row.get(f"{tool}_ttd_s") is None else float(row[f"{tool}_ttd_s"])
                for tool in TOOL_ORDER
            ]
            for row in basic_rows
        ],
        dtype=float,
    )
    if np.isnan(matrix).all():
        return None
    finite = matrix[np.isfinite(matrix)]
    vmax = max(1.0, float(np.nanpercentile(finite, 95))) if finite.size else 1.0
    fig, ax = plt.subplots(figsize=(8.8, max(4.6, len(scenarios) * 0.72)))
    cmap = plt.cm.YlOrRd.copy()
    cmap.set_bad("#e7e5e4")
    image = ax.imshow(np.ma.masked_invalid(matrix), aspect="auto", cmap=cmap, vmin=0.0, vmax=vmax)
    ax.set_xticks(range(len(TOOL_ORDER)))
    ax.set_xticklabels([TOOL_LABELS[tool] for tool in TOOL_ORDER])
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels([BASIC_SCENARIO_LABELS.get(scenario, scenario) for scenario in scenarios])
    ax.set_title("Basic Scenario Mean Time To First Detection")
    ax.grid(False)
    for row_index in range(matrix.shape[0]):
        for col_index in range(matrix.shape[1]):
            value = matrix[row_index, col_index]
            label = "miss" if np.isnan(value) else f"{value:.2f}"
            color = "#7f1d1d" if np.isnan(value) else "#1c1917"
            ax.text(col_index, row_index, label, ha="center", va="center", fontsize=9, color=color)
    cbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Seconds")
    ax.text(
        0.0,
        -0.18,
        "This figure appears after basic attack runs are present in the SQLite database.",
        transform=ax.transAxes,
        fontsize=9,
        color="#57534e",
    )
    return _save_db(fig, output_dir / "figure-db-07-basic-scenario-ttd-heatmap.png", plt)


def _plot_normal_attack_ttd_heatmap(attack_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    rows = [row for row in attack_rows if any(row.get(f"{tool}_ttd_s") is not None for tool in TOOL_ORDER)]
    if not rows:
        return None
    matrix = np.array(
        [
            [
                math.nan if row.get(f"{tool}_ttd_s") is None else float(row[f"{tool}_ttd_s"])
                for tool in TOOL_ORDER
            ]
            for row in rows
        ],
        dtype=float,
    )
    finite = matrix[np.isfinite(matrix)]
    if not finite.size:
        return None
    row_labels = [
        f"{BASIC_SCENARIO_LABELS.get(str(row['scenario']), row['scenario'])} / {ATTACK_TYPE_LABELS.get(str(row['attack_type']), row['attack_type'])}"
        for row in rows
    ]
    vmax = max(1.0, float(np.nanpercentile(finite, 95)))
    fig, ax = plt.subplots(figsize=(9.8, max(4.8, len(row_labels) * 0.62)))
    cmap = plt.cm.YlOrRd.copy()
    cmap.set_bad("#e7e5e4")
    image = ax.imshow(np.ma.masked_invalid(matrix), aspect="auto", cmap=cmap, vmin=0.0, vmax=vmax)
    ax.set_xticks(range(len(TOOL_ORDER)))
    ax.set_xticklabels([TOOL_LABELS[tool] for tool in TOOL_ORDER])
    ax.set_yticks(range(len(row_labels)))
    ax.set_yticklabels(row_labels)
    ax.set_title("Normal Scenario Mean Time To First Alert By Evidence Type")
    ax.grid(False)
    for row_index in range(matrix.shape[0]):
        for col_index in range(matrix.shape[1]):
            value = matrix[row_index, col_index]
            label = "miss" if np.isnan(value) else f"{value:.2f}"
            color = "#7f1d1d" if np.isnan(value) else "#1c1917"
            ax.text(col_index, row_index, label, ha="center", va="center", fontsize=9, color=color)
    cbar = fig.colorbar(image, ax=ax, fraction=0.042, pad=0.04)
    cbar.set_label("Seconds")
    return _save_db(fig, output_dir / "figure-db-09-normal-scenario-attack-ttd-heatmap.png", plt, reserve_title=True)


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
    return _save_db(fig, output_dir / "figure-db-05-detector-processed-pps.png", plt)


def _plot_truth_volume(summary_rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = [scenario for scenario in SCENARIO_LABELS if any(row["scenario"] == scenario for row in summary_rows)]
    if not scenarios:
        return None
    fig, ax = plt.subplots(figsize=(10.6, 4.8))
    for scenario in scenarios:
        scenario_rows = [row for row in summary_rows if row["scenario"] == scenario]
        losses = sorted(int(row["loss_percent"]) for row in scenario_rows)
        values = [
            next(float(row["mean_truth_packets"]) for row in scenario_rows if int(row["loss_percent"]) == loss)
            for loss in losses
        ]
        ax.plot(losses, values, marker="o", linewidth=2.2, label=SCENARIO_LABELS[scenario])
    ax.set_xlabel("NetEm packet loss (%)")
    ax.set_ylabel("Mean comparable truth packets per run")
    ax.set_title("Unimpaired Ground-Truth Packet Opportunities")
    ax.legend()
    return _save_db(fig, output_dir / "figure-db-06-ground-truth-volume.png", plt)


def _write_markdown(
    output_dir: Path,
    db_path: Path,
    plots: dict[str, Path],
    notes: list[str],
    summary_rows: list[dict[str, Any]],
    basic_rows: list[dict[str, Any]],
) -> Path:
    lines = [
        "# SQLite Experiment Report",
        "",
        f"Source database: `{db_path}`",
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
        lines.extend(["", "## Basic Scenario TTD Coverage", ""])
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
    basic_rows = _basic_ttd_rows(db_path)
    normal_run_rows = _normal_run_rows(db_path)
    normal_attack_rows = _normal_attack_type_rows(db_path)
    _write_csv(output_dir / "table-db-01-reliability-summary.csv", summary_rows)
    _write_csv(
        output_dir / "table-db-02-run-level-comparable-events.csv",
        [
            {
                "run_id": row.run_id,
                "scenario": row.scenario,
                "loss_percent": row.loss_percent,
                "truth_count": row.truth_count,
                "detector_alerts": row.detector_alerts,
                "zeek_alerts": row.zeek_alerts,
                "suricata_alerts": row.suricata_alerts,
                "detector_recall_pct": _fmt((_recall(row, "detector") or 0.0) * 100.0),
                "zeek_recall_pct": _fmt((_recall(row, "zeek") or 0.0) * 100.0),
                "suricata_recall_pct": _fmt((_recall(row, "suricata") or 0.0) * 100.0),
            }
            for row in rows
        ],
    )
    _write_csv(output_dir / "table-db-03-basic-scenario-ttd.csv", basic_rows)
    _write_csv(output_dir / "table-db-04-thesis-packet-recall-wide.csv", _wide_reliability_rows(summary_rows, "recall_pct"))
    _write_csv(output_dir / "table-db-05-thesis-detection-survival-wide.csv", _wide_reliability_rows(summary_rows, "detection_pct"))
    _write_csv(output_dir / "table-db-06-thesis-time-to-detection-wide.csv", _wide_reliability_rows(summary_rows, "ttd_s"))
    _write_csv(output_dir / "table-db-07-thesis-run-coverage-wide.csv", _wide_run_coverage_rows(summary_rows))
    _write_csv(output_dir / "table-db-08-thesis-reliability-paste-table.csv", _thesis_reliability_table_rows(summary_rows))
    _write_csv(output_dir / "table-db-09-normal-run-summary.csv", normal_run_rows)
    _write_csv(output_dir / "table-db-10-normal-attack-type-summary.csv", normal_attack_rows)
    _write_csv(output_dir / "table-db-11-normal-attack-ttd-wide.csv", _normal_ttd_wide_rows(normal_attack_rows))
    _write_csv(output_dir / "table-db-12-baseline-clean-alert-summary.csv", _baseline_clean_alert_rows(normal_run_rows))

    plt = _require_matplotlib()
    _apply_style(plt)
    plots: dict[str, Path] = {}
    for title, builder in [
        ("DNS packet recall by detector", _plot_packet_recall_dns),
        ("DHCP packet recall by detector", _plot_packet_recall_dhcp),
        ("Detection survival", _plot_detection_survival),
        ("Time to detection", _plot_ttd_heatmap),
        ("Detector processed pps", _plot_detector_pps),
    ]:
        path = builder(summary_rows, output_dir, plt)
        if path is not None:
            plots[title] = path
    basic_ttd_path = _plot_basic_ttd_heatmap(basic_rows, output_dir, plt)
    if basic_ttd_path is not None:
        plots["Basic scenario mean time to first detection"] = basic_ttd_path
    normal_attack_ttd_path = _plot_normal_attack_ttd_heatmap(normal_attack_rows, output_dir, plt)
    if normal_attack_ttd_path is not None:
        plots["Normal scenario attack-type time to first alert"] = normal_attack_ttd_path

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
    if not basic_rows:
        notes.append("Basic-scenario TTD heatmap support is implemented, but no basic attack rows are present in the current SQLite database yet.")
    report_path = _write_markdown(output_dir, db_path, plots, notes, summary_rows, basic_rows)
    print(f"Wrote SQLite report figures, tables, and markdown to {output_dir}")
    return report_path
