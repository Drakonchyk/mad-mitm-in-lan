from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np

from metrics.model import ATTACK_TYPE_LABELS, ATTACK_TYPE_ORDER
from metrics.run_artifacts import detector_delta_path, load_json, load_jsonl, parse_traffic_windows
from reporting.common import (
    COMPOSITION_SERIES,
    SCENARIO_LABELS,
    TOOL_LABELS,
    TOOL_ORDER,
    attack_relative_ttd,
    representative_probe_series,
    representative_row,
    row_mean,
    rows_for_scenario,
    run_dir_for_row,
    seconds_between,
    tool_alert_field,
    tool_first_alert_timestamp,
)
from scenarios.definitions import MAIN_SCENARIOS, SCENARIO_ATTACK_TYPES, SUPPLEMENTARY_SCENARIOS

SCENARIO_ORDER_ALL = [*MAIN_SCENARIOS, *SUPPLEMENTARY_SCENARIOS]
TOOL_COLORS = {"detector": "#1d4ed8", "zeek": "#d97706", "suricata": "#0f766e"}
SCENARIO_COLORS = {
    "baseline": "#94a3b8",
    "arp-poison-no-forward": "#ef4444",
    "arp-mitm-forward": "#f97316",
    "arp-mitm-dns": "#2563eb",
    "dhcp-spoof": "#0f766e",
    "mitigation-recovery": "#14b8a6",
    "intermittent-arp-mitm-dns": "#7c3aed",
    "intermittent-dhcp-spoof": "#0891b2",
    "dhcp-offer-only": "#22c55e",
    "noisy-benign-baseline": "#64748b",
    "reduced-observability": "#db2777",
}
SEMANTIC_EVENT_COLORS = {
    "gateway_mac_changed": "#dc2626",
    "multiple_gateway_macs_seen": "#ea580c",
    "icmp_redirects_seen": "#2563eb",
    "rogue_dhcp_server_seen": "#0f766e",
    "dhcp_binding_conflict_seen": "#10b981",
    "domain_resolution_changed": "#7c3aed",
    "gateway_mac_restored": "#16a34a",
    "domain_resolution_restored": "#0f766e",
    "arp_spoof_packet_seen": "#ef4444",
    "icmp_redirect_packet_seen": "#3b82f6",
    "dns_spoof_packet_seen": "#8b5cf6",
}


def _require_matplotlib():
    try:
        import matplotlib.pyplot as plt  # noqa: PLC0415
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install matplotlib to build experiment-report figures") from exc
    return plt


def _apply_style(plt: Any) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "#fffdf8",
            "axes.edgecolor": "#d6d3d1",
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": "#d6d3d1",
            "grid.alpha": 0.30,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.titleweight": "bold",
            "axes.titlesize": 14,
            "legend.frameon": False,
            "font.family": "DejaVu Serif",
            "figure.max_open_warning": 0,
        }
    )


def _save(fig: Any, output_path: Path, plt: Any) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)
    return output_path


def _scenario_order(rows: list[dict[str, Any]]) -> list[str]:
    return [scenario for scenario in SCENARIO_ORDER_ALL if rows_for_scenario(rows, scenario)]


def _attack_scenarios(rows: list[dict[str, Any]]) -> list[str]:
    return [scenario for scenario in _scenario_order(rows) if SCENARIO_ATTACK_TYPES.get(str(scenario))]


def _mean_or_none(values: list[float | None]) -> float | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    return sum(clean) / len(clean)


def _mean_counter_value(rows: list[dict[str, Any]], field_name: str, key: str) -> float:
    values = [float((row.get(field_name, {}) or {}).get(key, 0) or 0) for row in rows]
    return _mean_or_none(values) or 0.0


def _choose_representative_run(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return representative_row(
        rows,
        ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"],
        lambda row: any(row.get(field) is not None for field in ["detector_first_alert_at_native", "zeek_first_alert_at", "suricata_first_alert_at"]),
    )


def _timing_reference_info(row: dict[str, Any]) -> dict[str, float | str | None]:
    evaluation = load_json(run_dir_for_row(row) / "evaluation.json")
    return {
        "planned_start": seconds_between(row.get("started_at"), row.get("attack_started_at")),
        "planned_stop": seconds_between(row.get("started_at"), row.get("attack_stopped_at")),
        "observed_start": seconds_between(row.get("started_at"), evaluation.get("ground_truth_attack_started_at")),
        "observed_start_ts": evaluation.get("ground_truth_attack_started_at"),
    }


def _add_time_context(ax: Any, row: dict[str, Any]) -> dict[str, float | str | None]:
    info = _timing_reference_info(row)
    planned_start = info["planned_start"]
    planned_stop = info["planned_stop"]
    observed_start = info["observed_start"]
    if isinstance(planned_start, (int, float)) and isinstance(planned_stop, (int, float)) and planned_stop >= planned_start:
        ax.axvspan(planned_start, planned_stop, color="#e7e5e4", alpha=0.42)
    if isinstance(observed_start, (int, float)):
        ax.axvline(observed_start, color="#b91c1c", linewidth=1.5, linestyle="--")
    ax.text(0.01, 0.97, "gray = planned phase, red dashed = first observed attack evidence", transform=ax.transAxes, va="top", fontsize=8)
    return info


def _plot_detection_rate_matrix(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    matrix = []
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        matrix.append(
            [
                sum(1 for row in scenario_rows if row.get(f"{tool}_detected")) / len(scenario_rows) * 100.0 if scenario_rows else math.nan
                for tool in TOOL_ORDER
            ]
        )
    fig, ax = plt.subplots(figsize=(7.2, max(4, len(scenarios) * 0.6)))
    image = ax.imshow(matrix, aspect="auto", cmap="YlGnBu", vmin=0, vmax=100)
    ax.set_xticks(range(len(TOOL_ORDER)))
    ax.set_xticklabels([TOOL_LABELS[tool] for tool in TOOL_ORDER])
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels([SCENARIO_LABELS[scenario] for scenario in scenarios])
    ax.set_title("Detection Rate Matrix")
    for row_index, values in enumerate(matrix):
        for col_index, value in enumerate(values):
            ax.text(col_index, row_index, "n/a" if math.isnan(value) else f"{value:.0f}%", ha="center", va="center", fontsize=9)
    fig.colorbar(image, ax=ax, label="Detection rate (%)")
    return _save(fig, output_dir / "figure-01-detection-rate-matrix.png", plt)


def _plot_detection_rate_grouped_bars(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = list(range(len(labels)))
    width = 0.24
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.15), 4.8))
    for index, tool in enumerate(TOOL_ORDER):
        values = []
        for scenario in scenarios:
            scenario_rows = rows_for_scenario(rows, scenario)
            values.append(sum(1 for row in scenario_rows if row.get(f"{tool}_detected")) / len(scenario_rows) * 100.0 if scenario_rows else math.nan)
        ax.bar([position + (index - 1) * width for position in positions], values, width=width, label=TOOL_LABELS[tool], color=TOOL_COLORS[tool])
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Detection rate (%)")
    ax.set_title("Detection Rate By Scenario")
    ax.legend()
    return _save(fig, output_dir / "figure-02-detection-rate-by-scenario.png", plt)


def _plot_mean_alert_volume(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    positions = np.arange(len(scenarios))
    width = 0.25
    fig, ax = plt.subplots(figsize=(max(9, len(scenarios) * 1.18), 5.0))
    for index, tool in enumerate(TOOL_ORDER):
        values = [_mean_or_none([row.get(tool_alert_field(tool)) for row in rows_for_scenario(rows, scenario)]) or 0.0 for scenario in scenarios]
        bars = ax.bar(positions + (index - 1) * width, values, width=width, color=TOOL_COLORS[tool], label=TOOL_LABELS[tool])
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.45, f"{value:.1f}", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(positions)
    ax.set_xticklabels(scenarios, rotation=28, ha="right")
    ax.set_ylabel("Mean alerts per run")
    ax.set_title("Mean Alert Volume By Scenario")
    ax.legend(loc="upper left")
    return _save(fig, output_dir / "figure-03-mean-alert-volume-by-scenario.png", plt)


def _plot_detector_semantic_composition(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    fields = [
        ("gateway_mac_changed", "Gateway MAC Changed", "#ef4444"),
        ("multiple_gateway_macs_seen", "Multiple Gateway MACs", "#f97316"),
        ("icmp_redirects_seen", "ICMP Redirects", "#2563eb"),
        ("rogue_dhcp_server_seen", "Rogue DHCP Server", "#0f766e"),
        ("dhcp_binding_conflict_seen", "DHCP Binding Conflict", "#10b981"),
        ("domain_resolution_changed", "Domain Resolution Changed", "#7c3aed"),
        ("restoration_events", "Restoration Events", "#16a34a"),
    ]
    bottoms = np.zeros(len(scenarios))
    fig, ax = plt.subplots(figsize=(max(10, len(scenarios) * 1.2), 5.3))
    for field_name, label, color in fields:
        values = np.array([_mean_or_none([row.get(field_name, 0) for row in rows_for_scenario(rows, scenario)]) or 0.0 for scenario in scenarios])
        ax.bar(scenarios, values, bottom=bottoms, label=label, color=color)
        bottoms = bottoms + values
    ax.set_ylabel("Mean semantic-event count per run")
    ax.set_title("Detector Semantic Alert Composition")
    ax.tick_params(axis="x", rotation=28)
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-04-detector-semantic-alert-composition.png", plt)


def _plot_attack_relative_ttd_heatmap(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _attack_scenarios(rows)
    if not scenarios:
        return None
    matrix = []
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        matrix.append([_mean_or_none([attack_relative_ttd(row, tool) for row in scenario_rows]) for tool in TOOL_ORDER])
    matrix_np = np.array([[np.nan if value is None else float(value) for value in row] for row in matrix], dtype=float)
    fig, ax = plt.subplots(figsize=(7.1, 4.8))
    cmap = plt.cm.YlOrRd.copy()
    cmap.set_bad(color="#f5f5f4")
    image = ax.imshow(matrix_np, cmap=cmap, aspect="auto")
    ax.set_xticks(range(len(TOOL_ORDER)))
    ax.set_xticklabels([TOOL_LABELS[tool] for tool in TOOL_ORDER], rotation=20)
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels(scenarios)
    ax.set_title("Mean Attack-Relative Time-To-Detection")
    for row_index in range(matrix_np.shape[0]):
        for col_index in range(matrix_np.shape[1]):
            value = matrix_np[row_index, col_index]
            ax.text(col_index, row_index, "n/a" if np.isnan(value) else f"{value:.2f}", ha="center", va="center", color="#111827", fontsize=10)
    fig.colorbar(image, ax=ax, fraction=0.048, pad=0.04)
    return _save(fig, output_dir / "figure-05-mean-attack-relative-time-to-detection.png", plt)


def _plot_attack_relative_ttd_distributions(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _attack_scenarios(rows)
    if not scenarios:
        return None
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.2), sharey=True)
    rng = np.random.default_rng(7)
    fill_colors = {"detector": "#a5b4fc", "zeek": "#fcd34d", "suricata": "#99f6e4"}
    point_colors = {"detector": "#1d4ed8", "zeek": "#d97706", "suricata": "#0f766e"}
    for ax, tool in zip(axes, TOOL_ORDER):
        series = []
        for scenario in scenarios:
            values = [float(attack_relative_ttd(row, tool)) for row in rows_for_scenario(rows, scenario) if attack_relative_ttd(row, tool) is not None]
            series.append(values)
        safe_series = [values if values else [np.nan] for values in series]
        box = ax.boxplot(safe_series, labels=scenarios, patch_artist=True, showfliers=False, showmeans=True, meanprops={"marker": "+", "markeredgecolor": point_colors[tool], "markersize": 10})
        for patch in box["boxes"]:
            patch.set_facecolor(fill_colors[tool])
            patch.set_alpha(0.45)
        for median in box["medians"]:
            median.set_color("#111827")
        for whisker in box["whiskers"]:
            whisker.set_color("#111827")
        for cap in box["caps"]:
            cap.set_color("#111827")
        for idx, values in enumerate(series, start=1):
            if not values:
                continue
            jitter = rng.normal(idx, 0.06, len(values))
            ax.scatter(jitter, values, s=24, color=point_colors[tool], alpha=0.78, edgecolors="white", linewidths=0.35)
        ax.set_title(TOOL_LABELS[tool])
        ax.set_ylabel("Time from attack start to first alert (s)")
        ax.tick_params(axis="x", rotation=28)
    fig.suptitle("Attack-Relative Detection-Time Distributions", y=1.03)
    return _save(fig, output_dir / "figure-06-attack-relative-detection-time-distributions.png", plt)


def _plot_attack_relative_ttd_ecdf(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]
    if not attack_rows:
        return None
    fig, ax = plt.subplots(figsize=(8, 4.8))
    for tool in TOOL_ORDER:
        values = sorted(float(attack_relative_ttd(row, tool)) for row in attack_rows if attack_relative_ttd(row, tool) is not None)
        if not values:
            continue
        ys = [(index + 1) / len(values) for index in range(len(values))]
        ax.step(values, ys, where="post", linewidth=2, color=TOOL_COLORS[tool], label=TOOL_LABELS[tool])
    ax.set_xlabel("Attack-relative timing (s)")
    ax.set_ylabel("Fraction of attack runs")
    ax.set_title("ECDF Of Attack-Relative Time To First Alert")
    ax.legend()
    return _save(fig, output_dir / "figure-07-ecdf-of-attack-relative-timing.png", plt)


def _plot_first_alert_winner_count(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]
    if not attack_rows:
        return None
    counts = {tool: 0 for tool in TOOL_ORDER}
    for row in attack_rows:
        options = []
        for tool in TOOL_ORDER:
            value = attack_relative_ttd(row, tool)
            if value is not None:
                options.append((value, tool))
        if options:
            counts[min(options)[1]] += 1
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    labels = [TOOL_LABELS[tool] for tool in TOOL_ORDER]
    values = [counts[tool] for tool in TOOL_ORDER]
    ax.bar(labels, values, color=[TOOL_COLORS[tool] for tool in TOOL_ORDER])
    ax.set_ylabel("Attack runs where the tool was first")
    ax.set_title("First-Alert Winner Count")
    return _save(fig, output_dir / "figure-08-first-alert-winner-count.png", plt)


def _plot_detector_recovery_timing(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    values = [float(row["detector_recovery_seconds"]) for row in rows if row.get("detector_recovery_seconds") is not None]
    if not values:
        return None
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.boxplot([values], labels=["mitigation-recovery"], patch_artist=True, showfliers=False)
    ax.set_ylabel("Time to first restoration event (s)")
    ax.set_title("Detector Recovery Timing")
    return _save(fig, output_dir / "figure-09-detector-recovery-timing.png", plt)


def _plot_operational_metrics(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    specs = [
        ("ping_gateway_avg_ms", "Gateway ping latency\n(ms)", "Gateway ping latency (ms)", "#1d4ed8"),
        ("curl_total_s", "Curl time_total\n(s)", "Curl time_total (s)", "#ea580c"),
        ("iperf_mbps", "iperf3 throughput\n(Mbps)", "iperf3 throughput (Mbps)", "#0f766e"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.4))
    rng = np.random.default_rng(11)
    for ax, (field_name, title, ylabel, color) in zip(axes, specs):
        series = [[float(row[field_name]) for row in rows_for_scenario(rows, scenario) if row.get(field_name) is not None] for scenario in scenarios]
        safe_series = [values if values else [np.nan] for values in series]
        box = ax.boxplot(safe_series, labels=scenarios, patch_artist=True, showfliers=False, showmeans=True, meanprops={"marker": "+", "markeredgecolor": color, "markersize": 10})
        for patch in box["boxes"]:
            patch.set_facecolor(color)
            patch.set_alpha(0.22)
        for median in box["medians"]:
            median.set_color("#111827")
        for idx, values in enumerate(series, start=1):
            if not values:
                continue
            jitter = rng.normal(idx, 0.06, len(values))
            ax.scatter(jitter, values, s=22, color=color, alpha=0.78, edgecolors="white", linewidths=0.35)
        ax.set_title(title, fontsize=19)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis="x", rotation=28)
    fig.suptitle("Victim-Side Operational Metrics", y=1.03)
    return _save(fig, output_dir / "figure-10-victim-side-operational-metrics.png", plt)


def _plot_relative_change_vs_baseline(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    baseline_rows = rows_for_scenario(rows, "baseline")
    if not baseline_rows:
        return None
    baseline_ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in baseline_rows])
    baseline_curl = _mean_or_none([row.get("curl_total_s") for row in baseline_rows])
    baseline_iperf = _mean_or_none([row.get("iperf_mbps") for row in baseline_rows])
    scenarios = [scenario for scenario in _scenario_order(rows) if scenario != "baseline"]
    if not scenarios:
        return None
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = list(range(len(labels)))
    width = 0.24
    ping_over = []
    curl_over = []
    iperf_change = []
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in scenario_rows])
        curl = _mean_or_none([row.get("curl_total_s") for row in scenario_rows])
        iperf = _mean_or_none([row.get("iperf_mbps") for row in scenario_rows])
        ping_over.append(((ping - baseline_ping) / baseline_ping * 100.0) if ping is not None and baseline_ping else 0.0)
        curl_over.append(((curl - baseline_curl) / baseline_curl * 100.0) if curl is not None and baseline_curl else 0.0)
        iperf_change.append(((iperf - baseline_iperf) / baseline_iperf * 100.0) if iperf is not None and baseline_iperf else 0.0)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.15), 4.8))
    ax.bar([position - width for position in positions], ping_over, width=width, color="#2563eb", label="Ping overhead %")
    ax.bar(positions, curl_over, width=width, color="#ea580c", label="Curl overhead %")
    ax.bar([position + width for position in positions], iperf_change, width=width, color="#0f766e", label="Throughput change %")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Percent change vs baseline")
    ax.set_title("Relative Change Versus Baseline")
    ax.legend()
    return _save(fig, output_dir / "figure-11-relative-change-versus-baseline.png", plt)


def _plot_distribution_shape(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    specs = [
        ("ping_gateway_avg_ms", "Gateway ping latency (ms)", "#2563eb"),
        ("curl_total_s", "Curl time_total (s)", "#fb923c"),
        ("iperf_mbps", "iperf3 throughput (Mbps)", "#0f766e"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.2))
    for ax, (field_name, title, color) in zip(axes, specs):
        data = [[float(row[field_name]) for row in rows_for_scenario(rows, scenario) if row.get(field_name) is not None] for scenario in scenarios]
        non_empty = [(index + 1, values) for index, values in enumerate(data) if values]
        if non_empty:
            positions = [index for index, _ in non_empty]
            series = [values for _, values in non_empty]
            parts = ax.violinplot(series, positions=positions, showmeans=True, showmedians=False)
            for body in parts["bodies"]:
                body.set_facecolor(color)
                body.set_edgecolor(color)
                body.set_alpha(0.20)
            parts["cmeans"].set_color("#0f766e")
            parts["cbars"].set_color("#0f766e")
            parts["cmins"].set_color("#0f766e")
            parts["cmaxes"].set_color("#0f766e")
        ax.set_xticks(range(1, len(scenarios) + 1))
        ax.set_xticklabels(scenarios, rotation=28, ha="right")
        ax.set_title(title, fontsize=19)
        ax.set_ylabel(title)
    fig.suptitle("Distribution Shape of Operational Metrics", y=1.03)
    return _save(fig, output_dir / "figure-12-distribution-shape-of-operational-metrics.png", plt)


def _plot_wire_truth_packet_counts(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _attack_scenarios(rows)
    if not scenarios:
        return None
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = np.arange(len(scenarios))
    attack_specs = [
        ("arp_spoof", "ARP spoof", "#ef4444"),
        ("dns_spoof", "DNS spoof", "#7c3aed"),
        ("dhcp_spoof", "DHCP spoof", "#0f766e"),
        ("icmp_redirect", "ICMP redirect", "#2563eb"),
    ]
    bottoms = np.zeros(len(scenarios))
    fig, ax = plt.subplots(figsize=(max(9, len(labels) * 1.1), 5.1))
    for attack_type, label, color in attack_specs:
        values = np.array([
            _mean_counter_value(rows_for_scenario(rows, scenario), "ground_truth_attack_types", attack_type)
            for scenario in scenarios
        ])
        if not np.any(values):
            continue
        ax.bar(positions, values, bottom=bottoms, color=color, label=label)
        bottoms = bottoms + values
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Mean matched wire packets per run")
    ax.set_title("Wire-Truth Packet Counts By Scenario")
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-25-wire-truth-packet-counts.png", plt)


def _plot_wire_truth_packet_rates(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _attack_scenarios(rows)
    if not scenarios:
        return None
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = np.arange(len(labels))
    attack_specs = [
        ("arp_spoof", "ARP spoof pps", "#ef4444"),
        ("dns_spoof", "DNS spoof pps", "#7c3aed"),
        ("dhcp_spoof", "DHCP spoof pps", "#0f766e"),
    ]
    width = 0.22
    fig, ax = plt.subplots(figsize=(max(9, len(labels) * 1.15), 5.0))
    for index, (attack_type, label, color) in enumerate(attack_specs):
        values = []
        for scenario in scenarios:
            scenario_rows = rows_for_scenario(rows, scenario)
            values.append(
                _mean_or_none(
                    [float((row.get("ground_truth_attack_type_packet_rates_pps", {}) or {}).get(attack_type, 0) or 0) for row in scenario_rows]
                ) or 0.0
            )
        ax.bar(positions + (index - 1) * width, values, width=width, color=color, label=label)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Mean packets per second")
    ax.set_title("Wire-Truth Attack Packet Rates")
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-26-wire-truth-packet-rates.png", plt)


def _plot_sensor_vs_wire_volume(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _attack_scenarios(rows)
    if not scenarios:
        return None
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = np.arange(len(labels))
    width = 0.24
    fig, ax = plt.subplots(figsize=(max(9, len(labels) * 1.15), 5.0))
    for index, tool in enumerate(TOOL_ORDER):
        values = []
        for scenario in scenarios:
            scenario_rows = rows_for_scenario(rows, scenario)
            ratios: list[float] = []
            for row in scenario_rows:
                truth = float(row.get("ground_truth_attack_events") or 0)
                alerts = float(row.get(tool_alert_field(tool)) or 0)
                if truth > 0:
                    ratios.append(alerts / truth)
            values.append(_mean_or_none(ratios) or 0.0)
        ax.bar(positions + (index - 1) * width, values, width=width, color=TOOL_COLORS[tool], label=TOOL_LABELS[tool])
    ax.axhline(1.0, color="#6b7280", linewidth=1.5, linestyle="--")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Mean sensor alerts / wire packets")
    ax.set_title("Sensor Volume Relative To Wire Truth")
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-27-sensor-vs-wire-volume.png", plt)


def _plot_representative_attack_type_counts(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    attack_types = [attack_type for attack_type in ATTACK_TYPE_ORDER if attack_type in SCENARIO_ATTACK_TYPES.get(str(row["scenario"]), set())]
    if not attack_types:
        return None
    labels = [ATTACK_TYPE_LABELS[attack_type] for attack_type in attack_types]
    positions = list(range(len(labels)))
    width = 0.24
    fig, ax = plt.subplots(figsize=(8.0, 4.4))
    for index, tool in enumerate(TOOL_ORDER):
        values = [float(row.get(f"{tool}_attack_type_counts", {}).get(attack_type, 0)) for attack_type in attack_types]
        ax.bar([position + (index - 1) * width for position in positions], values, width=width, color=TOOL_COLORS[tool], label=TOOL_LABELS[tool])
    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Alert count")
    ax.set_title(f"Attack-Type Alert Counts: {row['run_id']}")
    ax.legend()
    return _save(fig, output_dir / "figure-13-attack-type-alert-counts.png", plt)


def _plot_representative_timeline(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    fig, ax = plt.subplots(figsize=(12, 2.8))
    duration = float(row.get("duration_seconds") or 0.0)
    ax.hlines(0, 0, duration, color="#6b7280", linewidth=2)
    _add_time_context(ax, row)
    for label, timestamp, color in [
        ("Detector", row.get("detector_first_alert_at_native"), TOOL_COLORS["detector"]),
        ("Zeek", row.get("zeek_first_alert_at"), TOOL_COLORS["zeek"]),
        ("Suricata", row.get("suricata_first_alert_at"), TOOL_COLORS["suricata"]),
        ("Mitigation", row.get("mitigation_started_at"), "#0f766e"),
    ]:
        offset = seconds_between(row.get("started_at"), timestamp)
        if offset is None:
            continue
        ax.vlines(offset, -0.35, 0.35, color=color, linewidth=2)
        ax.scatter([offset], [0], s=74, color=color, edgecolors="white", linewidths=0.55, zorder=3)
        ax.text(offset, 0.45, label, ha="center", va="bottom", fontsize=9)
    ax.set_title(f"Run Timeline: {row['run_id']}")
    ax.set_xlabel("Seconds since run start")
    ax.set_yticks([])
    ax.set_ylim(-0.6, 0.8)
    return _save(fig, output_dir / "figure-14-run-timeline.png", plt)


def _plot_representative_probe_trace(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    payload = representative_probe_series(row)
    if payload is None:
        return None
    x_values, series = payload
    fig, ax = plt.subplots(figsize=(12, 4.6))
    for name, values in series.items():
        color = "#2563eb" if "Gateway" in name else "#f97316"
        ax.plot(x_values, values, marker="o", linewidth=1.8, markersize=4, label=name, color=color)
    _add_time_context(ax, row)
    ax.set_title(f"Probe Trace: {row['run_id']}")
    ax.set_xlabel("Seconds since run start")
    ax.set_ylabel("Ping latency (ms)")
    ax.legend()
    return _save(fig, output_dir / "figure-15-probe-trace.png", plt)


def _plot_representative_curl_timeline(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    meta = load_json(run_dir_for_row(row) / "run-meta.json")
    windows = parse_traffic_windows(run_dir_for_row(row) / "victim" / "traffic-window.txt", gateway_ip=meta.get("gateway_lab_ip"), attacker_ip=meta.get("attacker_ip"))
    xs: list[float] = []
    ys: list[float] = []
    for window in windows:
        offset = seconds_between(row.get("started_at"), window.ts)
        if offset is None or window.curl_total_s is None:
            continue
        xs.append(offset)
        ys.append(float(window.curl_total_s))
    if not xs:
        return None
    fig, ax = plt.subplots(figsize=(12, 4.2))
    ax.plot(xs, ys, marker="o", linewidth=1.8, color="#ea580c")
    _add_time_context(ax, row)
    ax.set_title(f"Curl Timeline: {row['run_id']}")
    ax.set_xlabel("Seconds since run start")
    ax.set_ylabel("curl time_total (s)")
    return _save(fig, output_dir / "figure-16-curl-timeline.png", plt)


def _plot_detector_state_flags(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    records = [record for record in load_jsonl(detector_delta_path(run_dir_for_row(row))) if record.get("event") == "heartbeat"]
    xs: list[float] = []
    mismatch: list[float] = []
    multi: list[float] = []
    domain: list[float] = []
    for record in records:
        offset = seconds_between(row.get("started_at"), record.get("ts"))
        if offset is None:
            continue
        xs.append(offset)
        mismatch.append(1.0 if record.get("gateway_mismatch_active") else 0.0)
        multi.append(1.0 if record.get("multi_gateway_active") else 0.0)
        domain.append(1.0 if any(bool(value) for value in (record.get("domain_mismatch_active") or {}).values()) else 0.0)
    if not xs:
        return None
    fig, ax = plt.subplots(figsize=(12, 3.8))
    ax.step(xs, mismatch, where="post", linewidth=1.7, label="Gateway mismatch", color="#dc2626")
    ax.step(xs, multi, where="post", linewidth=1.7, label="Multiple gateway MACs", color="#2563eb")
    ax.step(xs, domain, where="post", linewidth=1.7, label="Domain mismatch", color="#7c3aed")
    _add_time_context(ax, row)
    ax.set_ylim(-0.1, 1.2)
    ax.set_title(f"Detector State Flags: {row['run_id']}")
    ax.set_xlabel("Seconds since run start")
    ax.set_ylabel("State active")
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-17-detector-state-flags.png", plt)


def _plot_detector_event_raster(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    records = load_jsonl(detector_delta_path(run_dir_for_row(row)))
    event_names = [
        "gateway_mac_changed",
        "multiple_gateway_macs_seen",
        "icmp_redirects_seen",
        "domain_resolution_changed",
        "gateway_mac_restored",
        "domain_resolution_restored",
        "arp_spoof_packet_seen",
        "icmp_redirect_packet_seen",
        "dns_spoof_packet_seen",
    ]
    fig, ax = plt.subplots(figsize=(12, 5.2))
    for idx, event_name in enumerate(event_names):
        offsets = [seconds_between(row.get("started_at"), record.get("ts")) for record in records if record.get("event") == event_name]
        offsets = [offset for offset in offsets if offset is not None]
        if offsets:
            color = SEMANTIC_EVENT_COLORS.get(event_name, "#475569")
            ax.scatter(offsets, [idx] * len(offsets), s=50, color=color, edgecolors="white", linewidths=0.45)
    _add_time_context(ax, row)
    ax.set_title(f"Detector Event Raster: {row['run_id']}")
    ax.set_xlabel("Seconds since run start")
    ax.set_yticks(range(len(event_names)))
    ax.set_yticklabels(event_names)
    return _save(fig, output_dir / "figure-18-detector-event-raster.png", plt)


def _plot_mean_detector_semantic_counts(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    fields = [
        ("gateway_mac_changed", "Gateway MAC Changed", "#dc2626"),
        ("multiple_gateway_macs_seen", "Multiple Gateway MACs", "#ea580c"),
        ("icmp_redirects_seen", "ICMP Redirects", "#2563eb"),
        ("rogue_dhcp_server_seen", "Rogue DHCP Server", "#0f766e"),
        ("dhcp_binding_conflict_seen", "DHCP Binding Conflict", "#10b981"),
        ("domain_resolution_changed", "Domain Resolution Changed", "#7c3aed"),
        ("restoration_events", "Restoration Events", "#16a34a"),
    ]
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = list(range(len(labels)))
    width = 0.11
    fig, ax = plt.subplots(figsize=(max(9, len(labels) * 1.1), 5.0))
    for index, (field_name, label, color) in enumerate(fields):
        values = [_mean_or_none([row.get(field_name, 0) for row in rows_for_scenario(rows, scenario)]) or 0.0 for scenario in scenarios]
        ax.bar([position + (index - 2) * width for position in positions], values, width=width, color=color, label=label)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Mean event count per run")
    ax.set_title("Mean Detector Semantic Counts")
    ax.legend(loc="upper right")
    return _save(fig, output_dir / "figure-19-mean-detector-semantic-counts.png", plt)


def _plot_detector_packet_alerts_by_scenario(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    attack_types = [
        ("arp_spoof", "ARP spoof packets", "#ef4444"),
        ("icmp_redirect", "ICMP redirects", "#2563eb"),
        ("dns_spoof", "DNS spoof packets", "#7c3aed"),
        ("dhcp_spoof", "DHCP spoof packets", "#0f766e"),
    ]
    labels = [SCENARIO_LABELS[scenario] for scenario in scenarios]
    positions = list(range(len(labels)))
    width = 0.18
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.1), 4.8))
    center_offset = (len(attack_types) - 1) / 2
    for index, (attack_type, label, color) in enumerate(attack_types):
        values = [_mean_or_none([row.get("detector_attack_type_counts", {}).get(attack_type, 0) for row in rows_for_scenario(rows, scenario)]) or 0.0 for scenario in scenarios]
        ax.bar([position + (index - center_offset) * width for position in positions], values, width=width, color=color, label=label)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=28, ha="right")
    ax.set_ylabel("Mean packet-alert count per run")
    ax.set_title("Detector Packet Alerts By Scenario")
    ax.legend()
    return _save(fig, output_dir / "figure-20-detector-packet-alerts-by-scenario.png", plt)


def _plot_share_of_runs_with_events(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    fields = [
        ("gateway_mac_changed", "Gateway MAC Changed"),
        ("multiple_gateway_macs_seen", "Multiple Gateway MACs"),
        ("icmp_redirects_seen", "ICMP Redirects"),
        ("rogue_dhcp_server_seen", "Rogue DHCP Server"),
        ("dhcp_binding_conflict_seen", "DHCP Binding Conflict"),
        ("domain_resolution_changed", "Domain Changed"),
        ("domain_resolution_restored", "Domain Restored"),
        ("gateway_mac_restored", "Gateway Restored"),
    ]
    matrix = []
    for field_name, _ in fields:
        row_values = []
        for scenario in scenarios:
            scenario_rows = rows_for_scenario(rows, scenario)
            present = sum(1 for row in scenario_rows if int(row.get(field_name, 0) or 0) > 0)
            row_values.append(present / len(scenario_rows) * 100.0 if scenario_rows else math.nan)
        matrix.append(row_values)
    fig, ax = plt.subplots(figsize=(max(7, len(scenarios) * 1.15), 4.6))
    image = ax.imshow(matrix, aspect="auto", cmap="BuPu", vmin=0, vmax=100)
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels([SCENARIO_LABELS[scenario] for scenario in scenarios], rotation=28, ha="right")
    ax.set_yticks(range(len(fields)))
    ax.set_yticklabels([label for _, label in fields])
    ax.set_title("Share Of Runs With Each Detector Event")
    for row_index, values in enumerate(matrix):
        for col_index, value in enumerate(values):
            ax.text(col_index, row_index, f"{value:.0f}%", ha="center", va="center", fontsize=8)
    fig.colorbar(image, ax=ax, label="Share of runs (%)")
    return _save(fig, output_dir / "figure-21-share-of-runs-with-each-detector-event.png", plt)


def _plot_restoration_ordering(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    points = []
    for row in rows:
        if str(row["scenario"]) != "mitigation-recovery":
            continue
        records = load_jsonl(detector_delta_path(run_dir_for_row(row)))
        gateway_restore = None
        domain_restore = None
        for record in records:
            offset = seconds_between(row.get("started_at"), record.get("ts"))
            if offset is None:
                continue
            if record.get("event") == "gateway_mac_restored" and gateway_restore is None:
                gateway_restore = offset
            if record.get("event") == "domain_resolution_restored" and domain_restore is None:
                domain_restore = offset
        if gateway_restore is not None and domain_restore is not None:
            points.append((gateway_restore, domain_restore, str(row["run_id"])))
    if not points:
        return None
    fig, ax = plt.subplots(figsize=(6.6, 5.0))
    ax.scatter([x for x, _, _ in points], [y for _, y, _ in points], s=70, color="#16a34a", edgecolors="white", linewidths=0.45)
    for x_value, y_value, run_id in points:
        ax.annotate(run_id[-6:], (x_value, y_value), textcoords="offset points", xytext=(4, 4), fontsize=8)
    ax.set_xlabel("Gateway restore offset (s)")
    ax.set_ylabel("Domain restore offset (s)")
    ax.set_title("Restoration Ordering In Mitigation Runs")
    return _save(fig, output_dir / "figure-22-restoration-ordering-in-mitigation-runs.png", plt)


def _plot_normalized_scenario_metric_profile(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    scenarios = _scenario_order(rows)
    if not scenarios:
        return None
    metric_specs = [
        ("Gateway ping", [_mean_or_none([row.get("ping_gateway_avg_ms") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
        ("Curl total", [_mean_or_none([row.get("curl_total_s") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
        ("iperf throughput", [_mean_or_none([row.get("iperf_mbps") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
        ("Detector alerts", [_mean_or_none([row.get("detector_alerts_native") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
        ("Zeek alerts", [_mean_or_none([row.get("zeek_alerts") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
        ("Suricata alerts", [_mean_or_none([row.get("suricata_alerts") for row in rows_for_scenario(rows, scenario)]) for scenario in scenarios]),
    ]
    normalized_rows = []
    metric_names = []
    for metric_name, values in metric_specs:
        clean = [value for value in values if value is not None]
        if not clean:
            continue
        low = min(clean)
        high = max(clean)
        if high == low:
            normalized_rows.append([0.5 for _ in values])
        else:
            normalized_rows.append([0.0 if value is None else (value - low) / (high - low) for value in values])
        metric_names.append(metric_name)
    if not normalized_rows:
        return None
    matrix = np.array(normalized_rows, dtype=float)
    fig, ax = plt.subplots(figsize=(10.2, 5.7))
    image = ax.imshow(matrix, cmap="BuGn", aspect="auto", vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(scenarios, rotation=24, ha="right")
    ax.set_yticks(range(len(metric_names)))
    ax.set_yticklabels(metric_names)
    ax.set_title("Normalized Scenario Metric Profile")
    for row_index in range(matrix.shape[0]):
        for col_index in range(matrix.shape[1]):
            ax.text(col_index, row_index, f"{matrix[row_index, col_index]:.2f}", ha="center", va="center", color="#111827", fontsize=10)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    return _save(fig, output_dir / "figure-23-normalized-scenario-metric-profile.png", plt)


def _plot_operational_overhead_lollipop(rows: list[dict[str, Any]], output_dir: Path, plt: Any) -> Path | None:
    baseline_rows = rows_for_scenario(rows, "baseline")
    if not baseline_rows:
        return None
    baseline_ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in baseline_rows])
    baseline_curl = _mean_or_none([row.get("curl_total_s") for row in baseline_rows])
    scenarios = [scenario for scenario in _scenario_order(rows) if scenario != "baseline"]
    if not scenarios:
        return None
    ping_over = []
    curl_over = []
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in scenario_rows])
        curl = _mean_or_none([row.get("curl_total_s") for row in scenario_rows])
        ping_over.append(((ping - baseline_ping) / baseline_ping * 100.0) if ping is not None and baseline_ping else 0.0)
        curl_over.append(((curl - baseline_curl) / baseline_curl * 100.0) if curl is not None and baseline_curl else 0.0)
    y_values = np.arange(len(scenarios))
    fig, ax = plt.subplots(figsize=(9.8, 5.0))
    for idx, (ping_value, curl_value) in enumerate(zip(ping_over, curl_over)):
        ax.hlines(y_values[idx], min(ping_value, curl_value), max(ping_value, curl_value), color="#cbd5e1", linewidth=2)
    ax.scatter(ping_over, y_values, s=80, color="#2563eb", label="Ping overhead %")
    ax.scatter(curl_over, y_values, s=80, color="#ea580c", label="Curl overhead %")
    ax.set_yticks(y_values)
    ax.set_yticklabels([SCENARIO_LABELS[scenario] for scenario in scenarios])
    ax.set_xlabel("Percent change versus baseline")
    ax.set_title("Operational Overhead Lollipop Comparison")
    ax.legend()
    return _save(fig, output_dir / "figure-24-operational-overhead-lollipop-comparison.png", plt)


def build_report_plots(rows: list[dict[str, Any]], output_dir: Path) -> tuple[dict[str, Path], list[str]]:
    plt = _require_matplotlib()
    _apply_style(plt)
    output_dir.mkdir(parents=True, exist_ok=True)

    plots: dict[str, Path] = {}
    notes = [
        "The report now mirrors the checked-in analysis notebook rather than a reduced report-only plot subset.",
        "Timing views use attack-relative first alert time where appropriate, because supported timing for Zeek and Suricata can visually collapse to zero in the current evaluation export.",
        "Representative run figures use a gray planned attack band and a red dashed line for first observed attack evidence.",
        "Wire-truth figures come from the mirrored switch view and now include DHCP-focused scenarios alongside ARP and DNS attack families.",
    ]

    builders = [
        ("Results Overview / Detection Rate Matrix", _plot_detection_rate_matrix),
        ("Results Overview / Detection Rate By Scenario", _plot_detection_rate_grouped_bars),
        ("Results Overview / Mean Alert Volume By Scenario", _plot_mean_alert_volume),
        ("Results Overview / Detector Semantic Alert Composition", _plot_detector_semantic_composition),
        ("Detection And Timing / Mean Attack-Relative Time-To-Detection", _plot_attack_relative_ttd_heatmap),
        ("Detection And Timing / Attack-Relative Detection-Time Distributions", _plot_attack_relative_ttd_distributions),
        ("Detection And Timing / ECDF Of Attack-Relative Time To First Alert", _plot_attack_relative_ttd_ecdf),
        ("Detection And Timing / First-Alert Winner Count", _plot_first_alert_winner_count),
        ("Detection And Timing / Detector Recovery Timing", _plot_detector_recovery_timing),
        ("Operational Impact / Victim-Side Operational Metrics", _plot_operational_metrics),
        ("Operational Impact / Relative Change Versus Baseline", _plot_relative_change_vs_baseline),
        ("Operational Impact / Distribution Shape Of Operational Metrics", _plot_distribution_shape),
        ("Wire Truth / Packet Counts By Scenario", _plot_wire_truth_packet_counts),
        ("Wire Truth / Attack Packet Rates", _plot_wire_truth_packet_rates),
        ("Wire Truth / Sensor Volume Relative To Wire Truth", _plot_sensor_vs_wire_volume),
        ("Representative Run / Attack-Type Alert Counts", _plot_representative_attack_type_counts),
        ("Representative Run / Timeline", _plot_representative_timeline),
        ("Representative Run / Probe Trace", _plot_representative_probe_trace),
        ("Representative Run / Curl Timeline", _plot_representative_curl_timeline),
        ("Representative Run / Detector State Flags", _plot_detector_state_flags),
        ("Representative Run / Detector Event Raster", _plot_detector_event_raster),
        ("Detector Event Forensics / Mean Detector Semantic Counts", _plot_mean_detector_semantic_counts),
        ("Detector Event Forensics / Detector Packet Alerts By Scenario", _plot_detector_packet_alerts_by_scenario),
        ("Detector Event Forensics / Share Of Runs With Each Detector Event", _plot_share_of_runs_with_events),
        ("Detector Event Forensics / Restoration Ordering In Mitigation Runs", _plot_restoration_ordering),
        ("Visual Atlas / Normalized Scenario Metric Profile", _plot_normalized_scenario_metric_profile),
        ("Visual Atlas / Operational Overhead Lollipop Comparison", _plot_operational_overhead_lollipop),
    ]

    for title, builder in builders:
        path = builder(rows, output_dir, plt)
        if path is not None:
            plots[title] = path

    return plots, notes
