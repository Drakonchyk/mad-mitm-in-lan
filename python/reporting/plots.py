from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from metrics.model import ATTACK_TYPE_LABELS, ATTACK_TYPE_ORDER
from metrics.primitives import (
    plot_bars_with_error,
    plot_grouped_bars,
    plot_stacked_bars,
    plot_time_series,
    plot_timeline_markers,
    safe_divide,
)
from metrics.run_artifacts import stddev_or_zero
from reporting.common import (
    COMPOSITION_SERIES,
    SCENARIO_LABELS,
    TOOL_LABELS,
    attack_window_offsets,
    available_scenarios,
    detector_marker_offsets,
    representative_probe_series,
    representative_row,
    row_mean,
    rows_for_scenario,
    seconds_between,
)
from scenarios.definitions import MAIN_SCENARIOS, SCENARIO_ATTACK_TYPES, SUPPLEMENTARY_SCENARIOS


def _mean_or_nan(values: list[float | None]) -> float:
    value = row_mean(values)
    return float(value) if value is not None else math.nan


def _scenario_detection_rate_series(rows: list[dict[str, Any]], scenarios: list[str]) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {label: [] for label in TOOL_LABELS.values()}
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        total = len(scenario_rows)
        for sensor, label in TOOL_LABELS.items():
            detected = sum(1 for row in scenario_rows if row.get(f"{sensor}_detected"))
            series[label].append(safe_divide(detected, total) * 100.0 if total else math.nan)
    return series


def _scenario_ttd_series(rows: list[dict[str, Any]], scenarios: list[str]) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {label: [] for label in TOOL_LABELS.values()}
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        for sensor, label in TOOL_LABELS.items():
            values = [row.get(f"{sensor}_ttd_seconds") for row in scenario_rows if row.get(f"{sensor}_ttd_seconds") is not None]
            series[label].append(_mean_or_nan(values))
    return series


def _scenario_alert_volume_series(rows: list[dict[str, Any]], scenarios: list[str]) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {label: [] for label in TOOL_LABELS.values()}
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        for sensor, label in TOOL_LABELS.items():
            field = "detector_alerts_native" if sensor == "detector" else f"{sensor}_alerts"
            values = [row.get(field) for row in scenario_rows if row.get(field) is not None]
            series[label].append(_mean_or_nan(values))
    return series


def _attack_type_recall_series(rows: list[dict[str, Any]]) -> tuple[list[str], dict[str, list[float]]]:
    labels: list[str] = []
    series: dict[str, list[float]] = {label: [] for label in TOOL_LABELS.values()}
    for attack_type in ATTACK_TYPE_ORDER:
        scenario_rows = [row for row in rows if attack_type in SCENARIO_ATTACK_TYPES.get(str(row["scenario"]), set())]
        if not scenario_rows:
            continue
        labels.append(ATTACK_TYPE_LABELS[attack_type])
        for sensor, label in TOOL_LABELS.items():
            eligible_rows = [
                row for row in scenario_rows
                if bool(row.get(f"{sensor}_coverage", {}).get(attack_type, False))
            ]
            if not eligible_rows:
                series[label].append(math.nan)
                continue
            detected = sum(
                1
                for row in eligible_rows
                if int(row.get(f"{sensor}_attack_type_counts", {}).get(attack_type, 0)) > 0
            )
            series[label].append(safe_divide(detected, len(eligible_rows)) * 100.0)
    return labels, series


def _scenario_metric_stats(rows: list[dict[str, Any]], scenarios: list[str], field_name: str) -> tuple[list[str], list[float], list[float]]:
    labels: list[str] = []
    values: list[float] = []
    errors: list[float] = []
    for scenario in scenarios:
        scenario_values = [row.get(field_name) for row in rows_for_scenario(rows, scenario) if row.get(field_name) is not None]
        if not scenario_values:
            continue
        labels.append(SCENARIO_LABELS[scenario])
        values.append(_mean_or_nan(scenario_values))
        errors.append(stddev_or_zero(scenario_values))
    return labels, values, errors


def _tool_timeline_markers(row: dict[str, Any]) -> tuple[list[tuple[str, float]], tuple[float, float] | None, float | None]:
    markers: list[tuple[str, float]] = []
    for label, timestamp in [
        ("Attack start", row.get("attack_started_at")),
        ("Detector first alert", row.get("detector_first_alert_at_native") or row.get("detector_first_alert_at")),
        ("Zeek first alert", row.get("zeek_first_alert_at")),
        ("Suricata first alert", row.get("suricata_first_alert_at")),
        ("Mitigation", row.get("mitigation_started_at")),
        ("Attack stop", row.get("attack_stopped_at")),
    ]:
        offset = seconds_between(row.get("started_at"), timestamp)
        if offset is not None:
            markers.append((label, offset))

    attack_start_offset = seconds_between(row.get("started_at"), row.get("attack_started_at"))
    attack_stop_offset = seconds_between(row.get("started_at"), row.get("attack_stopped_at"))
    attack_window = None
    if attack_start_offset is not None and attack_stop_offset is not None:
        attack_window = (attack_start_offset, attack_stop_offset)
    end_seconds = float(row["duration_seconds"]) if row.get("duration_seconds") is not None else None
    return markers, attack_window, end_seconds


def _representative_attack_type_count_series(row: dict[str, Any]) -> tuple[list[str], dict[str, list[float]]]:
    attack_types = [
        attack_type for attack_type in ATTACK_TYPE_ORDER
        if attack_type in SCENARIO_ATTACK_TYPES.get(str(row["scenario"]), set())
    ]
    labels = [ATTACK_TYPE_LABELS[attack_type] for attack_type in attack_types]
    series: dict[str, list[float]] = {label: [] for label in TOOL_LABELS.values()}
    for attack_type in attack_types:
        for sensor, label in TOOL_LABELS.items():
            if not bool(row.get(f"{sensor}_coverage", {}).get(attack_type, False)):
                series[label].append(math.nan)
                continue
            series[label].append(float(row.get(f"{sensor}_attack_type_counts", {}).get(attack_type, 0)))
    return labels, series


def build_main_plots(rows: list[dict[str, Any]], output_dir: Path) -> tuple[dict[str, Path], list[str]]:
    plots: dict[str, Path] = {}
    notes: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    notes.append("Comparison figures use supported-only timing for each tool. Suricata excludes ARP spoof in the current IDS setup, so missing Suricata bars there mean unsupported rather than missed.")
    notes.append("Tool alert-volume comparisons use detector packet alerts, not detector semantic alerts, so detector, Zeek, and Suricata are plotted in comparable alert units.")

    all_scenarios = available_scenarios(rows, scenario_order=MAIN_SCENARIOS)
    attack_scenarios = available_scenarios(rows, scenario_order=MAIN_SCENARIOS, include_baseline=False)

    if all_scenarios:
        plots["figure_1_detection_rate_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in all_scenarios],
            _scenario_detection_rate_series(rows, all_scenarios),
            output_dir / "figure-1-detection-rate-by-tool-and-scenario.png",
            "Figure 1. Detection Rate by Tool and Scenario",
            "Detection rate (%)",
        )
    else:
        notes.append("Figures 1 and 3 skipped because no main-profile scenarios were available in the current dataset.")

    if attack_scenarios:
        plots["figure_2_time_to_first_alert_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in attack_scenarios],
            _scenario_ttd_series(rows, attack_scenarios),
            output_dir / "figure-2-time-to-first-supported-alert-by-tool-and-scenario.png",
            "Figure 2. Mean Time to First Supported Alert by Tool and Scenario",
            "Time to first supported alert (s)",
        )
    else:
        notes.append("Figure 2 skipped because the current main dataset does not include attack scenarios.")

    if all_scenarios:
        plots["figure_3_alert_volume_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in all_scenarios],
            _scenario_alert_volume_series(rows, all_scenarios),
            output_dir / "figure-3-alert-volume-by-tool-and-scenario.png",
            "Figure 3. Mean Packet-Alert Volume by Tool and Scenario",
            "Mean alerts per run",
        )

    attack_type_labels, attack_type_series = _attack_type_recall_series(rows)
    if attack_type_labels:
        plots["figure_4_attack_type_recall_by_tool"] = plot_grouped_bars(
            attack_type_labels,
            attack_type_series,
            output_dir / "figure-4-supported-attack-type-recall-by-tool.png",
            "Figure 4. Supported Attack-Type Recall by Tool",
            "Runs with at least one alert for that attack type (%)",
        )
    else:
        notes.append("Figure 4 skipped because the current dataset does not contain any modeled attack types.")

    figure_5_labels, figure_5_values, figure_5_errors = _scenario_metric_stats(rows, all_scenarios, "ping_gateway_avg_ms")
    if figure_5_labels:
        plots["figure_5_gateway_ping"] = plot_bars_with_error(
            figure_5_labels,
            figure_5_values,
            figure_5_errors,
            output_dir / "figure-5-gateway-ping-latency-by-scenario.png",
            "Figure 5. Gateway Ping Latency by Scenario",
            "Average gateway ping latency (ms)",
        )
    else:
        notes.append("Figure 5 skipped because the current runs do not have parsed gateway ping samples.")

    figure_6_labels, figure_6_values, figure_6_errors = _scenario_metric_stats(rows, all_scenarios, "curl_total_s")
    if figure_6_labels:
        plots["figure_6_curl_time"] = plot_bars_with_error(
            figure_6_labels,
            figure_6_values,
            figure_6_errors,
            output_dir / "figure-6-curl-time-total-by-scenario.png",
            "Figure 6. Curl Time by Scenario",
            "Curl time_total (s)",
        )
    else:
        notes.append("Figure 6 skipped because the current runs do not have parsed curl timing samples.")

    figure_7_labels, figure_7_values, figure_7_errors = _scenario_metric_stats(rows, all_scenarios, "iperf_mbps")
    if figure_7_labels:
        plots["figure_7_throughput"] = plot_bars_with_error(
            figure_7_labels,
            figure_7_values,
            figure_7_errors,
            output_dir / "figure-7-throughput-by-scenario.png",
            "Figure 7. iperf3 Throughput by Scenario",
            "iperf3 throughput (Mbps)",
        )
    else:
        notes.append("Figure 7 skipped because the current runs do not include iperf3.json throughput captures yet.")

    recovery_labels, recovery_values, recovery_errors = _scenario_metric_stats(rows, ["mitigation-recovery"], "detector_recovery_seconds")
    if recovery_labels:
        plots["figure_8_recovery_time"] = plot_bars_with_error(
            recovery_labels,
            recovery_values,
            recovery_errors,
            output_dir / "figure-8-detector-recovery-time.png",
            "Figure 8. Detector Recovery Time After Mitigation",
            "Time to recovery (s)",
        )
    else:
        notes.append("Figure 8 skipped because the current dataset has no measured mitigation recovery times yet.")

    representative_timeline_row = representative_row(
        rows,
        ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"],
        lambda row: any(
            row.get(field) is not None
            for field in [
                "detector_first_alert_at_native",
                "zeek_first_alert_at",
                "suricata_first_alert_at",
            ]
        ),
    )
    if representative_timeline_row is not None:
        markers, attack_window, end_seconds = _tool_timeline_markers(representative_timeline_row)
        if markers:
            plots["figure_9_representative_tool_timeline"] = plot_timeline_markers(
                markers,
                output_dir / "figure-9-representative-tool-timeline.png",
                f"Figure 9. Representative Multi-Tool Alert Timeline ({representative_timeline_row['run_id']})",
                attack_window=attack_window,
                end_seconds=end_seconds,
            )
    else:
        notes.append("Figure 9 skipped because there is no representative attack run with parsed first-alert timestamps across the tools.")

    representative_probe_row = representative_row(
        rows,
        ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"],
        lambda row: representative_probe_series(row) is not None,
    )
    if representative_probe_row is not None:
        probe_payload = representative_probe_series(representative_probe_row)
        if probe_payload is not None:
            x_values, series = probe_payload
            plots["figure_10_representative_probe_trace"] = plot_time_series(
                x_values,
                series,
                output_dir / "figure-10-representative-probe-trace.png",
                f"Figure 10. Representative Probe Trace ({representative_probe_row['run_id']})",
                "Ping latency (ms)",
                xlabel="Seconds since run start",
                attack_windows=attack_window_offsets(representative_probe_row),
                markers=detector_marker_offsets(representative_probe_row),
            )
    else:
        notes.append("Figure 10 skipped because there is no representative run with parsed probe-window timing samples.")

    representative_count_row = representative_row(
        rows,
        ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"],
        lambda row: any(int(row.get(f"{sensor}_alerts", 0) if sensor != "detector" else row.get("detector_alerts_native", 0)) > 0 for sensor in TOOL_LABELS),
    )
    if representative_count_row is not None:
        count_labels, count_series = _representative_attack_type_count_series(representative_count_row)
        if count_labels:
            plots["figure_11_representative_attack_type_counts"] = plot_grouped_bars(
                count_labels,
                count_series,
                output_dir / "figure-11-representative-attack-type-counts-by-tool.png",
                f"Figure 11. Representative Attack-Type Alert Counts by Tool ({representative_count_row['run_id']})",
                "Alert count in the selected run",
            )
    else:
        notes.append("Figure 11 skipped because there is no representative attack run with tool alerts to compare.")

    return plots, notes


def build_supplementary_plots(rows: list[dict[str, Any]], output_dir: Path) -> tuple[dict[str, Path], list[str]]:
    plots: dict[str, Path] = {}
    notes: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = available_scenarios(rows, scenario_order=SUPPLEMENTARY_SCENARIOS)
    notes.append("Tool comparison plots are capability-aware. In the current IDS deployment, Suricata is compared on ICMP redirect and DNS spoof only, not ARP spoof.")
    notes.append("Supplementary tool alert-volume comparisons use detector packet alerts so Detector, Zeek, and Suricata stay on comparable alert units.")

    if scenarios:
        plots["supplementary_detection_rate_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in scenarios],
            _scenario_detection_rate_series(rows, scenarios),
            output_dir / "supplementary-detection-rate-by-tool.png",
            "Supplementary Figure S1. Detection Rate by Tool and Scenario",
            "Detection rate (%)",
        )
        plots["supplementary_time_to_first_alert_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in scenarios],
            _scenario_ttd_series(rows, scenarios),
            output_dir / "supplementary-time-to-first-supported-alert-by-tool.png",
            "Supplementary Figure S2. Mean Time to First Supported Alert by Tool and Scenario",
            "Time to first supported alert (s)",
        )
        plots["supplementary_alert_volume_by_tool"] = plot_grouped_bars(
            [SCENARIO_LABELS[scenario] for scenario in scenarios],
            _scenario_alert_volume_series(rows, scenarios),
            output_dir / "supplementary-alert-volume-by-tool.png",
            "Supplementary Figure S3. Mean Packet-Alert Volume by Tool and Scenario",
            "Mean alerts per run",
        )
    else:
        notes.append("Supplementary Figures S1-S3 skipped because no supplementary-profile scenarios were available in the current dataset.")

    ping_labels, ping_values, ping_errors = _scenario_metric_stats(rows, scenarios, "ping_gateway_avg_ms")
    if ping_labels:
        plots["supplementary_gateway_ping"] = plot_bars_with_error(
            ping_labels,
            ping_values,
            ping_errors,
            output_dir / "supplementary-gateway-ping-latency.png",
            "Supplementary Figure S4A. Gateway Ping Latency by Scenario",
            "Average gateway ping latency (ms)",
        )

    curl_labels, curl_values, curl_errors = _scenario_metric_stats(rows, scenarios, "curl_total_s")
    if curl_labels:
        plots["supplementary_curl_total"] = plot_bars_with_error(
            curl_labels,
            curl_values,
            curl_errors,
            output_dir / "supplementary-curl-time-total.png",
            "Supplementary Figure S4B. Curl Time by Scenario",
            "Curl time_total (s)",
        )

    iperf_labels, iperf_values, iperf_errors = _scenario_metric_stats(rows, scenarios, "iperf_mbps")
    if iperf_labels:
        plots["supplementary_iperf"] = plot_bars_with_error(
            iperf_labels,
            iperf_values,
            iperf_errors,
            output_dir / "supplementary-iperf-throughput.png",
            "Supplementary Figure S5. iperf3 Throughput by Scenario",
            "iperf3 throughput (Mbps)",
        )

    supplementary_attack_labels, supplementary_attack_series = _attack_type_recall_series(rows)
    if supplementary_attack_labels:
        plots["supplementary_attack_type_recall_by_tool"] = plot_grouped_bars(
            supplementary_attack_labels,
            supplementary_attack_series,
            output_dir / "supplementary-supported-attack-type-recall-by-tool.png",
            "Supplementary Figure S6. Supported Attack-Type Recall by Tool",
            "Runs with at least one alert for that attack type (%)",
        )

    composition_scenarios = scenarios
    if composition_scenarios:
        composition_series: dict[str, list[float]] = {label: [] for label in COMPOSITION_SERIES.values()}
        for scenario in composition_scenarios:
            scenario_rows = rows_for_scenario(rows, scenario)
            for field_name, label in COMPOSITION_SERIES.items():
                composition_series[label].append(row_mean([row[field_name] for row in scenario_rows]) or 0.0)
        plots["supplementary_detector_alert_composition"] = plot_stacked_bars(
            [SCENARIO_LABELS[scenario] for scenario in composition_scenarios],
            composition_series,
            output_dir / "supplementary-detector-alert-composition-by-scenario.png",
            "Supplementary Figure S7. Detector Semantic Alert Composition by Scenario",
            "Mean semantic alert count per run",
        )

    representative_supplementary_row = representative_row(
        rows,
        ["intermittent-arp-mitm-dns", "reduced-observability", "noisy-benign-baseline"],
        lambda row: representative_probe_series(row) is not None,
    )
    if representative_supplementary_row is not None:
        probe_payload = representative_probe_series(representative_supplementary_row)
        if probe_payload is not None:
            x_values, series = probe_payload
            plots["supplementary_probe_trace"] = plot_time_series(
                x_values,
                series,
                output_dir / "supplementary-probe-trace.png",
                f"Supplementary Figure S8. Representative Probe Trace ({representative_supplementary_row['run_id']})",
                "Ping latency (ms)",
                xlabel="Seconds since run start",
                attack_windows=attack_window_offsets(representative_supplementary_row),
                markers=detector_marker_offsets(representative_supplementary_row),
            )

    return plots, notes
