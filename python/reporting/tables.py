from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path
from typing import Any

from metrics.primitives import confusion_from_binary, safe_divide
from metrics.run_artifacts import detector_delta_path, load_json, load_jsonl, parse_traffic_windows
from reporting.common import (
    SCENARIO_LABELS,
    TOOL_LABELS,
    TOOL_ORDER,
    attack_relative_ttd,
    row_mean,
    rows_for_scenario,
    run_dir_for_row,
    seconds_between,
    tool_alert_field,
    tool_first_alert_timestamp,
)
from scenarios.definitions import MAIN_SCENARIOS, SCENARIO_ATTACK_TYPES, SUPPLEMENTARY_SCENARIOS

SCENARIO_ORDER_ALL = [*MAIN_SCENARIOS, *SUPPLEMENTARY_SCENARIOS]
GENERIC_PROTOCOLS = {"", "frame", "eth", "ethertype", "ip", "ipv6", "tcp", "udp", "data", "geninfo"}


def _ordered_scenarios(rows: list[dict[str, Any]]) -> list[str]:
    return [scenario for scenario in SCENARIO_ORDER_ALL if rows_for_scenario(rows, scenario)]


def _attack_scenarios(rows: list[dict[str, Any]]) -> list[str]:
    return [scenario for scenario in _ordered_scenarios(rows) if SCENARIO_ATTACK_TYPES.get(str(scenario))]


def _mean_or_none(values: list[float | None]) -> float | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    return sum(clean) / len(clean)


def _counter_sum(row: dict[str, Any], field_name: str, keys: tuple[str, ...]) -> float:
    counts = row.get(field_name, {}) or {}
    return float(sum(counts.get(key, 0) or 0 for key in keys))


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> Path | None:
    if not rows:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)

    def clean(value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, float):
            return f"{value:.3f}".rstrip("0").rstrip(".")
        return value

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows([{key: clean(value) for key, value in row.items()} for row in rows])
    return path


def _choose_representative_run(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred = ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"]
    for scenario in preferred:
        candidates = [
            row
            for row in rows_for_scenario(rows, scenario)
            if any(row.get(field) is not None for field in ["detector_first_alert_at_native", "zeek_first_alert_at", "suricata_first_alert_at"])
        ]
        if candidates:
            return sorted(candidates, key=lambda row: row["run_id"])[0]
    return None


def _choose_pcap_run(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred = ["mitigation-recovery", "arp-mitm-dns", "arp-mitm-forward", "arp-poison-no-forward"]
    for scenario in preferred:
        candidates = [
            row
            for row in rows_for_scenario(rows, scenario)
            if (run_dir_for_row(row) / "pcap" / "sensor.pcap").exists() or (run_dir_for_row(row) / "pcap" / "victim.pcap").exists()
        ]
        if candidates:
            return sorted(candidates, key=lambda row: row["run_id"])[0]
    return None


def _timing_reference_info(row: dict[str, Any]) -> dict[str, float | str | None]:
    evaluation = load_json(run_dir_for_row(row) / "evaluation.json")
    return {
        "planned_start": seconds_between(row.get("started_at"), row.get("attack_started_at")),
        "planned_stop": seconds_between(row.get("started_at"), row.get("attack_stopped_at")),
        "observed_start": seconds_between(row.get("started_at"), evaluation.get("ground_truth_attack_started_at")),
        "observed_start_ts": evaluation.get("ground_truth_attack_started_at"),
    }


def _pcap_path(row: dict[str, Any], capture: str = "sensor") -> Path:
    preferred = run_dir_for_row(row) / "pcap" / f"{capture}.pcap"
    if preferred.exists():
        return preferred
    fallback = run_dir_for_row(row) / "pcap" / "victim.pcap"
    return fallback


def _protocol_from_stack(stack: str | None) -> str:
    if not stack:
        return "unknown"
    candidates = [token.strip() for token in str(stack).split(":") if token.strip()]
    for candidate in reversed(candidates):
        if candidate.lower() not in GENERIC_PROTOCOLS:
            return candidate
    return candidates[-1] if candidates else "unknown"


def _tshark_rows(pcap_file: Path, fields: list[str], display_filter: str | None = None) -> list[dict[str, str]]:
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark is not installed on this host")
    command = ["tshark", "-r", str(pcap_file), "-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "occurrence=f", "-E", "aggregator=,"]
    if display_filter:
        command.extend(["-Y", display_filter])
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark failed for {pcap_file}")
    reader = csv.DictReader(result.stdout.splitlines(), delimiter="\t")
    return [{key: (value or "").strip() for key, value in record.items()} for record in reader if record]


def build_table_scenario_summary(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    summary_rows = []
    for scenario in _ordered_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        summary_rows.append(
            {
                "scenario": SCENARIO_LABELS[scenario],
                "runs": len(scenario_rows),
                "detector_rate_pct": _mean_or_none([100.0 if row.get("detector_detected") else 0.0 for row in scenario_rows]),
                "zeek_rate_pct": _mean_or_none([100.0 if row.get("zeek_detected") else 0.0 for row in scenario_rows]),
                "suricata_rate_pct": _mean_or_none([100.0 if row.get("suricata_detected") else 0.0 for row in scenario_rows]),
                "ping_ms": _mean_or_none([row.get("ping_gateway_avg_ms") for row in scenario_rows]),
                "curl_s": _mean_or_none([row.get("curl_total_s") for row in scenario_rows]),
            }
        )
    return _write_rows(output_dir / "table-01-scenario-summary.csv", summary_rows)


def build_table_timing_summary(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    summary_rows = []
    for scenario in _attack_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        record: dict[str, Any] = {"scenario": SCENARIO_LABELS[scenario]}
        for tool in TOOL_ORDER:
            record[f"{tool}_ttd_mean"] = _mean_or_none([row.get(f"{tool}_ttd_seconds") for row in scenario_rows])
            record[f"{tool}_attack_relative_mean"] = _mean_or_none([attack_relative_ttd(row, tool) for row in scenario_rows])
        summary_rows.append(record)
    return _write_rows(output_dir / "table-02-timing-summary.csv", summary_rows)


def build_table_operational_summary(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    baseline_rows = rows_for_scenario(rows, "baseline")
    baseline_ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in baseline_rows])
    baseline_curl = _mean_or_none([row.get("curl_total_s") for row in baseline_rows])
    baseline_iperf = _mean_or_none([row.get("iperf_mbps") for row in baseline_rows])

    summary_rows = []
    for scenario in _ordered_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        ping = _mean_or_none([row.get("ping_gateway_avg_ms") for row in scenario_rows])
        curl = _mean_or_none([row.get("curl_total_s") for row in scenario_rows])
        iperf = _mean_or_none([row.get("iperf_mbps") for row in scenario_rows])
        summary_rows.append(
            {
                "scenario": SCENARIO_LABELS[scenario],
                "ping_ms": ping,
                "curl_s": curl,
                "iperf_mbps": iperf,
                "ping_vs_baseline_pct": ((ping - baseline_ping) / baseline_ping * 100.0) if ping is not None and baseline_ping else None,
                "curl_vs_baseline_pct": ((curl - baseline_curl) / baseline_curl * 100.0) if curl is not None and baseline_curl else None,
                "iperf_vs_baseline_pct": ((iperf - baseline_iperf) / baseline_iperf * 100.0) if iperf is not None and baseline_iperf else None,
            }
        )
    return _write_rows(output_dir / "table-03-operational-summary.csv", summary_rows)


def build_table_tool_overall(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    attack_rows = [row for row in rows if SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))]
    ground_truth = [bool(SCENARIO_ATTACK_TYPES.get(str(row["scenario"]))) for row in rows]
    table_rows = []
    for tool in TOOL_ORDER:
        confusion = confusion_from_binary(ground_truth, [bool(row.get(f"{tool}_detected")) for row in rows])
        table_rows.append(
            {
                "tool": TOOL_LABELS[tool],
                "tp": confusion.tp,
                "fp": confusion.fp,
                "tn": confusion.tn,
                "fn": confusion.fn,
                "tpr": confusion.true_positive_rate(),
                "fpr": confusion.false_positive_rate(),
                "precision": confusion.precision(),
                "f1": confusion.f1(),
                "mean_attack_relative_ttd_s": _mean_or_none([attack_relative_ttd(row, tool) for row in attack_rows]),
                "mean_ttd_s": row_mean([row.get(f"{tool}_ttd_seconds") for row in attack_rows]),
                "mean_alerts_per_run": row_mean([row.get(tool_alert_field(tool)) for row in rows]),
            }
        )
    return _write_rows(output_dir / "table-04-tool-overall.csv", table_rows)


def build_table_tool_by_scenario(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    table_rows = []
    for scenario in _ordered_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        for tool in TOOL_ORDER:
            table_rows.append(
                {
                    "scenario": scenario,
                    "tool": TOOL_LABELS[tool],
                    "runs": len(scenario_rows),
                    "detection_rate_pct": safe_divide(sum(1 for row in scenario_rows if row.get(f"{tool}_detected")), len(scenario_rows)) * 100.0,
                    "mean_attack_relative_ttd_s": _mean_or_none([attack_relative_ttd(row, tool) for row in scenario_rows]),
                    "mean_ttd_s": row_mean([row.get(f"{tool}_ttd_seconds") for row in scenario_rows]),
                    "mean_alerts_per_run": row_mean([row.get(tool_alert_field(tool)) for row in scenario_rows]),
                }
            )
    return _write_rows(output_dir / "table-05-tool-by-scenario.csv", table_rows)


def build_table_wire_truth_summary(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    summary_rows = []
    for scenario in _attack_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        summary_rows.append(
            {
                "scenario": SCENARIO_LABELS[scenario],
                "mean_wire_packets": _mean_or_none([float(row.get("ground_truth_attack_events") or 0) for row in scenario_rows]),
                "mean_action_events": _mean_or_none([float(row.get("ground_truth_attacker_action_events") or 0) for row in scenario_rows]),
                "mean_attack_duration_s": _mean_or_none([row.get("ground_truth_attack_duration_seconds") for row in scenario_rows]),
                "mean_capture_duration_s": _mean_or_none([row.get("ground_truth_capture_duration_seconds") for row in scenario_rows]),
                "mean_arp_packets": _mean_or_none([float((row.get("ground_truth_attack_types", {}) or {}).get("arp_spoof", 0) or 0) for row in scenario_rows]),
                "mean_arp_actions": _mean_or_none([float((row.get("ground_truth_attacker_action_types", {}) or {}).get("arp_spoof", 0) or 0) for row in scenario_rows]),
                "mean_dns_packets": _mean_or_none([float((row.get("ground_truth_attack_types", {}) or {}).get("dns_spoof", 0) or 0) for row in scenario_rows]),
                "mean_dhcp_rogue_server_packets": _mean_or_none([float((row.get("ground_truth_attack_types", {}) or {}).get("dhcp_rogue_server", 0) or 0) for row in scenario_rows]),
                "mean_dhcp_untrusted_port_packets": _mean_or_none([float((row.get("ground_truth_attack_types", {}) or {}).get("dhcp_untrusted_switch_port", 0) or 0) for row in scenario_rows]),
                "mean_dhcp_packets": _mean_or_none([_counter_sum(row, "ground_truth_attack_types", ("dhcp_rogue_server", "dhcp_untrusted_switch_port", "dhcp_spoof")) for row in scenario_rows]),
                "mean_arp_pps": _mean_or_none([float((row.get("ground_truth_attack_type_packet_rates_pps", {}) or {}).get("arp_spoof", 0) or 0) for row in scenario_rows]),
                "mean_dns_pps": _mean_or_none([float((row.get("ground_truth_attack_type_packet_rates_pps", {}) or {}).get("dns_spoof", 0) or 0) for row in scenario_rows]),
                "mean_dhcp_pps": _mean_or_none([_counter_sum(row, "ground_truth_attack_type_packet_rates_pps", ("dhcp_rogue_server", "dhcp_untrusted_switch_port", "dhcp_spoof")) for row in scenario_rows]),
                "mean_dns_query_count": _mean_or_none([float(row.get("ground_truth_dns_query_count") or 0) for row in scenario_rows]),
                "mean_dns_success_ratio": _mean_or_none([row.get("ground_truth_dns_spoof_success_ratio") for row in scenario_rows]),
            }
        )
    return _write_rows(output_dir / "table-15-wire-truth-summary.csv", summary_rows)


def _detected_count(rows: list[dict[str, Any]], tool: str) -> int:
    return sum(1 for row in rows if row.get(f"{tool}_detected"))


def _rate_pct(count: int, total: int) -> float | None:
    if total <= 0:
        return None
    return count / total * 100.0


def _mean_event_count(rows: list[dict[str, Any]], event_name: str) -> float | None:
    values = []
    for row in rows:
        records = load_jsonl(detector_delta_path(run_dir_for_row(row)))
        values.append(float(sum(1 for record in records if record.get("event") == event_name)))
    return _mean_or_none(values)


def _build_detection_table(
    rows: list[dict[str, Any]],
    scenarios: list[str],
    output_path: Path,
) -> Path | None:
    table_rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        scenario_rows = rows_for_scenario(rows, scenario)
        if not scenario_rows:
            continue
        record: dict[str, Any] = {
            "scenario": SCENARIO_LABELS[scenario],
            "runs": len(scenario_rows),
        }
        for tool in TOOL_ORDER:
            detected = _detected_count(scenario_rows, tool)
            record[f"{tool}_detected_runs"] = detected
            record[f"{tool}_detection_rate_pct"] = _rate_pct(detected, len(scenario_rows))
            record[f"{tool}_mean_attack_relative_ttd_s"] = _mean_or_none([attack_relative_ttd(row, tool) for row in scenario_rows])
        table_rows.append(record)
    return _write_rows(output_path, table_rows)


def build_table_thesis_main_detection(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    return _build_detection_table(
        rows,
        MAIN_SCENARIOS,
        output_dir / "table-01-thesis-main-detection-timing.csv",
    )


def build_table_thesis_supplementary_detection(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    return _build_detection_table(
        rows,
        SUPPLEMENTARY_SCENARIOS,
        output_dir / "table-02-thesis-supplementary-campaign-summary.csv",
    )


def build_table_thesis_detector_semantics(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    table_rows: list[dict[str, Any]] = []
    for scenario in _ordered_scenarios(rows):
        scenario_rows = rows_for_scenario(rows, scenario)
        if not scenario_rows:
            continue
        table_rows.append(
            {
                "scenario": SCENARIO_LABELS[scenario],
                "runs": len(scenario_rows),
                "gateway_mac_changed_mean": _mean_or_none([float(row.get("gateway_mac_changed") or 0) for row in scenario_rows]),
                "multiple_gateway_macs_seen_mean": _mean_or_none([float(row.get("multiple_gateway_macs_seen") or 0) for row in scenario_rows]),
                "domain_resolution_changed_mean": _mean_or_none([float(row.get("domain_resolution_changed") or 0) for row in scenario_rows]),
                "rogue_dhcp_server_seen_mean": _mean_or_none([float(row.get("rogue_dhcp_server_seen") or 0) for row in scenario_rows]),
                "dhcp_binding_conflict_seen_mean": _mean_or_none([float(row.get("dhcp_binding_conflict_seen") or 0) for row in scenario_rows]),
                "restoration_events_mean": _mean_or_none([float(row.get("restoration_events") or 0) for row in scenario_rows]),
            }
        )
    return _write_rows(output_dir / "table-03-thesis-detector-semantic-coverage.csv", table_rows)


def build_table_thesis_reliability_thresholds(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    table_rows: list[dict[str, Any]] = []
    for scenario in ["reliability-arp-mitm-dns", "reliability-dhcp-spoof"]:
        scenario_rows = rows_for_scenario(rows, scenario)
        if not scenario_rows:
            continue
        levels = sorted({int(row.get("reliability_netem_loss_percent") or 0) for row in scenario_rows})
        for tool in TOOL_ORDER:
            detected_rows = [row for row in scenario_rows if row.get(f"{tool}_detected")]
            missed_rows = [row for row in scenario_rows if not row.get(f"{tool}_detected")]
            recalls = [float(row.get(f"{tool}_event_recall")) * 100.0 for row in scenario_rows if row.get(f"{tool}_event_recall") is not None]
            table_rows.append(
                {
                    "scenario": SCENARIO_LABELS[scenario],
                    "tool": TOOL_LABELS[tool],
                    "loss_levels_tested": " ".join(str(level) for level in levels),
                    "runs": len(scenario_rows),
                    "detected_runs": len(detected_rows),
                    "detection_rate_pct": _rate_pct(len(detected_rows), len(scenario_rows)),
                    "highest_loss_with_detection_pct": max((int(row.get("reliability_netem_loss_percent") or 0) for row in detected_rows), default=None),
                    "lowest_loss_with_miss_pct": min((int(row.get("reliability_netem_loss_percent") or 0) for row in missed_rows), default=None),
                    "mean_event_recall_pct": _mean_or_none(recalls),
                    "min_event_recall_pct": min(recalls) if recalls else None,
                }
            )
    return _write_rows(output_dir / "table-04-thesis-reliability-thresholds.csv", table_rows)


def build_table_thesis_recovery_timing(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    scenario_rows = rows_for_scenario(rows, "mitigation-recovery")
    if not scenario_rows:
        return None
    recovery_values = [
        float(row.get("detector_recovery_seconds"))
        for row in scenario_rows
        if row.get("detector_recovery_seconds") is not None
    ]
    table_rows = [
        {
            "scenario": SCENARIO_LABELS["mitigation-recovery"],
            "runs": len(scenario_rows),
            "restoration_runs": len(recovery_values),
            "restoration_rate_pct": _rate_pct(len(recovery_values), len(scenario_rows)),
            "detector_recovery_mean_s": _mean_or_none(recovery_values),
            "detector_recovery_min_s": min(recovery_values) if recovery_values else None,
            "detector_recovery_max_s": max(recovery_values) if recovery_values else None,
        }
    ]
    return _write_rows(output_dir / "table-06-thesis-recovery-timing.csv", table_rows)


def build_table_representative_context(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    timing = _timing_reference_info(row)
    records = [
        {"field": "run_id", "value": row["run_id"]},
        {"field": "scenario", "value": SCENARIO_LABELS[str(row["scenario"])]},
        {"field": "planned_attack_start", "value": row.get("attack_started_at")},
        {"field": "planned_attack_stop", "value": row.get("attack_stopped_at")},
        {"field": "observed_attack_start", "value": timing["observed_start_ts"]},
        {"field": "planned_start_offset_s", "value": timing["planned_start"]},
        {"field": "observed_start_offset_s", "value": timing["observed_start"]},
    ]
    return _write_rows(output_dir / "table-06-representative-run-context.csv", records)


def build_table_representative_first_alerts(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    records = [
        {
            "tool": TOOL_LABELS[tool],
            "first_alert_at": tool_first_alert_timestamp(row, tool),
            "ttd_s": row.get(f"{tool}_ttd_seconds"),
            "attack_relative_ttd_s": attack_relative_ttd(row, tool),
            "alerts": row.get(tool_alert_field(tool)),
        }
        for tool in TOOL_ORDER
    ]
    return _write_rows(output_dir / "table-07-representative-first-alerts.csv", records)


def build_table_probe_window_domain_observations(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_representative_run(rows)
    if row is None:
        return None
    meta = load_json(run_dir_for_row(row) / "run-meta.json")
    windows = parse_traffic_windows(run_dir_for_row(row) / "victim" / "traffic-window.txt", gateway_ip=meta.get("gateway_lab_ip"), attacker_ip=meta.get("attacker_ip"))
    records = []
    for window in windows:
        offset = seconds_between(row.get("started_at"), window.ts)
        if offset is None:
            continue
        domains = {name: ", ".join(values[:3]) for name, values in window.domains.items()}
        records.append(
            {
                "seconds": offset,
                "gateway_ping_ms": window.ping_gateway_avg_ms,
                "attacker_ping_ms": window.ping_attacker_avg_ms,
                "curl_total_s": window.curl_total_s,
                "example.com": domains.get("example.com", ""),
                "example.org": domains.get("example.org", ""),
                "iana.org": domains.get("iana.org", ""),
            }
        )
    return _write_rows(output_dir / "table-08-probe-window-domain-observations.csv", records[:30])


def build_table_noisiest_detector_runs(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    records = []
    semantic_events = {
        "gateway_mac_changed",
        "multiple_gateway_macs_seen",
        "icmp_redirects_seen",
        "domain_resolution_changed",
        "gateway_mac_restored",
        "domain_resolution_restored",
        "single_gateway_mac_restored",
    }
    packet_events = {"arp_spoof_packet_seen", "icmp_redirect_packet_seen", "dns_spoof_packet_seen"}
    for row in rows:
        detector_records = load_jsonl(detector_delta_path(run_dir_for_row(row)))
        semantic_total = sum(1 for record in detector_records if record.get("event") in semantic_events)
        packet_total = sum(1 for record in detector_records if record.get("event") in packet_events)
        records.append({"run_id": row["run_id"], "scenario": SCENARIO_LABELS[str(row["scenario"])], "semantic_total": semantic_total, "packet_total": packet_total})
    records = sorted(records, key=lambda item: (item["semantic_total"], item["packet_total"]), reverse=True)
    return _write_rows(output_dir / "table-09-noisiest-detector-runs.csv", records[:20])


def build_table_capture_overview(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_pcap_run(rows)
    if row is None:
        return None
    tshark_rows = _tshark_rows(_pcap_path(row), ["frame.time_epoch", "frame.protocols"])
    protocols: dict[str, int] = {}
    for record in tshark_rows:
        protocol = _protocol_from_stack(record.get("frame.protocols"))
        protocols[protocol] = protocols.get(protocol, 0) + 1
    first_ts = float(tshark_rows[0]["frame.time_epoch"]) if tshark_rows else None
    last_ts = float(tshark_rows[-1]["frame.time_epoch"]) if tshark_rows else None
    records = [
        {"field": "pcap_path", "value": str(_pcap_path(row))},
        {"field": "capture_role", "value": "victim"},
        {"field": "packet_count", "value": len(tshark_rows)},
        {"field": "duration_seconds", "value": (last_ts - first_ts) if first_ts is not None and last_ts is not None else None},
        {"field": "top_protocol", "value": max(protocols, key=protocols.get) if protocols else "n/a"},
    ]
    return _write_rows(output_dir / "table-10-capture-overview.csv", records)


def build_table_top_conversations(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_pcap_run(rows)
    if row is None:
        return None
    tshark_rows = _tshark_rows(_pcap_path(row), ["ip.src", "ip.dst", "frame.protocols", "frame.len"], display_filter="ip")
    totals: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in tshark_rows:
        src = record.get("ip.src") or "n/a"
        dst = record.get("ip.dst") or "n/a"
        protocol = _protocol_from_stack(record.get("frame.protocols"))
        key = (src, dst, protocol)
        totals.setdefault(key, {"src": src, "dst": dst, "protocol": protocol, "packets": 0, "bytes": 0})
        totals[key]["packets"] += 1
        totals[key]["bytes"] += int(record.get("frame.len") or 0)
    ranked = sorted(totals.values(), key=lambda item: (item["bytes"], item["packets"]), reverse=True)
    return _write_rows(output_dir / "table-11-top-conversations.csv", ranked[:20])


def build_table_arp_replies(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_pcap_run(rows)
    if row is None:
        return None
    arp_rows = _tshark_rows(_pcap_path(row), ["frame.time_epoch", "eth.src", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"], display_filter="arp.opcode==2")
    return _write_rows(output_dir / "table-12-arp-replies.csv", arp_rows[:15])


def build_table_dns_answers(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_pcap_run(rows)
    if row is None:
        return None
    dns_rows = _tshark_rows(_pcap_path(row), ["frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name", "dns.a"], display_filter="dns.flags.response==1")
    return _write_rows(output_dir / "table-13-dns-answers.csv", dns_rows[:15])


def build_table_icmp_redirects(rows: list[dict[str, Any]], output_dir: Path) -> Path | None:
    row = _choose_pcap_run(rows)
    if row is None:
        return None
    icmp_rows = _tshark_rows(_pcap_path(row), ["frame.time_epoch", "ip.src", "ip.dst", "icmp.code"], display_filter="icmp.type==5")
    return _write_rows(output_dir / "table-14-icmp-redirects.csv", icmp_rows[:15])
