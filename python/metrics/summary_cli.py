#!/usr/bin/env python3

import json
import sqlite3
import sys
import os
from pathlib import Path

from metrics.core import load_or_evaluate_single_run
from metrics.run_artifacts import (
    DETECTOR_PACKET_ALERT_EVENTS,
    DETECTOR_STATE_EVENTS,
    detector_delta_path,
    detector_event_counter,
    detector_throughput_summary,
    load_json,
    load_jsonl,
    mean_or_none,
    parse_iperf_connection,
    parse_iperf_mbps,
    parse_ovs_dhcp_snooping_stats,
    parse_ovs_switch_truth_snooping_stats,
    parse_synthetic_traffic_summary,
    parse_traffic_windows,
    suricata_eve_path,
    zeek_notice_path,
)
from metrics.truth_db import trusted_observation_counts, truth_db_path

def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def results_db_path(target: Path) -> Path:
    if target.is_file():
        return target
    return target / "experiment-results.sqlite"


def format_metric(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}"


def format_metric_map(values: dict[str, object], *, precision: int = 3, suffix: str = "") -> str:
    if not values:
        return "-"
    rendered = []
    for key in sorted(values):
        value = values[key]
        if value is None:
            rendered.append(f"{key}=n/a")
        elif isinstance(value, float):
            rendered.append(f"{key}={value:.{precision}f}{suffix}")
        else:
            rendered.append(f"{key}={value}{suffix}")
    return ", ".join(rendered)


def count_detector_events(path: Path) -> tuple[int, int, int, int]:
    records = load_jsonl(path)
    counts = detector_event_counter(records)
    total = sum(counts.values())
    packet_alerts = sum(count for event, count in counts.items() if event in DETECTOR_PACKET_ALERT_EVENTS)
    semantic_alerts = sum(count for event, count in counts.items() if event in DETECTOR_STATE_EVENTS)
    total_alerts = packet_alerts + semantic_alerts
    return (total, packet_alerts, semantic_alerts, total_alerts)


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def count_zeek_notices(path: Path) -> str:
    if not path.exists():
        return "n/a"
    alerts = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("note"):
            alerts += 1
    return str(alerts)


def count_suricata_alerts(path: Path, meta: dict[str, object]) -> str:
    if not path.exists():
        return "n/a"
    alerts = 0
    attacker_mac = str(meta.get("attacker_mac", "")).lower() or None
    gateway_ip = meta.get("gateway_lab_ip")
    victim_ip = meta.get("victim_ip")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("event_type") == "alert":
            alerts += 1
            continue
        if payload.get("event_type") != "arp":
            continue
        arp = payload.get("arp", {})
        opcode = str(arp.get("opcode", "")).lower()
        src_mac = str(arp.get("src_mac", "")).lower()
        src_ip = arp.get("src_ip")
        dest_ip = arp.get("dest_ip")
        if opcode not in {"reply", "response", "2"}:
            continue
        if attacker_mac and src_mac != attacker_mac:
            continue
        if gateway_ip and src_ip != gateway_ip:
            continue
        if victim_ip and dest_ip != victim_ip:
            continue
        alerts += 1
    return str(alerts)


def missing_metric_label(value: str, mode: str) -> str:
    if value != "-":
        return value
    return "n/a" if mode in {"manual-window", "scenario-window"} else value


def summarize_run(run_dir: Path) -> dict[str, str]:
    meta = load_json(run_dir / "run-meta.json")
    evaluation = load_or_evaluate_single_run(run_dir, use_cache=True, write_cache=True).as_dict()
    detector_total, detector_packet_alerts, detector_semantic_alerts, detector_total_alerts = count_detector_events(detector_delta_path(run_dir))
    detector_records = load_jsonl(detector_delta_path(run_dir))
    detector_throughput = detector_throughput_summary(detector_records)
    mode = meta.get("mode", "-")
    probe_windows = parse_traffic_windows(
        run_dir / "victim" / "traffic-window.txt",
        gateway_ip=meta.get("gateway_lab_ip"),
        attacker_ip=meta.get("attacker_ip"),
    )
    ping_gateway_avg = mean_or_none(window.ping_gateway_avg_ms for window in probe_windows)
    ping_attacker_avg = mean_or_none(window.ping_attacker_avg_ms for window in probe_windows)
    curl_avg = mean_or_none(window.curl_total_s for window in probe_windows)
    synthetic_traffic = parse_synthetic_traffic_summary(run_dir / "victim" / "traffic-window.txt")
    iperf_path = run_dir / "victim" / "iperf3.json"
    iperf_mbps = parse_iperf_mbps(iperf_path)
    iperf_local_host, iperf_remote_host = parse_iperf_connection(iperf_path)
    ovs_dhcp_stats = parse_ovs_dhcp_snooping_stats(run_dir / "detector" / "ovs-dhcp-snooping.txt")
    ovs_switch_truth_stats = parse_ovs_switch_truth_snooping_stats(run_dir / "detector" / "ovs-switch-truth-snooping.txt")
    truth_db_counts = trusted_observation_counts(run_dir)
    return {
        "run_id": meta.get("run_id", run_dir.name),
        "scenario": meta.get("scenario", "-"),
        "mode": mode,
        "ground_truth_source": evaluation.get("ground_truth_source", "-"),
        "wire_truth_attack_events": str(evaluation.get("ground_truth_attack_events", "-")),
        "wire_truth_attack_types": evaluation.get("ground_truth_attack_types", {}) or {},
        "ground_truth_attacker_action_events": str(evaluation.get("ground_truth_attacker_action_events", "-")),
        "ground_truth_attacker_action_types": evaluation.get("ground_truth_attacker_action_types", {}) or {},
        "wire_truth_capture_duration_seconds": evaluation.get("ground_truth_capture_duration_seconds"),
        "wire_truth_attack_duration_seconds": evaluation.get("ground_truth_attack_duration_seconds"),
        "wire_truth_attack_type_rates": evaluation.get("ground_truth_attack_type_packet_rates_pps", {}) or {},
        "wire_truth_dns_query_count": str(evaluation.get("ground_truth_dns_query_count", 0)),
        "wire_truth_dns_spoof_success_ratio": evaluation.get("ground_truth_dns_spoof_success_ratio"),
        "wire_truth_arp_direction_counts": evaluation.get("ground_truth_arp_spoof_direction_counts", {}) or {},
        "wire_truth_control_plane_counts": evaluation.get("ground_truth_control_plane_packet_counts", {}) or {},
        "ping_gateway_avg_ms": missing_metric_label(format_metric(ping_gateway_avg), mode),
        "ping_attacker_avg_ms": missing_metric_label(format_metric(ping_attacker_avg), mode),
        "curl_total_s": missing_metric_label(format_metric(curl_avg), mode),
        "traffic_probe_icmp_packets": str(synthetic_traffic.get("sent_icmp", "-")),
        "traffic_probe_dns_queries": str(synthetic_traffic.get("sent_dns_queries", "-")),
        "traffic_probe_requested_pps": format_metric(synthetic_traffic.get("icmp_requested_pps")),
        "traffic_probe_scapy_error": str(synthetic_traffic.get("scapy_error") or ""),
        "iperf_mbps": missing_metric_label(format_metric(iperf_mbps), mode),
        "iperf_path": f"{iperf_local_host or '?'} -> {iperf_remote_host or '?'}",
        "detector_events": str(detector_total),
        "detector_alerts": str(detector_packet_alerts),
        "detector_max_seen_pps": format_metric(detector_throughput.get("max_interval_seen_pps")),
        "detector_max_processed_pps": format_metric(detector_throughput.get("max_interval_processed_pps")),
        "detector_packets_seen": str(detector_throughput.get("packets_seen", "-")),
        "detector_packets_processed": str(detector_throughput.get("packets_processed", "-")),
        "zeek_alerts": count_zeek_notices(zeek_notice_path(run_dir)),
        "suricata_alerts": count_suricata_alerts(suricata_eve_path(run_dir), meta),
        "suricata_arp_rule_enabled": "yes" if meta.get("suricata_arp_rule_enabled") else "no",
        "suricata_arp_rule_note": meta.get("suricata_arp_rule_note", ""),
        "suricata_arp_detected": "yes" if (evaluation.get("suricata_attack_type_counts", {}) or {}).get("arp_spoof", 0) > 0 else "no",
        "ovs_dhcp_snooping_mode": str(ovs_dhcp_stats.get("mode") or meta.get("ovs_dhcp_snooping_mode", "n/a")),
        "ovs_dhcp_snooping_packets": str(ovs_dhcp_stats.get("packets", 0)),
        "ovs_dhcp_snooping_actions": ovs_dhcp_stats.get("packets_by_action", {}) or {},
        "ovs_switch_truth_packets": format_metric_map(ovs_switch_truth_stats.get("packets_by_type", {}) or {}, precision=0),
        "trusted_ground_truth_db": str(truth_db_path(run_dir).relative_to(run_dir)) if truth_db_path(run_dir).exists() else "-",
        "trusted_ground_truth_db_counts": format_metric_map(truth_db_counts, precision=0),
        "dns_log_lines": str(count_nonempty_lines(run_dir / "gateway" / "dnsmasq.delta.log")),
        "path": str(run_dir),
    }


def print_single(summary: dict[str, str]) -> None:
    truth_label = "Wire-truth" if summary["ground_truth_source"] in {"switch_pcap", "victim_pcap"} else "Ground-truth"
    print(f"Run: {summary['run_id']}")
    print(f"Scenario: {summary['scenario']} ({summary['mode']})")
    print(f"Ground-truth source: {summary['ground_truth_source']}")
    print(f"Ping gateway avg: {summary['ping_gateway_avg_ms']} ms")
    print(f"Ping attacker avg: {summary['ping_attacker_avg_ms']} ms")
    print(
        "Synthetic traffic: "
        f"icmp={summary['traffic_probe_icmp_packets']}, "
        f"dns_queries={summary['traffic_probe_dns_queries']}, "
        f"requested={summary['traffic_probe_requested_pps']} pps"
    )
    if summary["traffic_probe_scapy_error"]:
        print(f"Synthetic traffic Scapy fallback: {summary['traffic_probe_scapy_error']}")
    print(f"Curl total: {summary['curl_total_s']} s")
    print(f"Iperf lab throughput: {summary['iperf_mbps']} Mbps")
    print(f"Ground-truth attack packets: {summary['wire_truth_attack_events']}")
    print(f"Ground-truth action events: {summary['ground_truth_attacker_action_events']}")
    print(f"Ground-truth action types: {format_metric_map(summary['ground_truth_attacker_action_types'], precision=0)}")
    print(f"{truth_label} packets by type: {format_metric_map(summary['wire_truth_attack_types'], precision=0)}")
    if summary["wire_truth_capture_duration_seconds"] is not None:
        print(f"{truth_label} capture duration: {format_metric(summary['wire_truth_capture_duration_seconds'])} s")
    if summary["wire_truth_attack_duration_seconds"] is not None:
        print(f"{truth_label} attack duration: {format_metric(summary['wire_truth_attack_duration_seconds'])} s")
    if summary["wire_truth_attack_type_rates"]:
        print(f"{truth_label} packet rates: {format_metric_map(summary['wire_truth_attack_type_rates'], suffix=' pps')}")
    if summary["wire_truth_dns_query_count"] != "0" or summary["wire_truth_dns_spoof_success_ratio"] is not None:
        print(
            f"{truth_label} DNS spoof success: "
            f"{format_metric(summary['wire_truth_dns_spoof_success_ratio'])} "
            f"(queries={summary['wire_truth_dns_query_count']})"
        )
    if summary["ground_truth_source"] in {"switch_pcap", "victim_pcap"} and summary["wire_truth_arp_direction_counts"]:
        print(f"{truth_label} ARP symmetry: {format_metric_map(summary['wire_truth_arp_direction_counts'], precision=0)}")
    if summary["wire_truth_control_plane_counts"]:
        print(f"Wire-truth control-plane counts: {format_metric_map(summary['wire_truth_control_plane_counts'], precision=0)}")
    print(f"Detector packet alerts: {summary['detector_alerts']}")
    print(
        "Detector throughput: "
        f"seen={summary['detector_max_seen_pps']} pps, "
        f"processed={summary['detector_max_processed_pps']} pps "
        f"(packets={summary['detector_packets_processed']}/{summary['detector_packets_seen']})"
    )
    print(f"Zeek notices: {summary['zeek_alerts']}")
    print(f"Suricata alerts: {summary['suricata_alerts']}")
    print(
        "OVS DHCP replies from untrusted ports: "
        f"{summary['ovs_dhcp_snooping_packets']} "
        f"({summary['ovs_dhcp_snooping_mode']}; {format_metric_map(summary['ovs_dhcp_snooping_actions'], precision=0)})"
    )
    if summary["ovs_switch_truth_packets"] != "-":
        print(f"OVS ARP/DNS trust violations: {summary['ovs_switch_truth_packets']}")
    if summary["trusted_ground_truth_db"] != "-":
        print(f"Trusted ground-truth DB: {summary['trusted_ground_truth_db']} ({summary['trusted_ground_truth_db_counts']})")
    print(f"DNS log lines: {summary['dns_log_lines']}")
    print(f"Artifacts: {summary['path']}")


def print_table(summaries: list[dict[str, str]]) -> None:
    headers = [
        "run_id",
        "scenario",
        "mode",
        "ping_gateway_avg_ms",
        "traffic_probe_icmp_packets",
        "traffic_probe_dns_queries",
        "curl_total_s",
        "iperf_mbps",
        "wire_truth_attack_events",
        "detector_alerts",
        "detector_max_seen_pps",
        "detector_max_processed_pps",
        "ovs_dhcp_snooping_packets",
        "ovs_switch_truth_packets",
        "trusted_ground_truth_db_counts",
        "zeek_alerts",
        "suricata_alerts",
        "path",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for summary in summaries:
        print("| " + " | ".join(summary.get(header, "-") for header in headers) + " |")


def print_db_table(db_path: Path) -> None:
    headers = [
        "run_id",
        "scenario",
        "ground_truth_source",
        "detector_alert_events",
        "zeek_alert_events",
        "suricata_alert_events",
        "detector_max_processed_pps",
        "run_dir",
    ]
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT run_id, scenario, ground_truth_source, detector_alert_events,
                   zeek_alert_events, suricata_alert_events,
                   detector_max_processed_pps, run_dir
            FROM run_overview
            ORDER BY started_at DESC, run_id DESC
            """
        ).fetchall()
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join("-" if value is None else str(value) for value in row) + " |")


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    if not target.exists():
        print(f"No results found at {target}", file=sys.stderr)
        return 1

    db_path = results_db_path(target)
    if (
        target.is_dir()
        and not (target / "run-meta.json").exists()
        and db_path.exists()
        and os.getenv("MITM_LAB_SUMMARY_USE_FILES", "0") != "1"
    ):
        print_db_table(db_path)
        return 0

    run_dirs = find_run_dirs(target)
    if not run_dirs:
        if db_path.exists():
            print_db_table(db_path)
            return 0
        print(f"No run-meta.json files or experiment-results.sqlite found under {target}", file=sys.stderr)
        return 1

    summaries = [summarize_run(run_dir) for run_dir in run_dirs]
    if len(summaries) == 1:
        print_single(summaries[0])
    else:
        print_table(summaries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
