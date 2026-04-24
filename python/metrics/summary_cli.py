#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from metrics.run_artifacts import (
    DETECTOR_PACKET_ALERT_EVENTS,
    DETECTOR_STATE_EVENTS,
    detector_delta_path,
    detector_event_counter,
    load_json,
    load_jsonl,
    mean_or_none,
    parse_iperf_connection,
    parse_iperf_mbps,
    parse_traffic_windows,
    suricata_eve_path,
    zeek_notice_path,
)

def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


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
    evaluation = load_json(run_dir / "evaluation.json") if (run_dir / "evaluation.json").exists() else {}
    detector_total, detector_packet_alerts, detector_semantic_alerts, detector_total_alerts = count_detector_events(detector_delta_path(run_dir))
    mode = meta.get("mode", "-")
    probe_windows = parse_traffic_windows(
        run_dir / "victim" / "traffic-window.txt",
        gateway_ip=meta.get("gateway_lab_ip"),
        attacker_ip=meta.get("attacker_ip"),
    )
    ping_gateway_avg = mean_or_none(window.ping_gateway_avg_ms for window in probe_windows)
    ping_attacker_avg = mean_or_none(window.ping_attacker_avg_ms for window in probe_windows)
    curl_avg = mean_or_none(window.curl_total_s for window in probe_windows)
    iperf_path = run_dir / "victim" / "iperf3.json"
    iperf_mbps = parse_iperf_mbps(iperf_path)
    iperf_local_host, iperf_remote_host = parse_iperf_connection(iperf_path)
    return {
        "run_id": meta.get("run_id", run_dir.name),
        "scenario": meta.get("scenario", "-"),
        "mode": mode,
        "wire_truth_attack_events": str(evaluation.get("ground_truth_attack_events", "-")),
        "wire_truth_attack_types": evaluation.get("ground_truth_attack_types", {}) or {},
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
        "iperf_mbps": missing_metric_label(format_metric(iperf_mbps), mode),
        "iperf_path": f"{iperf_local_host or '?'} -> {iperf_remote_host or '?'}",
        "detector_events": str(detector_total),
        "detector_alerts": str(detector_packet_alerts),
        "zeek_alerts": count_zeek_notices(zeek_notice_path(run_dir)),
        "suricata_alerts": count_suricata_alerts(suricata_eve_path(run_dir), meta),
        "ground_truth_source": evaluation.get("ground_truth_source", "-"),
        "suricata_arp_rule_enabled": "yes" if meta.get("suricata_arp_rule_enabled") else "no",
        "suricata_arp_rule_note": meta.get("suricata_arp_rule_note", ""),
        "suricata_arp_detected": "yes" if (evaluation.get("suricata_attack_type_counts", {}) or {}).get("arp_spoof", 0) > 0 else "no",
        "dns_log_lines": str(count_nonempty_lines(run_dir / "gateway" / "dnsmasq.delta.log")),
        "path": str(run_dir),
    }


def print_single(summary: dict[str, str]) -> None:
    ground_truth_label = "Wire-truth matched packets" if summary["ground_truth_source"] in {"switch_pcap", "victim_pcap"} else "Ground-truth attack events"
    print(f"Run: {summary['run_id']}")
    print(f"Scenario: {summary['scenario']} ({summary['mode']})")
    print(f"Ping gateway avg: {summary['ping_gateway_avg_ms']} ms")
    print(f"Ping attacker avg: {summary['ping_attacker_avg_ms']} ms")
    print(f"Curl total: {summary['curl_total_s']} s")
    print(f"Iperf lab throughput: {summary['iperf_mbps']} Mbps")
    print(f"{ground_truth_label}: {summary['wire_truth_attack_events']}")
    if summary["ground_truth_source"] in {"switch_pcap", "victim_pcap"}:
        print(f"Wire-truth packets by type: {format_metric_map(summary['wire_truth_attack_types'], precision=0)}")
        print(f"Wire-truth capture duration: {format_metric(summary['wire_truth_capture_duration_seconds'])} s")
        print(f"Wire-truth attack duration: {format_metric(summary['wire_truth_attack_duration_seconds'])} s")
        print(f"Wire-truth packet rates: {format_metric_map(summary['wire_truth_attack_type_rates'], suffix=' pps')}")
        if summary["wire_truth_dns_query_count"] != "0" or summary["wire_truth_dns_spoof_success_ratio"] is not None:
            print(
                "Wire-truth DNS spoof success: "
                f"{format_metric(summary['wire_truth_dns_spoof_success_ratio'])} "
                f"(queries={summary['wire_truth_dns_query_count']})"
            )
        if summary["wire_truth_arp_direction_counts"]:
            print(f"Wire-truth ARP symmetry: {format_metric_map(summary['wire_truth_arp_direction_counts'], precision=0)}")
        if summary["wire_truth_control_plane_counts"]:
            print(f"Wire-truth control-plane counts: {format_metric_map(summary['wire_truth_control_plane_counts'], precision=0)}")
    print(f"Detector packet alerts: {summary['detector_alerts']}")
    print(f"Zeek notices: {summary['zeek_alerts']}")
    print(f"Suricata alerts: {summary['suricata_alerts']}")
    print(f"Ground truth source: {summary['ground_truth_source']}")
    if summary["suricata_arp_rule_enabled"] == "no":
        if summary["suricata_arp_detected"] == "yes":
            note = "signature self-test failed, but ARP spoof was detected via Suricata EVE ARP records"
        else:
            note = summary["suricata_arp_rule_note"] or "disabled on this host build/config"
        print(f"Suricata ARP coverage: {note}")
    print(f"DNS log lines: {summary['dns_log_lines']}")
    print(f"Artifacts: {summary['path']}")


def print_table(summaries: list[dict[str, str]]) -> None:
    headers = [
        "run_id",
        "scenario",
        "mode",
        "ping_gateway_avg_ms",
        "curl_total_s",
        "iperf_mbps",
        "wire_truth_attack_events",
        "detector_alerts",
        "zeek_alerts",
        "suricata_alerts",
        "ground_truth_source",
        "path",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for summary in summaries:
        print("| " + " | ".join(summary.get(header, "-") for header in headers) + " |")


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    if not target.exists():
        print(f"No results found at {target}", file=sys.stderr)
        return 1

    run_dirs = find_run_dirs(target)
    if not run_dirs:
        print(f"No run-meta.json files found under {target}", file=sys.stderr)
        return 1

    summaries = [summarize_run(run_dir) for run_dir in run_dirs]
    if len(summaries) == 1:
        print_single(summaries[0])
    else:
        print_table(summaries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
