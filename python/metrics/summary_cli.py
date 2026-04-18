#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from metrics.run_artifacts import (
    DETECTOR_PACKET_ALERT_EVENTS,
    DETECTOR_STATE_EVENTS,
    detector_event_counter,
    load_json,
    load_jsonl,
    mean_or_none,
    parse_iperf_connection,
    parse_iperf_mbps,
    parse_traffic_windows,
)

def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def format_metric(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}"


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


def count_suricata_alerts(path: Path) -> str:
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
        if payload.get("event_type") == "alert":
            alerts += 1
    return str(alerts)


def missing_metric_label(value: str, mode: str) -> str:
    if value != "-":
        return value
    return "n/a" if mode in {"manual-window", "scenario-window"} else value


def summarize_run(run_dir: Path) -> dict[str, str]:
    meta = load_json(run_dir / "run-meta.json")
    detector_total, detector_packet_alerts, detector_semantic_alerts, detector_total_alerts = count_detector_events(run_dir / "victim" / "detector.delta.jsonl")
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
        "ping_gateway_avg_ms": missing_metric_label(format_metric(ping_gateway_avg), mode),
        "ping_attacker_avg_ms": missing_metric_label(format_metric(ping_attacker_avg), mode),
        "curl_total_s": missing_metric_label(format_metric(curl_avg), mode),
        "iperf_mbps": missing_metric_label(format_metric(iperf_mbps), mode),
        "iperf_path": f"{iperf_local_host or '?'} -> {iperf_remote_host or '?'}",
        "detector_events": str(detector_total),
        "detector_alerts": str(detector_packet_alerts),
        "zeek_alerts": count_zeek_notices(run_dir / "zeek" / "victim" / "notice.log"),
        "suricata_alerts": count_suricata_alerts(run_dir / "suricata" / "victim" / "eve.json"),
        "dns_log_lines": str(count_nonempty_lines(run_dir / "gateway" / "dnsmasq.delta.log")),
        "path": str(run_dir),
    }


def print_single(summary: dict[str, str]) -> None:
    print(f"Run: {summary['run_id']}")
    print(f"Scenario: {summary['scenario']} ({summary['mode']})")
    print(f"Ping gateway avg: {summary['ping_gateway_avg_ms']} ms")
    print(f"Ping attacker avg: {summary['ping_attacker_avg_ms']} ms")
    print(f"Curl total: {summary['curl_total_s']} s")
    print(f"Iperf lab throughput: {summary['iperf_mbps']} Mbps")
    print(f"Detector alerts: {summary['detector_alerts']}")
    print(f"Zeek alerts: {summary['zeek_alerts']}")
    print(f"Suricata alerts: {summary['suricata_alerts']}")
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
        "detector_alerts",
        "zeek_alerts",
        "suricata_alerts",
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
