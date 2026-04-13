#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


PING_RE = re.compile(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms")
ALERT_EVENTS = {
    "gateway_mac_changed",
    "multiple_gateway_macs_seen",
    "domain_resolution_changed",
}


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def parse_ping_avg(path: Path) -> str:
    if not path.exists():
        return "-"
    match = PING_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    return match.group(2) if match else "-"


def parse_curl_total(path: Path) -> str:
    if not path.exists():
        return "-"
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values.get("time_total", "-")


def parse_iperf_mbps(path: Path) -> str:
    if not path.exists():
        return "-"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "-"
    bps = (
        payload.get("end", {})
        .get("sum_received", {})
        .get("bits_per_second")
    )
    if not bps:
        return "-"
    return f"{bps / 1_000_000:.2f}"


def count_detector_events(path: Path) -> tuple[int, int]:
    if not path.exists():
        return (0, 0)

    total = 0
    alerts = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        total += 1
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("event") in ALERT_EVENTS:
            alerts += 1
    return (total, alerts)


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def summarize_run(run_dir: Path) -> dict[str, str]:
    meta = json.loads((run_dir / "run-meta.json").read_text(encoding="utf-8"))
    detector_total, detector_alerts = count_detector_events(run_dir / "victim" / "detector.delta.jsonl")
    return {
        "run_id": meta.get("run_id", run_dir.name),
        "scenario": meta.get("scenario", "-"),
        "mode": meta.get("mode", "-"),
        "ping_gateway_avg_ms": parse_ping_avg(run_dir / "victim" / "ping-gateway.txt"),
        "ping_attacker_avg_ms": parse_ping_avg(run_dir / "victim" / "ping-attacker.txt"),
        "curl_total_s": parse_curl_total(run_dir / "victim" / "curl.txt"),
        "iperf_mbps": parse_iperf_mbps(run_dir / "victim" / "iperf3.json"),
        "detector_events": str(detector_total),
        "detector_alerts": str(detector_alerts),
        "dns_log_lines": str(count_nonempty_lines(run_dir / "gateway" / "dnsmasq.delta.log")),
        "path": str(run_dir),
    }


def print_single(summary: dict[str, str]) -> None:
    print(f"Run: {summary['run_id']}")
    print(f"Scenario: {summary['scenario']} ({summary['mode']})")
    print(f"Ping gateway avg: {summary['ping_gateway_avg_ms']} ms")
    print(f"Ping attacker avg: {summary['ping_attacker_avg_ms']} ms")
    print(f"Curl total: {summary['curl_total_s']} s")
    print(f"Iperf throughput: {summary['iperf_mbps']} Mbps")
    print(f"Detector events: {summary['detector_events']}")
    print(f"Detector alerts: {summary['detector_alerts']}")
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
