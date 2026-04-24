#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from metrics.run_artifacts import detector_delta_path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_probe_windows(path: Path) -> list[dict]:
    windows: list[dict] = []
    if not path.exists():
        return windows

    current: dict | None = None
    current_domain: str | None = None

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("ts="):
            if current:
                windows.append(current)
            current = {"ts": line.removeprefix("ts="), "domains": {}}
            current_domain = None
            continue
        if current is None:
            continue
        if line.startswith("domain="):
            current_domain = line.removeprefix("domain=")
            current["domains"].setdefault(current_domain, [])
            continue
        if current_domain and all(ch.isdigit() or ch == "." for ch in line):
            current["domains"][current_domain].append(line)

    if current:
        windows.append(current)
    return windows


def first_event(records: list[dict], event_type: str) -> dict | None:
    return next((record for record in records if record.get("event") == event_type), None)


def first_domain_event(records: list[dict], event_type: str) -> dict[str, dict]:
    matches: dict[str, dict] = {}
    for record in records:
        if record.get("event") != event_type:
            continue
        domain = record.get("domain")
        if domain and domain not in matches:
            matches[domain] = record
    return matches


def summarize_probe_windows(probes: list[dict], attacker_ip: str) -> tuple[str, list[str]]:
    if not probes:
        return ("no victim active-probe file captured", [])

    first_clean = probes[0]
    first_spoofed = None
    for probe in probes:
        for answers in probe.get("domains", {}).values():
            if attacker_ip in answers:
                first_spoofed = probe
                break
        if first_spoofed:
            break

    lines = [
        f"first_probe_ts={first_clean['ts']}",
        "first_probe_answers="
        + json.dumps(first_clean.get("domains", {}), sort_keys=True),
    ]
    if first_spoofed:
        lines.extend(
            [
                f"first_spoofed_probe_ts={first_spoofed['ts']}",
                "first_spoofed_probe_answers="
                + json.dumps(first_spoofed.get("domains", {}), sort_keys=True),
            ]
        )
        return ("victim active probes observed spoofed DNS answers", lines)

    return ("victim active probes did not observe spoofed DNS answers", lines)


def summarize_post_window_probe(path: Path, attacker_ip: str) -> tuple[str, str]:
    probes = parse_probe_windows(path)
    if not probes:
        return ("post_window_probe", "not_captured")
    latest = probes[-1]
    all_answers = latest.get("domains", {}).values()
    status = "clean"
    if all(not answers for answers in all_answers):
        status = "dns_unreachable"
    for answers in latest.get("domains", {}).values():
        if attacker_ip and attacker_ip in answers:
            status = "still_spoofed"
            break
    return ("post_window_probe", json.dumps({"status": status, "probe": latest}, sort_keys=True))


def main() -> int:
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    meta_path = run_dir / "run-meta.json"
    if not meta_path.exists():
        raise SystemExit(f"Missing run-meta.json under {run_dir}")

    meta = load_json(meta_path)
    attacker_ip = meta.get("attacker_ip", "")
    detector_records = load_jsonl(detector_delta_path(run_dir))
    probe_windows = parse_probe_windows(run_dir / "victim" / "traffic-window.txt")
    post_window_key, post_window_value = summarize_post_window_probe(
        run_dir / "victim" / "post-window-probe.txt",
        attacker_ip,
    )

    counts = Counter(record.get("event", "unknown") for record in detector_records)
    packet_alert_counts = {
        key: counts[key]
        for key in (
            "arp_spoof_packet_seen",
            "icmp_redirect_packet_seen",
            "dns_spoof_packet_seen",
            "rogue_dhcp_server_seen",
            "dhcp_binding_conflict_seen",
        )
        if counts.get(key, 0)
    }
    state_transition_counts = {
        key: counts[key]
        for key in (
            "gateway_mac_changed",
            "gateway_mac_restored",
            "multiple_gateway_macs_seen",
            "single_gateway_mac_restored",
            "icmp_redirects_seen",
            "domain_resolution_changed",
            "domain_resolution_restored",
            "rogue_dhcp_server_cleared",
        )
        if counts.get(key, 0)
    }

    gateway_change = first_event(detector_records, "gateway_mac_changed")
    multi_gateway = first_event(detector_records, "multiple_gateway_macs_seen")
    icmp_redirects = first_event(detector_records, "icmp_redirects_seen")
    domain_changes = first_domain_event(detector_records, "domain_resolution_changed")
    domain_restores = first_domain_event(detector_records, "domain_resolution_restored")
    probe_status, probe_lines = summarize_probe_windows(probe_windows, attacker_ip)

    lines = [
        f"run_id={meta.get('run_id', run_dir.name)}",
        f"scenario={meta.get('scenario', '-')}",
        f"mode={meta.get('mode', '-')}",
        f"attacker_ip={attacker_ip or '-'}",
        f"detector_event_count={len(detector_records)}",
        f"detector_packet_alert_count={sum(packet_alert_counts.values())}",
        f"detector_state_transition_alert_count={sum(state_transition_counts.values())}",
        f"detector_total_alert_count={sum(packet_alert_counts.values()) + sum(state_transition_counts.values())}",
        "detector_packet_alert_breakdown=" + json.dumps(packet_alert_counts, sort_keys=True),
        "detector_state_transition_breakdown=" + json.dumps(state_transition_counts, sort_keys=True),
        f"probe_summary={probe_status}",
    ]

    if gateway_change:
        lines.append(
            "first_gateway_mac_change="
            + json.dumps(
                {
                    "ts": gateway_change.get("ts"),
                    "expected_gateway_mac": gateway_change.get("expected_gateway_mac"),
                    "current_gateway_mac": gateway_change.get("current_gateway_mac"),
                },
                sort_keys=True,
            )
        )

    if multi_gateway:
        lines.append(
            "first_multi_gateway_view="
            + json.dumps(
                {
                    "ts": multi_gateway.get("ts"),
                    "gateway_macs": multi_gateway.get("gateway_macs", []),
                },
                sort_keys=True,
            )
        )

    if icmp_redirects:
        lines.append(
            "first_icmp_redirect_signal="
            + json.dumps(
                {
                    "ts": icmp_redirects.get("ts"),
                    "previous_count": icmp_redirects.get("previous_count"),
                    "current_count": icmp_redirects.get("current_count"),
                    "delta": icmp_redirects.get("delta"),
                },
                sort_keys=True,
            )
        )

    if domain_changes:
        lines.append("first_domain_changes=")
        for domain in sorted(domain_changes):
            record = domain_changes[domain]
            lines.append(
                json.dumps(
                    {
                        "domain": domain,
                        "ts": record.get("ts"),
                        "baseline": record.get("baseline", []),
                        "current": record.get("current", []),
                    },
                    sort_keys=True,
                )
            )

    if domain_restores:
        lines.append("first_domain_restores=")
        for domain in sorted(domain_restores):
            record = domain_restores[domain]
            lines.append(
                json.dumps(
                    {
                        "domain": domain,
                        "ts": record.get("ts"),
                        "baseline": record.get("baseline", []),
                        "current": record.get("current", []),
                    },
                    sort_keys=True,
                )
            )

    if probe_lines:
        lines.append("victim_probe_windows=")
        lines.extend(probe_lines)
    lines.append(f"{post_window_key}={post_window_value}")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
