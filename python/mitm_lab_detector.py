#!/usr/bin/env python3
from __future__ import annotations

import json
import ipaddress
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

GATEWAY_IP = "__GATEWAY_IP__"
DNS_SERVER = "__DNS_SERVER__"
DOMAINS = [__PYTHON_DOMAIN_LIST__]
LOG_PATH = Path("/var/log/mitm-lab-detector.jsonl")
STATE_PATH = Path("/var/lib/mitm-lab-detector/state.json")
POLL_SECONDS = 2
MAC_RE = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)


def now():
    return datetime.now(timezone.utc).isoformat()


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def get_gateway_mac():
    result = run(["ip", "neigh", "show", GATEWAY_IP])
    match = MAC_RE.search(result.stdout)
    return match.group(1).lower() if match else None


def get_icmp_redirect_count():
    try:
        lines = Path("/proc/net/snmp").read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0

    for index, line in enumerate(lines):
        if not line.startswith("Icmp: "):
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("Icmp: "):
            continue
        headers = line.split()[1:]
        values = lines[index + 1].split()[1:]
        try:
            position = headers.index("InRedirects")
            return int(values[position])
        except (ValueError, IndexError):
            return 0
    return 0


def normalize_answers(answers):
    normalized = []
    for answer in answers:
        value = answer.strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        normalized.append(value)
    return sorted(set(normalized))


def resolve_a(domain):
    result = run(["dig", "+time=1", "+tries=1", "+short", "A", domain, f"@{DNS_SERVER}"])
    return normalize_answers(result.stdout.splitlines())


def load_state():
    if not STATE_PATH.exists():
        return {"domain_baselines": {}}
    try:
        payload = json.loads(STATE_PATH.read_text())
    except Exception:
        return {"domain_baselines": {}}

    baselines = {
        domain: normalize_answers(answers)
        for domain, answers in payload.get("domain_baselines", {}).items()
        if isinstance(answers, list)
    }
    return {
        "expected_gateway_mac": payload.get("expected_gateway_mac"),
        "domain_baselines": baselines,
        "icmp_redirect_count": int(payload.get("icmp_redirect_count", 0) or 0),
    }


def save_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


def log_event(event_type, **payload):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": now(), "event": event_type, **payload}
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def main():
    state = load_state()
    seen_gateway_macs = set()
    domain_baselines = dict(state.get("domain_baselines", {}))
    expected_gateway_mac = state.get("expected_gateway_mac")
    previous_icmp_redirect_count = int(state.get("icmp_redirect_count", 0) or 0)
    gateway_mismatch_active = False
    last_mismatch_gateway_mac = None
    multi_gateway_active = False
    last_reported_gateway_macs = []
    domain_mismatch_active = {domain: False for domain in DOMAINS}
    domain_failure_active = {domain: False for domain in DOMAINS}
    last_domain_mismatch_answers = {}
    poll_count = 0

    log_event(
        "detector_started",
        gateway_ip=GATEWAY_IP,
        dns_server=DNS_SERVER,
        domains=DOMAINS,
        expected_gateway_mac=expected_gateway_mac,
        domain_baselines=domain_baselines,
    )

    while True:
        poll_count += 1
        current_mac = get_gateway_mac()
        if current_mac and not expected_gateway_mac:
            expected_gateway_mac = current_mac
            log_event("gateway_baseline_set", expected_gateway_mac=expected_gateway_mac)

        if current_mac:
            seen_gateway_macs.add(current_mac)

        current_icmp_redirect_count = get_icmp_redirect_count()
        if current_icmp_redirect_count > previous_icmp_redirect_count:
            log_event(
                "icmp_redirects_seen",
                previous_count=previous_icmp_redirect_count,
                current_count=current_icmp_redirect_count,
                delta=current_icmp_redirect_count - previous_icmp_redirect_count,
            )
        previous_icmp_redirect_count = current_icmp_redirect_count

        gateway_mismatch = bool(expected_gateway_mac and current_mac and current_mac != expected_gateway_mac)
        if gateway_mismatch:
            if not gateway_mismatch_active or current_mac != last_mismatch_gateway_mac:
                log_event(
                    "gateway_mac_changed",
                    expected_gateway_mac=expected_gateway_mac,
                    current_gateway_mac=current_mac,
                )
            last_mismatch_gateway_mac = current_mac
        elif gateway_mismatch_active:
            log_event(
                "gateway_mac_restored",
                expected_gateway_mac=expected_gateway_mac,
                current_gateway_mac=current_mac,
            )
            last_mismatch_gateway_mac = None
        gateway_mismatch_active = gateway_mismatch

        current_gateway_macs = sorted(seen_gateway_macs)
        multiple_gateway_macs = len(current_gateway_macs) > 1
        if multiple_gateway_macs:
            if (not multi_gateway_active) or current_gateway_macs != last_reported_gateway_macs:
                log_event("multiple_gateway_macs_seen", gateway_macs=current_gateway_macs)
                last_reported_gateway_macs = list(current_gateway_macs)
        elif multi_gateway_active:
            log_event("single_gateway_mac_restored", gateway_macs=current_gateway_macs)
            last_reported_gateway_macs = list(current_gateway_macs)
        multi_gateway_active = multiple_gateway_macs

        resolutions = {}
        for domain in DOMAINS:
            answers = resolve_a(domain)
            resolutions[domain] = answers
            if answers and domain not in domain_baselines:
                domain_baselines[domain] = answers
                log_event("domain_baseline_set", domain=domain, answers=answers)
                continue

            if not answers and domain in domain_baselines:
                if not domain_failure_active.get(domain, False):
                    log_event(
                        "domain_resolution_failed",
                        domain=domain,
                        baseline=domain_baselines[domain],
                    )
                domain_failure_active[domain] = True
                continue

            if domain_failure_active.get(domain, False):
                log_event(
                    "domain_resolution_recovered",
                    domain=domain,
                    current=answers,
                )
                domain_failure_active[domain] = False

            if not answers or domain not in domain_baselines:
                continue

            mismatch = answers != domain_baselines[domain]
            if mismatch:
                if (
                    not domain_mismatch_active.get(domain, False)
                    or answers != last_domain_mismatch_answers.get(domain)
                ):
                    log_event(
                        "domain_resolution_changed",
                        domain=domain,
                        baseline=domain_baselines[domain],
                        current=answers,
                    )
                    last_domain_mismatch_answers[domain] = list(answers)
            elif domain_mismatch_active.get(domain, False):
                log_event(
                    "domain_resolution_restored",
                    domain=domain,
                    baseline=domain_baselines[domain],
                    current=answers,
                )
                last_domain_mismatch_answers.pop(domain, None)
            domain_mismatch_active[domain] = mismatch

        log_event(
            "heartbeat",
            poll=poll_count,
            expected_gateway_mac=expected_gateway_mac,
            current_gateway_mac=current_mac,
            gateway_mismatch_active=gateway_mismatch_active,
            multi_gateway_active=multi_gateway_active,
            icmp_redirect_count=current_icmp_redirect_count,
            seen_gateway_macs=current_gateway_macs,
            domain_mismatch_active={
                domain: domain_mismatch_active.get(domain, False)
                for domain in DOMAINS
            },
            domain_failure_active={
                domain: domain_failure_active.get(domain, False)
                for domain in DOMAINS
            },
            resolutions=resolutions,
        )

        save_state({
            "expected_gateway_mac": expected_gateway_mac,
            "domain_baselines": domain_baselines,
            "icmp_redirect_count": previous_icmp_redirect_count,
        })
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
