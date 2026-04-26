#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from scenarios.definitions import SCENARIOS

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"
GENERATED_DIR = REPO_ROOT / "generated" / "demo-ui"
JOB_LOG_DIR = GENERATED_DIR / "logs"
REPORT_DOWNLOAD_ZIP = GENERATED_DIR / "experiment-report.zip"
LATEST_RUN_DOWNLOAD_ZIP = GENERATED_DIR / "latest-run.zip"
ROOT_MODE = os.geteuid() == 0
DEMO_REAL_USER = os.environ.get("DEMO_REAL_USER") or ""
DEMO_REAL_GROUP = os.environ.get("DEMO_REAL_GROUP") or ""
DEMO_DISPLAY = os.environ.get("DEMO_DISPLAY") or os.environ.get("DISPLAY") or ""
DEMO_XAUTHORITY = os.environ.get("DEMO_XAUTHORITY") or os.environ.get("XAUTHORITY") or ""

DETECTOR_LOG = Path("/tmp/mitm-lab-detector-host.jsonl")
DETECTOR_STATE = Path("/tmp/mitm-lab-detector-host-state.json")
DETECTOR_PID = Path("/tmp/mitm-lab-detector-host.pid")
ZEEK_LOG = Path("/tmp/mitm-lab-zeek-host/current/notice.log")
ZEEK_PID = Path("/tmp/mitm-lab-zeek-host/zeek.pid")
SURICATA_LOG = Path("/tmp/mitm-lab-suricata-host/current/eve.json")
SURICATA_PID = Path("/tmp/mitm-lab-suricata-host/suricata.pid")

SCENARIO_SCRIPTS = {
    "arp-poison-no-forward": REPO_ROOT / "shell/scenarios/record-arp-poison-no-forward.sh",
    "arp-mitm-forward": REPO_ROOT / "shell/scenarios/record-arp-mitm-forward.sh",
    "arp-mitm-dns": REPO_ROOT / "shell/scenarios/record-arp-mitm-dns.sh",
    "dhcp-spoof": REPO_ROOT / "shell/scenarios/record-dhcp-spoof.sh",
    "dhcp-starvation": REPO_ROOT / "shell/scenarios/record-dhcp-starvation.sh",
    "dhcp-starvation-rogue-dhcp": REPO_ROOT / "shell/scenarios/record-dhcp-starvation-rogue-dhcp.sh",
    "visibility-arp-mitm-dns": REPO_ROOT / "shell/scenarios/record-visibility-arp-mitm-dns.sh",
    "visibility-dhcp-spoof": REPO_ROOT / "shell/scenarios/record-visibility-dhcp-spoof.sh",
    "mitigation-recovery": REPO_ROOT / "shell/scenarios/record-mitigation-recovery.sh",
}

DEMO_SCENARIOS = [
    "arp-poison-no-forward",
    "arp-mitm-forward",
    "arp-mitm-dns",
    "dhcp-spoof",
    "dhcp-starvation",
    "dhcp-starvation-rogue-dhcp",
    "visibility-arp-mitm-dns",
    "visibility-dhcp-spoof",
    "mitigation-recovery",
]

FEATURED_SCENARIOS = {"arp-mitm-dns", "dhcp-spoof", "dhcp-starvation", "dhcp-starvation-rogue-dhcp", "visibility-arp-mitm-dns", "visibility-dhcp-spoof"}


def load_lab_constants() -> dict[str, str]:
    constants: dict[str, str] = {}
    lab_conf = REPO_ROOT / "lab.conf"
    if not lab_conf.exists():
        return constants
    for raw_line in lab_conf.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        constants[key.strip()] = value.strip().strip('"').strip("'")
    return constants


LAB_CONSTANTS = load_lab_constants()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_generated_dirs() -> None:
    JOB_LOG_DIR.mkdir(parents=True, exist_ok=True)


def clamp_duration(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 20
    return max(5, min(60, value))


def clamp_visibility(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 100
    return max(0, min(100, value))


def clamp_workers(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(108, value))


def load_json_file(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def read_pid(pid_path: Path) -> int | None:
    try:
        return int(pid_path.read_text(encoding="utf-8", errors="replace").strip())
    except (OSError, ValueError):
        return None


def pid_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_last_lines(path: Path, limit: int = 40, max_bytes: int = 256 * 1024) -> list[str]:
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            data = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = [line for line in data.splitlines() if line.strip()]
    return lines[-limit:]


def load_jsonl_tail(path: Path, limit: int = 40) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in read_last_lines(path, limit=limit * 4):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries[-limit:]


def load_jsonl_all(path: Path, max_bytes: int = 1024 * 1024) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            data = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def summarize_detector_entry(entry: dict[str, Any]) -> str:
    event = entry.get("event", "unknown")
    if event == "heartbeat":
        return (
            f"Heartbeat: arp={entry.get('arp_spoof_packets_seen', 0)} "
            f"dns={entry.get('dns_spoof_packets_seen', 0)} "
            f"dhcp={entry.get('rogue_dhcp_packets_seen', 0)} "
            f"starvation={entry.get('dhcp_starvation_packets_seen', 0)}"
        )
    if event == "dhcp_offer_seen":
        return (
            f"DHCP OFFER from {entry.get('dhcp_server')} to {entry.get('client_mac')} "
            f"assigned {entry.get('assigned_ip')}"
        )
    if event == "dhcp_ack_seen":
        return (
            f"DHCP ACK from {entry.get('dhcp_server')} to {entry.get('client_mac')} "
            f"assigned {entry.get('assigned_ip')}"
        )
    if event == "rogue_dhcp_server_seen":
        return f"Rogue DHCP server {entry.get('dhcp_server')} ({entry.get('dhcp_server_mac')})"
    if event == "dhcp_starvation_seen":
        return (
            f"DHCP starvation suspected: {entry.get('unique_client_count')} unique clients "
            f"in {entry.get('window_seconds')}s"
        )
    if event == "dhcp_starvation_packet_seen":
        return (
            f"DHCP {entry.get('message_type')} from {entry.get('client_mac')} "
            f"(unique clients={entry.get('unique_client_count')})"
        )
    if event == "gateway_mac_changed":
        return f"Gateway MAC changed to {entry.get('gateway_mac')}"
    if event == "multiple_gateway_macs_seen":
        return f"Multiple gateway MACs seen: {', '.join(entry.get('seen_gateway_macs', []))}"
    if event == "domain_resolution_changed":
        return f"DNS changed for {entry.get('domain')} -> {entry.get('answers')}"
    return json.dumps(entry, sort_keys=True)


def summarize_zeek_entry(entry: dict[str, Any]) -> str:
    note = entry.get("note", "notice")
    msg = entry.get("msg") or entry.get("sub") or "Zeek notice"
    return f"{note}: {msg}"


def summarize_suricata_entry(entry: dict[str, Any]) -> str:
    event_type = entry.get("event_type", "event")
    if event_type == "alert":
        alert = entry.get("alert", {})
        return alert.get("signature") or "Suricata alert"
    if event_type == "arp":
        arp = entry.get("arp", {})
        return (
            f"ARP {arp.get('opcode')} {arp.get('src_ip')} ({arp.get('src_mac')}) "
            f"-> {arp.get('dest_ip')}"
        )
    if event_type == "dns":
        dns = entry.get("dns", {})
        rrname = dns.get("rrname") or dns.get("query", [{}])[0].get("rrname") if isinstance(dns.get("query"), list) else None
        return f"DNS {dns.get('type', '').upper() or 'event'} {rrname or ''}".strip()
    if event_type == "dhcp":
        dhcp = entry.get("dhcp", {})
        return f"DHCP {dhcp.get('type', 'event')} from {entry.get('src_ip')}"
    if event_type == "icmp":
        return f"ICMP from {entry.get('src_ip')} to {entry.get('dest_ip')}"
    return json.dumps(entry, sort_keys=True)


def interesting_detector_entries(limit: int = 25) -> list[dict[str, Any]]:
    records = load_jsonl_tail(DETECTOR_LOG, limit=limit * 3)
    filtered = [entry for entry in records if entry.get("event") != "heartbeat"]
    chosen = filtered[-limit:] if filtered else records[-limit:]
    return [
        {
            "timestamp": entry.get("ts"),
            "kind": entry.get("event", "event"),
            "summary": summarize_detector_entry(entry),
            "raw": entry,
        }
        for entry in chosen
    ]


def interesting_zeek_entries(limit: int = 25) -> list[dict[str, Any]]:
    records = load_jsonl_tail(ZEEK_LOG, limit=limit)
    return [
        {
            "timestamp": entry.get("ts"),
            "kind": entry.get("note", "notice"),
            "summary": summarize_zeek_entry(entry),
            "raw": entry,
        }
        for entry in records[-limit:]
    ]


def interesting_suricata_entries(limit: int = 25) -> list[dict[str, Any]]:
    interesting_types = {"alert", "arp", "dns", "dhcp", "icmp"}
    records = [
        entry
        for entry in load_jsonl_tail(SURICATA_LOG, limit=limit * 8)
        if entry.get("event_type") in interesting_types
    ]
    return [
        {
            "timestamp": entry.get("timestamp"),
            "kind": entry.get("event_type", "event"),
            "summary": summarize_suricata_entry(entry),
            "raw": entry,
        }
        for entry in records[-limit:]
    ]


def detector_status() -> dict[str, Any]:
    pid = read_pid(DETECTOR_PID)
    state = load_json_file(DETECTOR_STATE) or {}
    records = load_jsonl_all(DETECTOR_LOG)
    arp_count = sum(1 for entry in records if entry.get("event") == "arp_spoof_packet_seen")
    dns_count = sum(1 for entry in records if entry.get("event") == "dns_spoof_packet_seen")
    dhcp_count = sum(1 for entry in records if entry.get("event") in {"dhcp_offer_seen", "dhcp_ack_seen"})
    starvation_count = sum(1 for entry in records if entry.get("event") == "dhcp_starvation_packet_seen")
    recent = interesting_detector_entries(limit=1)
    return {
        "name": "Detector",
        "running": pid_running(pid),
        "pid": pid,
        "log_path": str(DETECTOR_LOG),
        "state_path": str(DETECTOR_STATE),
        "last_event": recent[-1] if recent else None,
        "counters": {
            "arp_spoof": arp_count,
            "dns_spoof": dns_count,
            "dhcp_spoof": dhcp_count,
            "dhcp_starvation": starvation_count,
        },
        "known_victim_ip": state.get("known_victim_ip"),
        "known_attacker_ip": state.get("known_attacker_ip"),
    }


def zeek_status() -> dict[str, Any]:
    pid = read_pid(ZEEK_PID)
    records = load_jsonl_all(ZEEK_LOG)
    counts = {"arp_spoof": 0, "dns_spoof": 0, "dhcp_spoof": 0, "dhcp_starvation": 0}
    for entry in records:
        note = entry.get("note")
        if note == "MITMLab::ARP_Spoof":
            counts["arp_spoof"] += 1
        elif note == "MITMLab::DNS_Spoof":
            counts["dns_spoof"] += 1
        elif note == "MITMLab::DHCP_Spoof":
            counts["dhcp_spoof"] += 1
        elif note == "MITMLab::DHCP_Starvation":
            counts["dhcp_starvation"] += 1
    recent = interesting_zeek_entries(limit=1)
    return {
        "name": "Zeek",
        "running": pid_running(pid),
        "pid": pid,
        "log_path": str(ZEEK_LOG),
        "last_event": recent[-1] if recent else None,
        "counters": counts,
    }


def suricata_status() -> dict[str, Any]:
    pid = read_pid(SURICATA_PID)
    attacker_mac = LAB_CONSTANTS.get("ATTACKER_MAC", "").lower()
    gateway_ip = LAB_CONSTANTS.get("GATEWAY_IP", "")
    records = load_jsonl_all(SURICATA_LOG, max_bytes=2 * 1024 * 1024)
    counts = {"arp_spoof": 0, "dns_spoof": 0, "dhcp_spoof": 0, "dhcp_starvation": 0}
    for entry in records:
        event_type = entry.get("event_type")
        if event_type == "alert":
            signature = entry.get("alert", {}).get("signature", "")
            if "DNS answer contains attacker IP" in signature:
                counts["dns_spoof"] += 1
            elif "rogue DHCP reply from attacker" in signature:
                counts["dhcp_spoof"] += 1
            elif "DHCP starvation" in signature:
                counts["dhcp_starvation"] += 1
        elif event_type == "arp":
            arp = entry.get("arp", {})
            if (
                str(arp.get("opcode", "")).lower() == "reply"
                and str(arp.get("src_mac", "")).lower() == attacker_mac
                and str(arp.get("src_ip", "")) == gateway_ip
            ):
                counts["arp_spoof"] += 1
    recent = interesting_suricata_entries(limit=1)
    return {
        "name": "Suricata",
        "running": pid_running(pid),
        "pid": pid,
        "log_path": str(SURICATA_LOG),
        "last_event": recent[-1] if recent else None,
        "counters": counts,
    }


def pretty_label(name: str) -> str:
    custom = {
        "arp-poison-no-forward": "ARP Poison",
        "arp-mitm-forward": "ARP MITM",
        "arp-mitm-dns": "ARP + DNS MITM",
        "dhcp-spoof": "DHCP Spoof",
        "dhcp-starvation": "DHCP Starvation",
        "dhcp-starvation-rogue-dhcp": "Starvation + Rogue DHCP",
        "visibility-arp-mitm-dns": "Visibility ARP + DNS",
        "visibility-dhcp-spoof": "Visibility DHCP",
        "mitigation-recovery": "Mitigation Recovery",
    }
    return custom.get(name, name.replace("-", " ").title())


def scenario_catalog() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in DEMO_SCENARIOS:
        definition = SCENARIOS.get(name)
        rows.append(
            {
                "name": name,
                "label": pretty_label(name),
                "group": definition.group if definition else "main",
                "featured": name in FEATURED_SCENARIOS,
                "attack_types": sorted((definition.attack_types if definition else [])),
            }
        )
    return rows


def newest_result_dir(scenario: str | None = None) -> Path | None:
    results_root = REPO_ROOT / "results"
    if not results_root.exists():
        return None
    candidates = [
        path
        for path in results_root.iterdir()
        if path.is_dir() and (scenario is None or path.name.endswith(f"-{scenario}"))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def latest_result_summary(result_dir: Path | None) -> dict[str, Any] | None:
    if result_dir is None:
        return None
    evaluation_path = result_dir / "evaluation.json"
    summary_path = result_dir / "evaluation-summary.txt"
    payload: dict[str, Any] = {
        "path": str(result_dir),
        "summary_path": str(summary_path) if summary_path.exists() else None,
    }
    if not evaluation_path.exists():
        return payload
    try:
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return payload
    payload.update(
        {
            "scenario": evaluation.get("scenario"),
            "ground_truth_attack_events": evaluation.get("ground_truth_attack_events"),
            "ground_truth_attack_types": evaluation.get("ground_truth_attack_types", {}),
            "ground_truth_arp_spoof_direction_counts": evaluation.get("ground_truth_arp_spoof_direction_counts", {}),
            "ground_truth_attack_duration_seconds": evaluation.get("ground_truth_attack_duration_seconds"),
            "detector_alert_events": evaluation.get("detector_alert_events"),
            "detector_attack_type_counts": evaluation.get("detector_attack_type_counts", {}),
            "zeek_alert_events": evaluation.get("zeek_alert_events"),
            "zeek_attack_type_counts": evaluation.get("zeek_attack_type_counts", {}),
            "suricata_alert_events": evaluation.get("suricata_alert_events"),
            "suricata_attack_type_counts": evaluation.get("suricata_attack_type_counts", {}),
        }
    )
    return payload


def extract_artifacts_path(log_path: Path) -> str | None:
    if not log_path.exists():
        return None
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    matches = re.findall(r"Artifacts:\s+(.+)", text)
    return matches[-1].strip() if matches else None


def read_runner_log(path: Path, limit: int = 80) -> list[str]:
    return read_last_lines(path, limit=limit, max_bytes=512 * 1024)


def run_shell_json(script_path: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["bash", str(script_path)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        return {
            "generated_at": utc_now(),
            "error": proc.stderr.strip() or proc.stdout.strip() or f"{script_path.name} failed",
        }
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "generated_at": utc_now(),
            "error": f"{script_path.name} returned invalid JSON",
            "raw": proc.stdout,
        }


def shell_command_string(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def normalize_owned_path(path: Path | None) -> None:
    if not ROOT_MODE or not DEMO_REAL_USER or path is None:
        return
    with suppress(Exception):
        if path.exists():
            group = DEMO_REAL_GROUP or DEMO_REAL_USER
            subprocess.run(
                ["chown", "-R", f"{DEMO_REAL_USER}:{group}", str(path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


@dataclass
class ManagedJob:
    kind: str
    label: str
    command: list[str]
    log_path: Path
    process: subprocess.Popen[str]
    started_at: str
    scenario: str | None = None
    duration: int | None = None
    completed_at: str | None = None
    exit_code: int | None = None
    artifacts_path: str | None = None

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def running(self) -> bool:
        return self.process.poll() is None


@dataclass
class JobManager:
    active: ManagedJob | None = None
    last_completed: ManagedJob | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def _refresh_locked(self) -> None:
        if self.active is None:
            return
        exit_code = self.active.process.poll()
        if exit_code is None:
            return
        self.active.exit_code = exit_code
        self.active.completed_at = utc_now()
        self.active.artifacts_path = extract_artifacts_path(self.active.log_path)
        normalize_owned_path(self.active.log_path)
        if self.active.artifacts_path:
            normalize_owned_path(Path(self.active.artifacts_path))
        self.last_completed = self.active
        self.active = None

    def refresh(self) -> None:
        with self.lock:
            self._refresh_locked()

    def state(self) -> dict[str, Any]:
        with self.lock:
            self._refresh_locked()
            active = self.active
            last = self.last_completed
            return {
                "active": self._job_payload(active),
                "last_completed": self._job_payload(last),
            }

    def _job_payload(self, job: ManagedJob | None) -> dict[str, Any] | None:
        if job is None:
            return None
        return {
            "kind": job.kind,
            "label": job.label,
            "scenario": job.scenario,
            "duration": job.duration,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "pid": job.pid,
            "running": job.running,
            "exit_code": job.exit_code,
            "log_path": str(job.log_path),
            "artifacts_path": job.artifacts_path,
        }

    def start(self, kind: str, label: str, command: list[str], scenario: str | None = None, duration: int | None = None) -> ManagedJob:
        ensure_generated_dirs()
        with self.lock:
            self._refresh_locked()
            if self.active and self.active.running:
                raise RuntimeError(f"{self.active.label} is already running")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
            log_path = JOB_LOG_DIR / f"{stamp}-{slug}.log"
            log_handle = log_path.open("w", encoding="utf-8")
            process = subprocess.Popen(
                command,
                cwd=REPO_ROOT,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            job = ManagedJob(
                kind=kind,
                label=label,
                command=command,
                log_path=log_path,
                process=process,
                started_at=utc_now(),
                scenario=scenario,
                duration=duration,
            )
            self.active = job
            return job


JOB_MANAGER = JobManager()


def build_status_payload() -> dict[str, Any]:
    JOB_MANAGER.refresh()
    lab = run_shell_json(REPO_ROOT / "shell/demo/status-json.sh")
    detector_state = load_json_file(DETECTOR_STATE) or {}
    hosts = lab.setdefault("hosts", {})
    if isinstance(hosts, dict):
        victim = hosts.setdefault("victim", {})
        attacker = hosts.setdefault("attacker", {})
        if isinstance(victim, dict) and not victim.get("ip"):
            victim["ip"] = detector_state.get("known_victim_ip") or ""
        if isinstance(attacker, dict) and not attacker.get("ip"):
            attacker["ip"] = detector_state.get("known_attacker_ip") or ""
    latest_result = newest_result_dir()
    latest_result_payload = latest_result_summary(latest_result)
    return {
        "generated_at": utc_now(),
        "lab": lab,
        "lab_facts": {
            "subnet": LAB_CONSTANTS.get("LAB_SUBNET", ""),
            "dns_server": LAB_CONSTANTS.get("DNS_SERVER", ""),
            "gateway_ip": LAB_CONSTANTS.get("GATEWAY_IP", ""),
            "gateway_mac": LAB_CONSTANTS.get("GATEWAY_LAB_MAC", ""),
            "victim_mac": LAB_CONSTANTS.get("VICTIM_MAC", ""),
            "attacker_mac": LAB_CONSTANTS.get("ATTACKER_MAC", ""),
            "detector_domains": LAB_CONSTANTS.get("DETECTOR_DOMAINS", ""),
        },
        "tools": {
            "detector": detector_status(),
            "zeek": zeek_status(),
            "suricata": suricata_status(),
        },
        "job": JOB_MANAGER.state(),
        "scenarios": scenario_catalog(),
        "latest_result": latest_result_payload,
        "hints": {
            "sudo": "Start the dashboard via `make demo-ui` so browser actions inherit the required privileges.",
            "wireshark": "The Wireshark button tries to open the desktop app on the mirrored switch port.",
        },
        "sensor_notes": {
            "arp_direction_note": bool(
                latest_result_payload
                and isinstance(latest_result_payload.get("ground_truth_arp_spoof_direction_counts"), dict)
                and latest_result_payload.get("ground_truth_arp_spoof_direction_counts")
            ),
        },
        "dashboard_root_mode": ROOT_MODE,
    }


def run_action(payload: dict[str, Any]) -> dict[str, Any]:
    action = payload.get("action")
    if not ROOT_MODE:
        return {"ok": False, "message": "Restart the dashboard via `make demo-ui` so actions can run with the required privileges."}
    if action == "start_lab":
        JOB_MANAGER.start(
            kind="lab",
            label="Prepare Lab",
            command=["bash", "./shell/lab/setup-lab.sh"],
        )
        return {"ok": True, "message": "Lab startup launched", "job": JOB_MANAGER.state()["active"]}

    if action == "start_monitoring":
        JOB_MANAGER.start(
            kind="monitoring",
            label="Ensure Monitoring",
            command=["bash", "./shell/demo/start-monitoring.sh"],
        )
        return {"ok": True, "message": "Monitoring bootstrap started", "job": JOB_MANAGER.state()["active"]}

    if action == "stop_monitoring":
        proc = subprocess.run(
            ["bash", "./shell/demo/stop-monitoring.sh"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "message": (proc.stdout or "").strip() or ("Monitoring stopped" if proc.returncode == 0 else "Failed to stop monitoring"),
        }

    if action == "open_wireshark":
        proc = subprocess.run(
            ["bash", "./shell/demo/open-wireshark.sh"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "message": (proc.stdout or "").strip() or ("Wireshark launched" if proc.returncode == 0 else "Failed to launch Wireshark"),
        }

    if action == "update_report":
        JOB_MANAGER.refresh()
        state = JOB_MANAGER.state()
        if state.get("active"):
            raise RuntimeError("Wait for the running scenario to finish before rebuilding the report.")
        output_dir = REPO_ROOT / "results" / "experiment-report"
        proc = subprocess.run(
            ["python3", "-m", "reporting.cli", "results", "--profile", "all", "--output-dir", str(output_dir)],
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONPATH": "./python"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            check=False,
        )
        if proc.returncode != 0:
            return {"ok": False, "message": (proc.stdout or "Report build failed").strip()}
        ensure_generated_dirs()
        REPORT_DOWNLOAD_ZIP.unlink(missing_ok=True)
        archive_base = REPORT_DOWNLOAD_ZIP.with_suffix("")
        shutil.make_archive(str(archive_base), "zip", root_dir=output_dir)
        normalize_owned_path(output_dir)
        normalize_owned_path(REPORT_DOWNLOAD_ZIP)
        return {
            "ok": True,
            "message": "Report updated.",
            "report_dir": str(output_dir),
            "download_url": "/api/download/experiment-report.zip",
        }

    if action == "run_scenario":
        scenario = str(payload.get("scenario") or "").strip()
        duration = clamp_duration(payload.get("duration"))
        visibility = clamp_visibility(payload.get("visibility"))
        workers = clamp_workers(payload.get("workers"))
        takeover_enabled = bool(payload.get("takeover_enabled", True))
        script_path = SCENARIO_SCRIPTS.get(scenario)
        if not script_path:
            return {"ok": False, "message": f"Unknown scenario: {scenario}"}
        label = pretty_label(scenario)
        env_parts = [
            "IPERF_ENABLE=0",
            "POST_ATTACK_SETTLE_SECONDS=0",
            "KEEP_DEBUG_ARTIFACTS=0",
            "PCAP_ENABLE=1",
            "GUEST_PCAP_ENABLE=0",
            "PCAP_SUMMARIES_ENABLE=0",
            "PCAP_RETENTION_POLICY=first-run-per-scenario",
            f"SENSOR_VISIBILITY_PERCENT={visibility}",
            f"DHCP_STARVATION_WORKERS={workers}",
            f"TAKEOVER_ENABLE={1 if takeover_enabled else 0}",
        ]
        script_args = [shlex.quote(str(script_path)), shlex.quote(str(duration))]
        if scenario.startswith("visibility-"):
            script_args.append(shlex.quote(str(visibility)))
        elif scenario == "dhcp-starvation-rogue-dhcp":
            script_args.append(shlex.quote(str(workers)))
            script_args.append(shlex.quote("1" if takeover_enabled else "0"))
        inner = " ".join(env_parts + script_args)
        JOB_MANAGER.start(
            kind="scenario",
            label=label,
            scenario=scenario,
            duration=duration,
            command=["bash", "-lc", inner],
        )
        return {"ok": True, "message": f"Started {label}", "job": JOB_MANAGER.state()["active"]}

    return {"ok": False, "message": f"Unsupported action: {action}"}


class DemoRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def _send_json(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/api/status":
            self._send_json(build_status_payload())
            return
        if parsed.path == "/api/download/experiment-report.zip":
            if not REPORT_DOWNLOAD_ZIP.exists():
                self._send_json({"ok": False, "message": "Build the report first."}, status=HTTPStatus.NOT_FOUND)
                return
            data = REPORT_DOWNLOAD_ZIP.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="experiment-report.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(data)
            return
        if parsed.path == "/api/download/latest-run.zip":
            state = JOB_MANAGER.state()
            last = state.get("last_completed") or {}
            run_path = Path(str(last.get("artifacts_path") or "")) if last.get("artifacts_path") else newest_result_dir()
            if not run_path or not run_path.exists():
                self._send_json({"ok": False, "message": "No completed run is available yet."}, status=HTTPStatus.NOT_FOUND)
                return
            resolved = run_path.resolve()
            results_root = (REPO_ROOT / "results").resolve()
            if results_root not in resolved.parents:
                self._send_json({"ok": False, "message": "Refusing to package a path outside results/."}, status=HTTPStatus.BAD_REQUEST)
                return
            ensure_generated_dirs()
            LATEST_RUN_DOWNLOAD_ZIP.unlink(missing_ok=True)
            archive_base = LATEST_RUN_DOWNLOAD_ZIP.with_suffix("")
            shutil.make_archive(str(archive_base), "zip", root_dir=resolved)
            normalize_owned_path(LATEST_RUN_DOWNLOAD_ZIP)
            data = LATEST_RUN_DOWNLOAD_ZIP.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{resolved.name}.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(data)
            return
        if parsed.path.startswith("/api/logs/"):
            source = parsed.path.rsplit("/", 1)[-1]
            params = parse_qs(parsed.query)
            limit = clamp_duration(params.get("limit", ["25"])[0]) if "limit" in params else 25
            if source == "detector":
                payload = {"entries": interesting_detector_entries(limit=limit), "path": str(DETECTOR_LOG)}
            elif source == "zeek":
                payload = {"entries": interesting_zeek_entries(limit=limit), "path": str(ZEEK_LOG)}
            elif source == "suricata":
                payload = {"entries": interesting_suricata_entries(limit=limit), "path": str(SURICATA_LOG)}
            elif source == "runner":
                state = JOB_MANAGER.state()
                job = state.get("active") or state.get("last_completed")
                log_path = Path(job["log_path"]) if job and job.get("log_path") else None
                payload = {
                    "entries": read_runner_log(log_path, limit=80) if log_path else [],
                    "path": str(log_path) if log_path else None,
                }
            else:
                self._send_json({"ok": False, "message": f"Unknown log source: {source}"}, status=HTTPStatus.NOT_FOUND)
                return
            self._send_json(payload)
            return
        return super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/action":
            self._send_json({"ok": False, "message": "Unknown endpoint"}, status=HTTPStatus.NOT_FOUND)
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"ok": False, "message": "Invalid JSON payload"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            result = run_action(payload)
        except RuntimeError as exc:
            self._send_json({"ok": False, "message": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except subprocess.TimeoutExpired:
            self._send_json({"ok": False, "message": "Action timed out"}, status=HTTPStatus.GATEWAY_TIMEOUT)
            return
        self._send_json(result, status=HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the MITM lab demo dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    ensure_generated_dirs()
    httpd = ThreadingHTTPServer((args.host, args.port), DemoRequestHandler)
    print(f"Demo dashboard listening on http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
