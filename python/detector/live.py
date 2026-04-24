#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, UDP, sniff

GATEWAY_IP = "__GATEWAY_IP__"
DNS_SERVER = "__DNS_SERVER__"
ATTACKER_IP = "__ATTACKER_IP__"
VICTIM_IP = "__VICTIM_IP__"
LAB_SUBNET = ip_network("__LAB_SUBNET__", strict=False)
DOMAINS = [__PYTHON_DOMAIN_LIST__]
INTERFACE = os.getenv("MITM_LAB_INTERFACE", "vnic0")
LOG_PATH = Path(os.getenv("MITM_LAB_LOG_PATH", "/var/log/mitm-lab-detector.jsonl"))
STATE_PATH = Path(os.getenv("MITM_LAB_STATE_PATH", "/var/lib/mitm-lab-detector/state.json"))
EXPECTED_GATEWAY_MAC = os.getenv("MITM_LAB_EXPECTED_GATEWAY_MAC")
EXPECTED_DHCP_SERVER = os.getenv("MITM_LAB_EXPECTED_DHCP_SERVER", GATEWAY_IP)
EXPECTED_DHCP_SERVER_MAC_RAW = os.getenv("MITM_LAB_EXPECTED_DHCP_SERVER_MAC")
KNOWN_VICTIM_MAC_RAW = os.getenv("MITM_LAB_VICTIM_MAC")
KNOWN_ATTACKER_MAC_RAW = os.getenv("MITM_LAB_ATTACKER_MAC")
SNIFF_TIMEOUT_SECONDS = 1
SNIFF_FILTER = "arp or (udp and port 53) or icmp or (udp and (port 67 or port 68))"
MAC_RE = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def getenv_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.lower()


def normalize_ip_answers(answers: list[str]) -> list[str]:
    return sorted({answer.strip() for answer in answers if answer and answer.strip()})


def normalize_domain(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".").lower()
    return value.rstrip(".").lower()


def getenv_ip(name: str, default: str) -> str | None:
    value = os.getenv(name, default).strip()
    if not value:
        return None
    return value


MONITORED_DOMAINS = {normalize_domain(item) for item in DOMAINS}
HEARTBEAT_SECONDS = getenv_float("MITM_LAB_HEARTBEAT_SECONDS", 10.0)
PACKET_SAMPLE_RATE = max(0.0, min(1.0, getenv_float("MITM_LAB_PACKET_SAMPLE_RATE", 1.0)))
EXPECTED_DHCP_SERVER_MAC = normalize_mac(EXPECTED_DHCP_SERVER_MAC_RAW)
KNOWN_VICTIM_MAC = normalize_mac(KNOWN_VICTIM_MAC_RAW)
KNOWN_ATTACKER_MAC = normalize_mac(KNOWN_ATTACKER_MAC_RAW)
INITIAL_VICTIM_IP = getenv_ip("MITM_LAB_VICTIM_IP", VICTIM_IP)
INITIAL_ATTACKER_IP = getenv_ip("MITM_LAB_ATTACKER_IP", ATTACKER_IP)


def get_gateway_mac_from_neighbor_cache() -> str | None:
    result = run(["ip", "neigh", "show", GATEWAY_IP])
    match = MAC_RE.search(result.stdout)
    return normalize_mac(match.group(1)) if match else None


def extract_dns_a_answers(packet) -> list[str]:
    if not packet.haslayer(DNS) or packet[DNS].ancount <= 0:
        return []

    answers: list[str] = []
    record = packet[DNS].an
    while isinstance(record, DNSRR):
        if getattr(record, "type", None) == 1:
            answers.append(str(record.rdata))
        payload = getattr(record, "payload", None)
        if not isinstance(payload, DNSRR):
            break
        record = payload
    return normalize_ip_answers(answers)


def is_lab_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value) in LAB_SUBNET
    except ValueError:
        return False


def normalize_dhcp_option_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def dhcp_options(packet) -> dict[str, str]:
    if not packet.haslayer(DHCP):
        return {}
    options: dict[str, str] = {}
    for item in getattr(packet[DHCP], "options", []):
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        key, value = item
        normalized = normalize_dhcp_option_value(value)
        if normalized is not None:
            options[str(key)] = normalized
    return options


def dhcp_message_type(packet) -> str | None:
    value = dhcp_options(packet).get("message-type")
    if value is None:
        return None
    if value.isdigit():
        mapping = {
            "1": "discover",
            "2": "offer",
            "3": "request",
            "4": "decline",
            "5": "ack",
            "6": "nak",
            "7": "release",
            "8": "inform",
        }
        return mapping.get(value, value)
    return value.lower()


def dhcp_server_identifier(packet) -> str | None:
    options = dhcp_options(packet)
    server_id = options.get("server_id")
    if server_id and server_id != "0.0.0.0":
        return server_id
    if packet.haslayer(IP):
        source_ip = str(packet[IP].src)
        if source_ip != "0.0.0.0":
            return source_ip
    return None


def dhcp_client_identity(packet) -> dict[str, str | None]:
    assigned_ip = None
    client_ip = None
    client_mac = None
    if packet.haslayer(BOOTP):
        assigned_ip = str(packet[BOOTP].yiaddr or "") or None
        client_ip = str(packet[BOOTP].ciaddr or "") or None
        chaddr = getattr(packet[BOOTP], "chaddr", b"")
        if isinstance(chaddr, bytes) and len(chaddr) >= 6:
            client_mac = ":".join(f"{byte:02x}" for byte in chaddr[:6])
    return {
        "assigned_ip": assigned_ip,
        "client_ip": client_ip,
        "client_mac": normalize_mac(client_mac),
    }


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {"domain_baselines": {}, "seen_gateway_macs": [], "seen_dhcp_servers": []}
    try:
        payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"domain_baselines": {}, "seen_gateway_macs": [], "seen_dhcp_servers": []}

    baselines = {
        normalize_domain(domain): normalize_ip_answers(answers)
        for domain, answers in payload.get("domain_baselines", {}).items()
        if isinstance(answers, list)
    }
    return {
        "expected_gateway_mac": normalize_mac(payload.get("expected_gateway_mac")),
        "domain_baselines": baselines,
        "seen_gateway_macs": [
            normalize_mac(value) for value in payload.get("seen_gateway_macs", []) if value
        ],
        "known_victim_ip": payload.get("known_victim_ip"),
        "known_attacker_ip": payload.get("known_attacker_ip"),
        "dhcp_bindings": {
            normalize_mac(mac): str(ip)
            for mac, ip in payload.get("dhcp_bindings", {}).items()
            if normalize_mac(mac) and isinstance(ip, str) and is_lab_ip(ip)
        },
        "seen_dhcp_servers": sorted(
            {
                str(value)
                for value in payload.get("seen_dhcp_servers", [])
                if isinstance(value, str) and is_lab_ip(value)
            }
        ),
    }


def save_state(state) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "expected_gateway_mac": state.expected_gateway_mac,
        "domain_baselines": state.domain_baselines,
        "seen_gateway_macs": sorted(state.seen_gateway_macs),
        "known_victim_ip": state.known_victim_ip,
        "known_attacker_ip": state.known_attacker_ip,
        "dhcp_bindings": dict(sorted(state.dhcp_bindings.items())),
        "seen_dhcp_servers": sorted(state.seen_dhcp_servers),
    }
    STATE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def log_event(event_type: str, **payload) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": now(), "event": event_type, **payload}
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


@dataclass
class DetectorState:
    expected_gateway_mac: str | None
    domain_baselines: dict[str, list[str]]
    seen_gateway_macs: set[str] = field(default_factory=set)
    known_victim_ip: str | None = None
    known_attacker_ip: str | None = None
    dhcp_bindings: dict[str, str] = field(default_factory=dict)
    seen_dhcp_servers: set[str] = field(default_factory=set)
    gateway_mismatch_active: bool = False
    last_mismatch_gateway_mac: str | None = None
    multi_gateway_active: bool = False
    last_reported_gateway_macs: list[str] = field(default_factory=list)
    domain_mismatch_active: dict[str, bool] = field(default_factory=dict)
    last_domain_mismatch_answers: dict[str, list[str]] = field(default_factory=dict)
    rogue_dhcp_active: bool = False
    last_rogue_dhcp_server: str | None = None
    icmp_redirect_packets_seen: int = 0
    arp_spoof_packets_seen: int = 0
    dns_spoof_packets_seen: int = 0
    dhcp_offer_packets_seen: int = 0
    dhcp_ack_packets_seen: int = 0
    rogue_dhcp_packets_seen: int = 0
    packet_sequence: int = 0
    dirty: bool = False


def build_initial_state() -> DetectorState:
    loaded = load_state()
    expected_gateway_mac = normalize_mac(EXPECTED_GATEWAY_MAC) or loaded.get("expected_gateway_mac") or get_gateway_mac_from_neighbor_cache()
    seen_gateway_macs = {
        mac for mac in loaded.get("seen_gateway_macs", []) if mac
    }
    if expected_gateway_mac:
        seen_gateway_macs.add(expected_gateway_mac)

    state = DetectorState(
        expected_gateway_mac=expected_gateway_mac,
        domain_baselines=dict(loaded.get("domain_baselines", {})),
        seen_gateway_macs=seen_gateway_macs,
        known_victim_ip=loaded.get("known_victim_ip") or INITIAL_VICTIM_IP,
        known_attacker_ip=loaded.get("known_attacker_ip") or INITIAL_ATTACKER_IP,
        dhcp_bindings=dict(loaded.get("dhcp_bindings", {})),
        seen_dhcp_servers={value for value in loaded.get("seen_dhcp_servers", []) if is_lab_ip(value)},
        domain_mismatch_active={domain: False for domain in MONITORED_DOMAINS},
    )
    return state


def ensure_gateway_baseline(state: DetectorState) -> None:
    if state.expected_gateway_mac:
        log_event("gateway_baseline_set", expected_gateway_mac=state.expected_gateway_mac)
        state.dirty = True


def handle_gateway_arp(packet, state: DetectorState) -> None:
    if not packet.haslayer(ARP):
        return
    if int(packet[ARP].op) != 2:
        return
    if str(packet[ARP].psrc) != GATEWAY_IP:
        return

    current_mac = normalize_mac(packet[ARP].hwsrc)
    if not current_mac:
        return

    if not state.expected_gateway_mac:
        state.expected_gateway_mac = current_mac
        log_event("gateway_baseline_set", expected_gateway_mac=state.expected_gateway_mac)
        state.dirty = True

    state.seen_gateway_macs.add(current_mac)

    if state.expected_gateway_mac and current_mac != state.expected_gateway_mac:
        state.arp_spoof_packets_seen += 1
        log_event(
            "arp_spoof_packet_seen",
            expected_gateway_mac=state.expected_gateway_mac,
            current_gateway_mac=current_mac,
            claimed_gateway_ip=GATEWAY_IP,
        )
        if (not state.gateway_mismatch_active) or current_mac != state.last_mismatch_gateway_mac:
            log_event(
                "gateway_mac_changed",
                expected_gateway_mac=state.expected_gateway_mac,
                current_gateway_mac=current_mac,
            )
        state.gateway_mismatch_active = True
        state.last_mismatch_gateway_mac = current_mac
    elif state.gateway_mismatch_active:
        log_event(
            "gateway_mac_restored",
            expected_gateway_mac=state.expected_gateway_mac,
            current_gateway_mac=current_mac,
        )
        state.gateway_mismatch_active = False
        state.last_mismatch_gateway_mac = None

    current_gateway_macs = sorted(state.seen_gateway_macs)
    multiple_gateway_macs = len(current_gateway_macs) > 1
    if multiple_gateway_macs:
        if (not state.multi_gateway_active) or current_gateway_macs != state.last_reported_gateway_macs:
            log_event("multiple_gateway_macs_seen", gateway_macs=current_gateway_macs)
            state.last_reported_gateway_macs = list(current_gateway_macs)
        state.multi_gateway_active = True
    elif state.multi_gateway_active:
        log_event("single_gateway_mac_restored", gateway_macs=current_gateway_macs)
        state.last_reported_gateway_macs = list(current_gateway_macs)
        state.multi_gateway_active = False

    state.dirty = True


def handle_icmp_redirect(packet, state: DetectorState) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
        return
    if packet[ICMP].type != 5:
        return
    if state.known_victim_ip and packet[IP].dst != state.known_victim_ip:
        return
    if packet[IP].src == GATEWAY_IP:
        return

    state.icmp_redirect_packets_seen += 1
    log_event(
        "icmp_redirect_packet_seen",
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        redirect_gateway=getattr(packet[ICMP], "gw", None),
        count=state.icmp_redirect_packets_seen,
    )
    log_event(
        "icmp_redirects_seen",
        current_count=state.icmp_redirect_packets_seen,
        delta=1,
        previous_count=state.icmp_redirect_packets_seen - 1,
    )
    state.dirty = True


def handle_dns_response(packet, state: DetectorState) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return
    if packet[DNS].qr != 1:
        return
    if str(packet[IP].src) != DNS_SERVER:
        return
    if state.known_victim_ip and str(packet[IP].dst) != state.known_victim_ip:
        return

    domain = normalize_domain(packet[DNSQR].qname)
    if domain not in MONITORED_DOMAINS:
        return

    answers = extract_dns_a_answers(packet)
    if not answers:
        return

    if domain not in state.domain_baselines and (not state.known_attacker_ip or state.known_attacker_ip not in answers):
        state.domain_baselines[domain] = answers
        log_event("domain_baseline_set", domain=domain, answers=answers)
        state.dirty = True
        return

    baseline = state.domain_baselines.get(domain)
    suspicious = (state.known_attacker_ip in answers if state.known_attacker_ip else False) or (
        baseline is not None and answers != baseline
    )
    if suspicious:
        state.dns_spoof_packets_seen += 1
        log_event(
            "dns_spoof_packet_seen",
            domain=domain,
            answers=answers,
            baseline=baseline,
            count=state.dns_spoof_packets_seen,
        )
        if (
            not state.domain_mismatch_active.get(domain, False)
            or answers != state.last_domain_mismatch_answers.get(domain)
        ):
            log_event(
                "domain_resolution_changed",
                domain=domain,
                baseline=baseline,
                current=answers,
            )
            state.last_domain_mismatch_answers[domain] = list(answers)
        state.domain_mismatch_active[domain] = True
        state.dirty = True
        return

    if state.domain_mismatch_active.get(domain, False):
        log_event(
            "domain_resolution_restored",
            domain=domain,
            baseline=baseline,
            current=answers,
        )
        state.domain_mismatch_active[domain] = False
        state.last_domain_mismatch_answers.pop(domain, None)
        state.dirty = True


def handle_dhcp(packet, state: DetectorState) -> None:
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP) and packet.haslayer(UDP)):
        return

    message_type = dhcp_message_type(packet)
    if message_type not in {"offer", "ack"}:
        return

    server_ip = dhcp_server_identifier(packet)
    client = dhcp_client_identity(packet)
    assigned_ip = client["assigned_ip"]
    client_ip = client["client_ip"]
    client_mac = client["client_mac"]
    server_mac = normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else None

    if server_ip and is_lab_ip(server_ip):
        state.seen_dhcp_servers.add(server_ip)

    event_name = "dhcp_offer_seen" if message_type == "offer" else "dhcp_ack_seen"
    if message_type == "offer":
        state.dhcp_offer_packets_seen += 1
        count = state.dhcp_offer_packets_seen
    else:
        state.dhcp_ack_packets_seen += 1
        count = state.dhcp_ack_packets_seen

    log_event(
        event_name,
        dhcp_server=server_ip,
        dhcp_server_mac=server_mac,
        expected_dhcp_server=EXPECTED_DHCP_SERVER,
        expected_dhcp_server_mac=EXPECTED_DHCP_SERVER_MAC,
        client_ip=client_ip,
        assigned_ip=assigned_ip,
        client_mac=client_mac,
        count=count,
    )

    trusted_server = (
        bool(server_ip)
        and server_ip == EXPECTED_DHCP_SERVER
        and (not EXPECTED_DHCP_SERVER_MAC or server_mac == EXPECTED_DHCP_SERVER_MAC)
    )
    suspicious = (
        (bool(server_ip) and server_ip != EXPECTED_DHCP_SERVER and is_lab_ip(server_ip))
        or (bool(server_mac) and EXPECTED_DHCP_SERVER_MAC is not None and server_mac != EXPECTED_DHCP_SERVER_MAC and is_lab_ip(server_ip))
    )
    if suspicious:
        state.rogue_dhcp_packets_seen += 1
        log_event(
            "rogue_dhcp_server_seen",
            dhcp_server=server_ip,
            dhcp_server_mac=server_mac,
            expected_dhcp_server=EXPECTED_DHCP_SERVER,
            expected_dhcp_server_mac=EXPECTED_DHCP_SERVER_MAC,
            client_ip=client_ip,
            assigned_ip=assigned_ip,
            client_mac=client_mac,
            count=state.rogue_dhcp_packets_seen,
        )
        state.rogue_dhcp_active = True
        state.last_rogue_dhcp_server = server_ip or server_mac
    elif state.rogue_dhcp_active and trusted_server:
        log_event(
            "rogue_dhcp_server_cleared",
            dhcp_server=server_ip,
            dhcp_server_mac=server_mac,
            expected_dhcp_server=EXPECTED_DHCP_SERVER,
            expected_dhcp_server_mac=EXPECTED_DHCP_SERVER_MAC,
            last_rogue_dhcp_server=state.last_rogue_dhcp_server,
        )
        state.rogue_dhcp_active = False
        state.last_rogue_dhcp_server = None

    if trusted_server and client_mac and assigned_ip and is_lab_ip(assigned_ip):
        previous_ip = state.dhcp_bindings.get(client_mac)
        if previous_ip != assigned_ip:
            log_event(
                "dhcp_binding_updated",
                client_mac=client_mac,
                previous_ip=previous_ip,
                current_ip=assigned_ip,
                dhcp_server=server_ip,
                dhcp_server_mac=server_mac,
            )
        conflicting_mac = next(
            (mac for mac, ip in state.dhcp_bindings.items() if mac != client_mac and ip == assigned_ip),
            None,
        )
        if conflicting_mac:
            log_event(
                "dhcp_binding_conflict_seen",
                assigned_ip=assigned_ip,
                current_client_mac=client_mac,
                conflicting_client_mac=conflicting_mac,
                dhcp_server=server_ip,
                dhcp_server_mac=server_mac,
            )
        state.dhcp_bindings[client_mac] = assigned_ip
        if KNOWN_VICTIM_MAC and client_mac == KNOWN_VICTIM_MAC:
            if state.known_victim_ip != assigned_ip:
                log_event(
                    "victim_ip_updated",
                    previous_ip=state.known_victim_ip,
                    current_ip=assigned_ip,
                    client_mac=client_mac,
                )
            state.known_victim_ip = assigned_ip
        if KNOWN_ATTACKER_MAC and client_mac == KNOWN_ATTACKER_MAC:
            if state.known_attacker_ip != assigned_ip:
                log_event(
                    "attacker_ip_updated",
                    previous_ip=state.known_attacker_ip,
                    current_ip=assigned_ip,
                    client_mac=client_mac,
                )
            state.known_attacker_ip = assigned_ip

    state.dirty = True


def log_heartbeat(state: DetectorState) -> None:
    log_event(
        "heartbeat",
        expected_gateway_mac=state.expected_gateway_mac,
        expected_dhcp_server=EXPECTED_DHCP_SERVER,
        expected_dhcp_server_mac=EXPECTED_DHCP_SERVER_MAC,
        known_victim_ip=state.known_victim_ip,
        known_attacker_ip=state.known_attacker_ip,
        gateway_mismatch_active=state.gateway_mismatch_active,
        multi_gateway_active=state.multi_gateway_active,
        rogue_dhcp_active=state.rogue_dhcp_active,
        seen_gateway_macs=sorted(state.seen_gateway_macs),
        dhcp_bindings=dict(sorted(state.dhcp_bindings.items())),
        seen_dhcp_servers=sorted(state.seen_dhcp_servers),
        arp_spoof_packets_seen=state.arp_spoof_packets_seen,
        icmp_redirect_packets_seen=state.icmp_redirect_packets_seen,
        dns_spoof_packets_seen=state.dns_spoof_packets_seen,
        dhcp_offer_packets_seen=state.dhcp_offer_packets_seen,
        dhcp_ack_packets_seen=state.dhcp_ack_packets_seen,
        rogue_dhcp_packets_seen=state.rogue_dhcp_packets_seen,
        packet_sample_rate=PACKET_SAMPLE_RATE,
        domain_mismatch_active={
            domain: state.domain_mismatch_active.get(domain, False)
            for domain in sorted(state.domain_mismatch_active)
        },
    )


def should_process_packet(state: DetectorState) -> bool:
    state.packet_sequence += 1
    if PACKET_SAMPLE_RATE >= 1.0:
        return True
    if PACKET_SAMPLE_RATE <= 0.0:
        return False

    keep_every = max(int(round(1.0 / PACKET_SAMPLE_RATE)), 1)
    return state.packet_sequence % keep_every == 1


def process_packet(packet, state: DetectorState) -> None:
    if not should_process_packet(state):
        return
    handle_gateway_arp(packet, state)
    handle_icmp_redirect(packet, state)
    handle_dns_response(packet, state)
    handle_dhcp(packet, state)


def main() -> None:
    state = build_initial_state()
    ensure_gateway_baseline(state)
    save_state(state)

    log_event(
        "detector_started",
        interface=INTERFACE,
        sniff_filter=SNIFF_FILTER,
        heartbeat_seconds=HEARTBEAT_SECONDS,
        packet_sample_rate=PACKET_SAMPLE_RATE,
        gateway_ip=GATEWAY_IP,
        dns_server=DNS_SERVER,
        expected_dhcp_server=EXPECTED_DHCP_SERVER,
        attacker_ip=state.known_attacker_ip,
        victim_ip=state.known_victim_ip,
        attacker_mac=KNOWN_ATTACKER_MAC,
        victim_mac=KNOWN_VICTIM_MAC,
        lab_subnet=str(LAB_SUBNET),
        domains=sorted(MONITORED_DOMAINS),
        expected_gateway_mac=state.expected_gateway_mac,
        expected_dhcp_server_mac=EXPECTED_DHCP_SERVER_MAC,
        known_victim_ip=state.known_victim_ip,
        known_attacker_ip=state.known_attacker_ip,
        domain_baselines=state.domain_baselines,
    )

    next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS

    while True:
        sniff(
            iface=INTERFACE,
            filter=SNIFF_FILTER,
            store=False,
            timeout=SNIFF_TIMEOUT_SECONDS,
            prn=lambda packet: process_packet(packet, state),
        )

        if state.dirty:
            save_state(state)
            state.dirty = False

        if time.monotonic() >= next_heartbeat:
            log_heartbeat(state)
            save_state(state)
            next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS


if __name__ == "__main__":
    main()
