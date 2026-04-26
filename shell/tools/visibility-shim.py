#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import sendp, sniff


RUNNING = True


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stop(_signum, _frame) -> None:
    global RUNNING
    RUNNING = False


def parse_visibility(value: str) -> int:
    percent = int(value)
    if percent < 0 or percent > 100:
        raise argparse.ArgumentTypeError("visibility must be in [0, 100]")
    return percent


def keep_every_for(percent: int) -> int | None:
    if percent <= 0:
        return None
    return max(int(round(100.0 / percent)), 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Forward a sampled live packet stream to a virtual sensor interface.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--visibility", type=parse_visibility, required=True)
    parser.add_argument("--stats", type=Path, required=True)
    parser.add_argument("--bpf", default="arp or (udp and port 53) or icmp or (udp and (port 67 or port 68))")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    keep_every = keep_every_for(args.visibility)
    seen = 0
    forwarded = 0
    started_at = now()
    last_flush = 0.0

    args.stats.parent.mkdir(parents=True, exist_ok=True)

    def flush() -> None:
        payload = {
            "ts": now(),
            "started_at": started_at,
            "input_interface": args.input,
            "output_interface": args.output,
            "visibility_percent": args.visibility,
            "packets_seen": seen,
            "packets_forwarded": forwarded,
            "packets_dropped": max(seen - forwarded, 0),
        }
        args.stats.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def handle(packet) -> None:
        nonlocal seen, forwarded, last_flush
        seen += 1
        if keep_every is not None and (seen - 1) % keep_every == 0:
            sendp(packet, iface=args.output, verbose=False)
            forwarded += 1
        current = time.monotonic()
        if current - last_flush >= 2:
            flush()
            last_flush = current

    while RUNNING:
        sniff(iface=args.input, filter=args.bpf, store=False, timeout=1, prn=handle)

    flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

