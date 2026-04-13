#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


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


def main() -> int:
    eve_path = Path(sys.argv[1])
    run_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else eve_path.parent.parent

    meta = json.loads((run_dir / "run-meta.json").read_text(encoding="utf-8"))
    domains = set(meta.get("domains", "").split())
    attacker_ip = meta.get("attacker_ip")
    records = load_jsonl(eve_path)

    event_counts = Counter(record.get("event_type", "unknown") for record in records)
    alerts = [record for record in records if record.get("event_type") == "alert"]
    dns_records = [record for record in records if record.get("event_type") == "dns"]

    suspicious_dns: list[dict] = []
    for record in dns_records:
        dns = record.get("dns", {})
        rrname = dns.get("rrname") or dns.get("query") or dns.get("rdata")
        answers = dns.get("grouped", {}).get("A", [])
        if isinstance(answers, str):
            answers = [answers]
        if attacker_ip and any(answer == attacker_ip for answer in answers):
            suspicious_dns.append(
                {
                    "timestamp": record.get("timestamp"),
                    "rrname": rrname,
                    "answers": answers,
                    "src_ip": record.get("src_ip"),
                    "dest_ip": record.get("dest_ip"),
                }
            )

    lines = [
        f"eve_path={eve_path}",
        "event_type_counts=" + json.dumps(dict(sorted(event_counts.items())), sort_keys=True),
        f"alert_count={len(alerts)}",
        f"dns_event_count={len(dns_records)}",
        f"suspicious_dns_event_count={len(suspicious_dns)}",
    ]

    if alerts:
        lines.append("alerts=")
        for record in alerts[:20]:
            alert = record.get("alert", {})
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity"),
                        "src_ip": record.get("src_ip"),
                        "dest_ip": record.get("dest_ip"),
                    },
                    sort_keys=True,
                )
            )

    if suspicious_dns:
        lines.append("suspicious_dns=")
        for record in suspicious_dns[:20]:
            lines.append(json.dumps(record, sort_keys=True))

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
