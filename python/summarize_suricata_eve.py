#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def main() -> int:
    eve_path = Path(sys.argv[1])
    records = load_jsonl(eve_path)
    event_counts = Counter(record.get("event_type", "unknown") for record in records)
    alerts = [record for record in records if record.get("event_type") == "alert"]
    alert_counts = Counter(
        record.get("alert", {}).get("signature", "unknown")
        for record in alerts
    )

    lines = [
        f"eve_path={eve_path}",
        "event_type_counts=" + json.dumps(dict(sorted(event_counts.items())), sort_keys=True),
        f"alert_count={len(alerts)}",
        f"unique_signatures={len(alert_counts)}",
        "alert_signature_counts=" + json.dumps(dict(sorted(alert_counts.items())), sort_keys=True),
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

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
