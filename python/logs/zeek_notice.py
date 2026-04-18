#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
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


def iso_from_zeek_ts(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            return value
    return None


def main() -> int:
    notice_path = Path(sys.argv[1])
    records = load_jsonl(notice_path)
    note_counts = Counter(record.get("note", "unknown") for record in records if record.get("note"))

    lines = [
        f"notice_path={notice_path}",
        f"notice_count={len(records)}",
        f"unique_notes={len(note_counts)}",
        "note_counts=" + json.dumps(dict(sorted(note_counts.items())), sort_keys=True),
    ]

    if records:
        lines.append("notices=")
        for record in records[:20]:
            lines.append(
                json.dumps(
                    {
                        "ts": iso_from_zeek_ts(record.get("ts")),
                        "note": record.get("note"),
                        "msg": record.get("msg"),
                        "sub": record.get("sub"),
                        "src": record.get("src"),
                        "dst": record.get("dst"),
                    },
                    sort_keys=True,
                )
            )

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
