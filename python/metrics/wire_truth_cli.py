#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from metrics.parsers import (
    build_wire_truth_summary,
    find_attack_stdout_files,
    load_json,
    normalize_ground_truth_event,
    parse_concatenated_json,
    wire_truth_summary_path,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build compact switch-truth summaries from run pcaps.")
    parser.add_argument("run_dir", help="Run directory under results/")
    parser.add_argument("--out", help="Optional output path; defaults to pcap/wire-truth.json inside the run")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir)
    meta = load_json(run_dir / "run-meta.json")

    attack_records = []
    for path in find_attack_stdout_files(run_dir):
        attack_records.extend(normalize_ground_truth_event(payload) for payload in parse_concatenated_json(path))

    payload = build_wire_truth_summary(run_dir, meta, attack_records)
    if not payload:
        return 0

    out_path = Path(args.out) if args.out else wire_truth_summary_path(run_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
