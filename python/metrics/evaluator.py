#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from metrics.aggregate import aggregate_runs, render_multi, render_single
from metrics.core import load_or_evaluate_single_run, write_evaluation_cache
from metrics.parsers import filter_run_dirs, find_run_dirs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate lab runs against ground truth, detector alerts, Zeek alerts, and Suricata alerts.")
    parser.add_argument("target", nargs="?", default="results", help="Run directory or results root")
    parser.add_argument("--glob", action="append", help="Optional glob pattern for run directory names, for example '20260416T20*'")
    parser.add_argument("--json-out", help="Optional path to write JSON output")
    parser.add_argument("--text-out", help="Optional path to write text output")
    parser.add_argument("--no-cache", action="store_true", help="Recompute evaluations even if cached evaluation.json files are valid")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    run_dirs = filter_run_dirs(find_run_dirs(target), args.glob)
    if not run_dirs:
        raise SystemExit(f"No run-meta.json files found under {target}")

    if len(run_dirs) == 1:
        evaluation = load_or_evaluate_single_run(run_dirs[0], use_cache=not args.no_cache)
        json_payload: dict[str, Any] = evaluation.as_dict()
        text_payload = render_single(evaluation)
    else:
        json_payload = aggregate_runs(run_dirs, use_cache=not args.no_cache)
        text_payload = render_multi(json_payload)

    print(text_payload)

    if args.json_out:
        if len(run_dirs) == 1 and Path(args.json_out).resolve() == (run_dirs[0] / "evaluation.json").resolve():
            write_evaluation_cache(run_dirs[0], evaluation)
        else:
            Path(args.json_out).write_text(json.dumps(json_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.text_out:
        Path(args.text_out).write_text(text_payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
