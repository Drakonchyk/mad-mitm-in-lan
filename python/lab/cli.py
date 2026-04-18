#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

from lab.templates import LabTemplateRenderer


def json_string_array_from_words(text: str) -> None:
    print(json.dumps([item for item in text.split() if item]))


def timestamp_at_offset(base_ts: str, offset_seconds: float) -> None:
    base = datetime.fromisoformat(base_ts.replace("Z", "+00:00"))
    ts = (base + timedelta(seconds=offset_seconds)).astimezone(timezone.utc).isoformat()
    print(json.dumps(ts))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shared experiment helpers for shell orchestration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_detector_parser = subparsers.add_parser("render-detector")
    render_detector_parser.add_argument("repo_root")
    render_detector_parser.add_argument("output_path")

    render_zeek_parser = subparsers.add_parser("render-zeek-policy")
    render_zeek_parser.add_argument("repo_root")
    render_zeek_parser.add_argument("output_path")

    json_array_parser = subparsers.add_parser("json-string-array")
    json_array_parser.add_argument("text")

    timestamp_parser = subparsers.add_parser("timestamp-at-offset")
    timestamp_parser.add_argument("base_ts")
    timestamp_parser.add_argument("offset_seconds", type=float)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "render-detector":
        LabTemplateRenderer.from_repo_root(Path(args.repo_root)).write_detector(Path(args.output_path))
        return 0
    if args.command == "render-zeek-policy":
        LabTemplateRenderer.from_repo_root(Path(args.repo_root)).write_zeek_policy(Path(args.output_path))
        return 0
    if args.command == "json-string-array":
        json_string_array_from_words(args.text)
        return 0
    if args.command == "timestamp-at-offset":
        timestamp_at_offset(args.base_ts, args.offset_seconds)
        return 0
    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
