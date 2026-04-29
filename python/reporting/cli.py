from __future__ import annotations

import argparse
from pathlib import Path

from reporting.db_report import build_db_report

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build one combined experiment report from the runs under a results directory.")
    parser.add_argument("target", nargs="?", default="results", help="Run directory or results root")
    parser.add_argument("--output-dir", default="results/experiment-report", help="Directory for generated CSVs, figures, and markdown")
    parser.add_argument("--profile", choices=["all"], default="all", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    db_path = target if target.suffix == ".sqlite" else target / "experiment-results.sqlite"
    if not db_path.exists():
        raise SystemExit(f"Result database does not exist: {db_path}. Run make results-db or collect experiments first.")
    build_db_report(db_path, Path(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
