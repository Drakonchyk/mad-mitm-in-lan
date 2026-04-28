from __future__ import annotations

import argparse
from pathlib import Path

from reporting.db_report import build_db_report
from reporting.builder import ExperimentReportBuilder, ReportBuildOptions

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build one combined experiment report from the runs under a results directory.")
    parser.add_argument("target", nargs="?", default="results", help="Run directory or results root")
    parser.add_argument("--output-dir", default="results/experiment-report", help="Directory for CSV, JSON, plots, and markdown")
    parser.add_argument("--no-cache", action="store_true", help="Recompute per-run evaluations instead of reusing valid evaluation.json caches")
    parser.add_argument("--profile", choices=["main", "supplementary", "all"], default="all", help="Subset of scenarios to include")
    parser.add_argument("--max-runs-per-scenario", type=int, default=None, help="Keep at most this many measured runs per scenario, preferring the latest run ids")
    parser.add_argument("--source", choices=["auto", "db", "files"], default="auto", help="Build plots from SQLite results DB or retained run files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    db_path = target if target.suffix == ".sqlite" else target / "experiment-results.sqlite"
    if args.source == "db" or (args.source == "auto" and db_path.exists()):
        build_db_report(db_path, Path(args.output_dir))
        return 0
    options = ReportBuildOptions(
        target=target,
        output_dir=Path(args.output_dir),
        use_cache=not args.no_cache,
        profile=args.profile,
        max_runs_per_scenario=args.max_runs_per_scenario,
    )
    ExperimentReportBuilder(options).build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
