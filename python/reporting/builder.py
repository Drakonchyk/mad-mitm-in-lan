from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporting.dataset import build_rows, clear_plot_outputs, limit_rows_per_scenario, write_dataset
from reporting.markdown import write_markdown_summary
from reporting.plots import build_main_plots, build_supplementary_plots
from reporting.tables import build_table_a, build_table_b, build_table_c, build_table_s1

@dataclass(frozen=True)
class ReportBuildOptions:
    target: Path
    output_dir: Path
    include_warmups: bool = False
    use_cache: bool = True
    profile: str = "main"
    max_runs_per_scenario: int | None = None


class ExperimentReportBuilder:
    def __init__(self, options: ReportBuildOptions) -> None:
        self.options = options

    def load_rows(self) -> list[dict[str, Any]]:
        rows = build_rows(
            self.options.target,
            include_warmups=self.options.include_warmups,
            use_cache=self.options.use_cache,
            profile=self.options.profile,
        )
        return limit_rows_per_scenario(rows, self.options.max_runs_per_scenario)

    def build_plots(self, rows: list[dict[str, Any]]) -> tuple[dict[str, Path], list[str], str | None]:
        plot_error: str | None = None
        plots: dict[str, Path] = {}
        plot_notes: list[str] = []
        try:
            if self.options.profile == "supplementary":
                plots, plot_notes = build_supplementary_plots(rows, self.options.output_dir)
            else:
                plots, plot_notes = build_main_plots(rows, self.options.output_dir)
        except RuntimeError as exc:
            plot_error = str(exc)
        return plots, plot_notes, plot_error

    def build_tables(self, rows: list[dict[str, Any]]) -> dict[str, Path]:
        if self.options.profile == "supplementary":
            return {
                "table_s1_supplementary_summary": build_table_s1(rows, self.options.output_dir),
                "table_b_tool_summary": build_table_b(rows, self.options.output_dir),
            }
        return {
            "table_a_scenario_design": build_table_a(self.options.output_dir),
            "table_b_tool_summary": build_table_b(rows, self.options.output_dir),
            "table_c_recovery_summary": build_table_c(rows, self.options.output_dir),
        }

    def build(self) -> Path:
        rows = self.load_rows()
        if not rows:
            raise SystemExit(f"No evaluated runs found under {self.options.target} for profile={self.options.profile}")

        self.options.output_dir.mkdir(parents=True, exist_ok=True)
        write_dataset(rows, self.options.output_dir)
        clear_plot_outputs(self.options.output_dir)

        plots, plot_notes, plot_error = self.build_plots(rows)
        tables = self.build_tables(rows)
        write_markdown_summary(
            rows,
            plots,
            plot_notes,
            tables,
            self.options.output_dir,
            plot_error,
            profile=self.options.profile,
        )

        if plot_error:
            print(f"Wrote experiment dataset and tables to {self.options.output_dir} (plots skipped: {plot_error})")
        else:
            print(f"Wrote experiment dataset, figures, and tables to {self.options.output_dir}")
        return self.options.output_dir / "experiment-report.md"
