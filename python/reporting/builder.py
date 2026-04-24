from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporting.dataset import build_rows, clear_report_outputs, limit_rows_per_scenario, write_dataset
from reporting.markdown import write_markdown_summary
from reporting.plots import build_report_plots
from reporting.tables import (
    build_table_arp_replies,
    build_table_capture_overview,
    build_table_control_plane_noise,
    build_table_dns_answers,
    build_table_icmp_redirects,
    build_table_noisiest_detector_runs,
    build_table_operational_summary,
    build_table_probe_window_domain_observations,
    build_table_representative_context,
    build_table_representative_first_alerts,
    build_table_scenario_summary,
    build_table_timing_summary,
    build_table_top_conversations,
    build_table_tool_by_scenario,
    build_table_tool_overall,
    build_table_wire_truth_summary,
)


@dataclass(frozen=True)
class ReportBuildOptions:
    target: Path
    output_dir: Path
    include_warmups: bool = False
    use_cache: bool = True
    profile: str = "all"
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
            plots, plot_notes = build_report_plots(rows, self.options.output_dir)
        except RuntimeError as exc:
            plot_error = str(exc)
        return plots, plot_notes, plot_error

    def build_tables(self, rows: list[dict[str, Any]]) -> dict[str, Path]:
        builders = [
            ("Results Overview / Scenario Summary", build_table_scenario_summary),
            ("Detection And Timing / Timing Summary", build_table_timing_summary),
            ("Operational Impact / Operational Summary", build_table_operational_summary),
            ("Additional Summary / Tool Overall", build_table_tool_overall),
            ("Additional Summary / Tool By Scenario", build_table_tool_by_scenario),
            ("Additional Summary / Wire-Truth Summary", build_table_wire_truth_summary),
            ("Additional Summary / Control-Plane Noise", build_table_control_plane_noise),
            ("Representative Run / Context", build_table_representative_context),
            ("Representative Run / First Alerts", build_table_representative_first_alerts),
            ("Representative Run / Probe-Window Domain Observations", build_table_probe_window_domain_observations),
            ("Detector Event Forensics / Noisiest Detector Runs", build_table_noisiest_detector_runs),
            ("PCAP Forensics / Capture Overview", build_table_capture_overview),
            ("PCAP Forensics / Top Conversations", build_table_top_conversations),
            ("PCAP Forensics / ARP Replies", build_table_arp_replies),
            ("PCAP Forensics / DNS Answers", build_table_dns_answers),
            ("PCAP Forensics / ICMP Redirects", build_table_icmp_redirects),
        ]
        tables: dict[str, Path] = {}
        for title, builder in builders:
            path = builder(rows, self.options.output_dir)
            if path is not None:
                tables[title] = path
        return tables

    def build(self) -> Path:
        rows = self.load_rows()
        if not rows:
            raise SystemExit(f"No evaluated runs found under {self.options.target} for profile={self.options.profile}")

        self.options.output_dir.mkdir(parents=True, exist_ok=True)
        clear_report_outputs(self.options.output_dir)
        write_dataset(rows, self.options.output_dir)

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
            print(f"Wrote experiment dataset, figures, tables, and markdown report to {self.options.output_dir}")
        return self.options.output_dir / "experiment-report.md"
