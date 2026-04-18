#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


@dataclass(frozen=True)
class ConfusionCounts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def true_positive_rate(self) -> float:
        return safe_divide(self.tp, self.tp + self.fn)

    def false_positive_rate(self) -> float:
        return safe_divide(self.fp, self.fp + self.tn)

    def precision(self) -> float:
        return safe_divide(self.tp, self.tp + self.fp)

    def f1(self) -> float:
        precision = self.precision()
        recall = self.true_positive_rate()
        return safe_divide(2 * precision * recall, precision + recall)

    def accuracy(self) -> float:
        return safe_divide(self.tp + self.tn, self.total())

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "tpr": self.true_positive_rate(),
            "fpr": self.false_positive_rate(),
            "precision": self.precision(),
            "f1": self.f1(),
            "accuracy": self.accuracy(),
        }


def confusion_from_binary(ground_truth: Sequence[bool], predictions: Sequence[bool]) -> ConfusionCounts:
    if len(ground_truth) != len(predictions):
        raise ValueError("ground_truth and predictions must have the same length")

    counts = ConfusionCounts()
    tp = fp = tn = fn = 0
    for truth, predicted in zip(ground_truth, predictions):
        if truth and predicted:
            tp += 1
        elif not truth and predicted:
            fp += 1
        elif truth and not predicted:
            fn += 1
        else:
            tn += 1
    return ConfusionCounts(tp=tp, fp=fp, tn=tn, fn=fn)


def parse_iso8601(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)
    except ValueError:
        pass
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def time_to_detection_seconds(attack_started_at: str | datetime | None, first_alert_at: str | datetime | None) -> float | None:
    start = parse_iso8601(attack_started_at)
    alert = parse_iso8601(first_alert_at)
    if start is None or alert is None:
        return None
    return (alert - start).total_seconds()


def relative_overhead_percent(baseline_value: float, with_detector_value: float) -> float | None:
    if baseline_value == 0:
        return None
    return ((with_detector_value - baseline_value) / baseline_value) * 100.0


def relative_overhead_series_percent(
    baseline_values: Iterable[float],
    with_detector_values: Iterable[float],
) -> list[float | None]:
    return [
        relative_overhead_percent(baseline, with_detector)
        for baseline, with_detector in zip(baseline_values, with_detector_values)
    ]


def _require_matplotlib():
    try:
        import matplotlib.pyplot as plt  # noqa: PLC0415
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install matplotlib to use plotting helpers") from exc
    return plt


def plot_grouped_bars(
    labels: Sequence[str],
    series: dict[str, Sequence[float]],
    output_path: str | Path,
    title: str,
    ylabel: str,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    series_names = list(series)
    width = 0.8 / max(len(series_names), 1)
    positions = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.2), 5))
    for index, name in enumerate(series_names):
        offset = (index - (len(series_names) - 1) / 2) * width
        ax.bar([position + offset for position in positions], series[name], width=width, label=name)

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_scatter_groups(
    groups: dict[str, Sequence[tuple[float, float, str | None]]],
    output_path: str | Path,
    title: str,
    xlabel: str,
    ylabel: str,
    *,
    annotate: bool = False,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(9, 5.5))
    for label, points in groups.items():
        if not points:
            continue
        x_values = [point[0] for point in points]
        y_values = [point[1] for point in points]
        ax.scatter(x_values, y_values, s=52, alpha=0.85, label=label)
        if annotate:
            for x_value, y_value, note in points:
                if note:
                    ax.annotate(note, (x_value, y_value), textcoords="offset points", xytext=(4, 4), fontsize=8)

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_pie_chart(
    values: dict[str, float],
    output_path: str | Path,
    title: str,
    *,
    donut: bool = True,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    filtered = [(label, value) for label, value in values.items() if value > 0]
    labels = [label for label, _ in filtered]
    sizes = [value for _, value in filtered]

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, _, _ = ax.pie(
        sizes,
        labels=labels,
        autopct=lambda pct: f"{pct:.1f}%" if pct >= 3 else "",
        startangle=90,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
    )
    if donut:
        centre_circle = plt.Circle((0, 0), 0.60, fc="white")
        ax.add_artist(centre_circle)
    ax.set_title(title)
    ax.legend(wedges, [f"{label} ({value:.0f})" for label, value in filtered], loc="center left", bbox_to_anchor=(1.0, 0.5))
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_box_by_category(
    labels: Sequence[str],
    series: Sequence[Sequence[float]],
    output_path: str | Path,
    title: str,
    ylabel: str,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    clean_series = [list(values) for values in series]
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.4), 5))
    ax.boxplot(clean_series, labels=labels, patch_artist=True)
    for category_index, values in enumerate(clean_series, start=1):
        if not values:
            continue
        offsets = [
            (point_index - (len(values) - 1) / 2) * 0.04
            for point_index in range(len(values))
        ]
        ax.scatter(
            [category_index + offset for offset in offsets],
            values,
            alpha=0.85,
            s=26,
            zorder=3,
        )
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_bars_with_error(
    labels: Sequence[str],
    values: Sequence[float],
    errors: Sequence[float],
    output_path: str | Path,
    title: str,
    ylabel: str,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    positions = list(range(len(labels)))
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.2), 5))
    ax.bar(positions, values, yerr=errors, capsize=5)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_stacked_bars(
    labels: Sequence[str],
    series: dict[str, Sequence[float]],
    output_path: str | Path,
    title: str,
    ylabel: str,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    positions = list(range(len(labels)))
    bottoms = [0.0 for _ in labels]
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.3), 5))
    for name, values in series.items():
        numeric_values = [float(value) for value in values]
        ax.bar(positions, numeric_values, bottom=bottoms, label=name)
        bottoms = [bottom + value for bottom, value in zip(bottoms, numeric_values)]

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_timeline_markers(
    markers: Sequence[tuple[str, float]],
    output_path: str | Path,
    title: str,
    *,
    attack_window: tuple[float, float] | None = None,
    end_seconds: float | None = None,
    xlabel: str = "Seconds Since Run Start",
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 2.8))
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_yticks([])

    if attack_window is not None:
        ax.axvspan(attack_window[0], attack_window[1], alpha=0.15, color="tab:red")

    for index, (label, offset_seconds) in enumerate(markers):
        ax.axvline(offset_seconds, linewidth=2, label=label if index == 0 else None)
        ax.text(offset_seconds, 0.02 + (index % 2) * 0.08, label, rotation=90, va="bottom", ha="center")

    if end_seconds is not None:
        ax.set_xlim(0.0, end_seconds)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output


def plot_time_series(
    x_values: Sequence[float],
    series: dict[str, Sequence[float]],
    output_path: str | Path,
    title: str,
    ylabel: str,
    xlabel: str = "Time",
    *,
    attack_windows: Sequence[tuple[float, float]] | None = None,
    markers: Sequence[tuple[str, float]] | None = None,
    step: bool = False,
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 5))
    if attack_windows:
        for start, stop in attack_windows:
            ax.axvspan(start, stop, alpha=0.12, color="tab:red")

    for name, values in series.items():
        if step:
            ax.step(x_values, values, where="post", linewidth=1.7, label=name)
        else:
            ax.plot(x_values, values, marker="o", linewidth=1.5, label=name)

    if markers:
        ymax = ax.get_ylim()[1] if ax.get_ylim()[1] else 1.0
        for index, (label, x_value) in enumerate(markers):
            ax.axvline(x_value, linewidth=1.2, linestyle="--", alpha=0.5, color="black")
            ax.text(x_value, ymax * (0.92 - (index % 3) * 0.08), label, rotation=90, va="top", ha="center", fontsize=8)

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output
