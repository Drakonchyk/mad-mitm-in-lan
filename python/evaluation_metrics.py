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


def plot_time_series(
    x_values: Sequence[float],
    series: dict[str, Sequence[float]],
    output_path: str | Path,
    title: str,
    ylabel: str,
    xlabel: str = "Time",
) -> Path:
    plt = _require_matplotlib()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 5))
    for name, values in series.items():
        ax.plot(x_values, values, marker="o", linewidth=1.5, label=name)

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return output
