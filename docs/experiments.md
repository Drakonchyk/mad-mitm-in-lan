# Experiments

This page explains the experiment set implemented in the repository and how the retained sample dataset relates to the full local evaluation.

## Evaluation Structure

The repo uses two layers of evaluation:

- main evaluation:
  - the five core scenarios that form the main thesis-style comparison
- supplementary evaluation:
  - three extra scenarios used to study response speed, robustness, false positives, and degraded observability

The goal is not only to ask whether the detector, Zeek, or Suricata alert at least once. It is also to compare:

- how quickly they react;
- what kinds of evidence they react to;
- how many semantic detector alerts are generated;
- what operational impact is visible from the victim-side probe loop.

## Main Evaluation

The main evaluation keeps the core five-scenario matrix:

- `baseline`
  - benign negative class
- `arp-poison-no-forward`
  - disruption-only poisoning without a transparent forwarding path
- `arp-mitm-forward`
  - transparent ARP MITM with forwarding enabled
- `arp-mitm-dns`
  - transparent MITM with focused DNS spoofing for the monitored domain set
- `mitigation-recovery`
  - attack followed by victim-side restoration of the legitimate gateway MAC

Canonical command:

```bash
make experiment-plan
```

Typical report build:

```bash
make experiment-report
```

## Supplementary Evaluation

The supplementary scenarios exist because plain accuracy can become uninformative once the obvious attack cases are easy for every tool.

The extra scenarios are:

- `intermittent-arp-mitm-dns`
  - pulsed attack windows to study reaction speed and missed short windows
- `noisy-benign-baseline`
  - benign churn intended to pressure false-positive behavior
- `reduced-observability`
  - the same attack family under lower detector packet visibility

Canonical command:

```bash
make experiment-plan-extra
```

Typical report build:

```bash
make experiment-report-extra
```

## Run Counts

The intended local full dataset is:

- main evaluation:
  - 1 warm-up run per scenario
  - 10 measured runs per scenario
- supplementary evaluation:
  - 1 warm-up run per scenario
  - 5 measured runs per scenario

Warm-up runs are excluded from the normal plots unless `--include-warmups` is passed to the report builder.

## Timing Windows

Main scenarios use fixed windows so time-to-detection and recovery metrics are comparable.

- 90-second attack runs:
  - `t=0..10 s`: clean prefix
  - `t=10..70 s`: attack active
  - `t=70..90 s`: recovery tail
- mitigation-recovery:
  - `t=0..10 s`: clean prefix
  - `t=10..45 s`: attack active
  - `t=45 s`: mitigation
  - `t=45..120 s`: recovery observation

The exact per-scenario timing descriptions are in [Scenario Definitions](./scenario-definitions.md).

## Metrics Used

The generated reports focus on:

- run-level detection
- attack-type coverage
- event recall
- time to first supported alert
- time to recovery
- semantic detector alert composition
- victim-side operational metrics:
  - gateway ping latency
  - attacker ping latency
  - `curl time_total`
  - `iperf3` throughput

Timing comparisons between detector, Zeek, and Suricata use the first supported ground-truth attack evidence for each tool rather than the nominal planned attack start.

The full metric definition page is [Evaluation Metrics](./evaluation-metrics.md).

## Figures Produced

The reports now generate a mix of plot types rather than relying mainly on box plots.

Main report figures include:

- box plots for time-to-alert, latency, throughput, and recovery
- bar charts with error bars for detector alert volume
- stacked bars for compositional detector alert breakdown
- timeline markers for a representative `arp-mitm-dns` run
- scatter plots showing alert volume versus detection delay
- donut charts for aggregate semantic alert composition
- time-series traces for representative probe behavior and cumulative detector alerts

Supplementary report figures include:

- box plots for detector timing and operational metrics
- grouped bars for tool detection rate and mean alert volume
- scatter plots for operational impact relationships
- donut charts for detector alert composition in the supplementary dataset
- representative time-based detector traces

## Deterministic Retained Sample

The repository keeps only a small retained sample locally under version control.

That retained sample is meant for:

- a deterministic `make demo-report` path;
- fast inspection by readers;
- lightweight repository size.

The retained sample is not the full thesis dataset. For the full evaluation, keep the complete `results/` tree locally and rebuild reports from that larger local tree.

## Canonical Commands

Full setup and demo path:

```bash
make setup
make demo-start
make demo-scenario
make demo-report
```

Single-scenario commands:

```bash
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-mitigation-recovery
```

Live capture helper:

```bash
make demo-capture HOST=victim IFACE=vnic0 FILTER="arp or icmp or port 53"
```
