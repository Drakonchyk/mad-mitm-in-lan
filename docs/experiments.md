# Experiments

This page explains the experiment set implemented in the repository and how the retained sample dataset relates to the full local evaluation.

## Evaluation Structure

The repo uses two layers of evaluation:

- main evaluation:
  - the core scenarios that form the main thesis-style comparison
- supplementary evaluation:
  - extra scenarios used to study response speed, DHCP behavior, robustness, false positives, and degraded observability

The goal is not only to ask whether the detector, Zeek, or Suricata alert at least once. It is also to compare:

- how quickly they react;
- what kinds of evidence they react to;
- how many detector packet alerts are generated;
- what operational impact is visible from the victim-side probe loop.

## Main Evaluation

The main evaluation keeps this core scenario matrix:

- `baseline`
  - benign negative class
- `arp-poison-no-forward`
  - disruption-only poisoning without a transparent forwarding path
- `arp-mitm-forward`
  - transparent ARP MITM with forwarding enabled
- `arp-mitm-dns`
  - transparent MITM with focused DNS spoofing for the monitored domain set
- `dhcp-spoof`
  - rogue DHCP offer and ACK broadcast behavior
- `dhcp-starvation`
  - repeated DHCP client impersonation intended to pressure or deplete the lab lease pool
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

- `dhcp-starvation-rogue-dhcp`
  - starvation pressure repeated with increasing parallel spoofing workers, real lease counting, and optional rogue DHCP takeover probes
- `visibility-arp-mitm-dns`
  - the ARP/DNS attack family under live packet loss at the sensor feed
- `visibility-dhcp-spoof`
  - the rogue-DHCP attack family under live packet loss at the sensor feed

Canonical command:

```bash
make experiment-plan-extra
```

Visibility-degradation campaign:

```bash
make visibility-plan
```

DHCP-starvation worker-scaling campaign:

```bash
make starvation-takeover-plan
```

Set `TAKEOVER_ENABLE=0` to test only lease-pool flooding. Leave `TAKEOVER_ENABLE=1` for the full rogue-DHCP takeover probe.

Typical report build:

```bash
make experiment-report
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

To run only one scenario through the main pipeline, override `PLAN_SCENARIOS`. Example:

```bash
WARMUP_RUNS=0 MEASURED_RUNS=10 PLAN_SCENARIOS="dhcp-starvation" make experiment-plan
```

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
- detector packet-alert composition
- victim-side operational metrics:
  - gateway ping latency
  - attacker ping latency
  - `curl time_total`
  - `iperf3` throughput

Timing comparisons between detector, Zeek, and Suricata use the first supported ground-truth attack evidence for each tool rather than the nominal planned attack start.

When packet capture is enabled, the preferred observed-wire basis is the mirrored switch capture on `results/<run>/pcap/sensor.pcap`. That keeps detector evaluation tied to raw packets from the switch view instead of the detector's own emitted events.

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

- fast inspection by readers;
- lightweight repository size.

The retained sample is not the full thesis dataset. For the full evaluation, keep the complete `results/` tree locally and rebuild reports from that larger local tree.

## Canonical Commands

Full setup and demo path:

```bash
make setup
make demo-ui
```

Single-scenario commands:

```bash
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
make scenario-dhcp-starvation
make scenario-dhcp-starvation-rogue-dhcp
make scenario-mitigation-recovery
```
