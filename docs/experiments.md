# Experiments

This page explains the experiment set implemented in the repository and how the retained sample dataset relates to the full local evaluation.

## Evaluation Structure

The repo uses two layers of evaluation:

- main evaluation:
  - the core scenarios that form the main thesis-style comparison
- supplementary evaluation:
  - extra scenarios used to study response speed, DHCP behavior, detector throughput limits, false positives, and degraded sensor reliability

The goal is not only to ask whether the detector, Zeek, or Suricata alert at least once. It is also to compare:

- how quickly they react;
- what kinds of evidence they react to;
- how many detector packet alerts are generated;
- what operational impact is visible from the victim-side probe loop.

## Main Evaluation

Run `make baseline` separately before the attack matrix to collect the clean negative-control reference.

The main evaluation plan keeps this core attack scenario matrix:

- `arp-poison-no-forward`
  - disruption-only poisoning without a transparent forwarding path
- `arp-mitm-forward`
  - transparent ARP MITM with forwarding enabled
- `arp-mitm-dns`
  - transparent MITM with focused DNS spoofing for the monitored domain set
- `dhcp-spoof`
  - rogue DHCP offer and ACK broadcast behavior

Mitigation is deliberately excluded from the default main plan because detection and reliability are the thesis-critical measurements. The `mitigation-recovery` scenario still exists as an executable standalone run.

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

- `reliability-arp-mitm-dns`
  - the ARP/DNS attack family under NetEm-impaired sensor traffic
- `reliability-dhcp-spoof`
  - the rogue-DHCP attack family under NetEm-impaired sensor traffic

Canonical command:

```bash
make experiment-plan-extra
```

Reliability-degradation campaign:

```bash
make reliability RUNS=3
make reliability-plan
```

Use `make reliability RUNS=3` for the thesis packet-loss sweep: ARP/DNS MITM and focused DHCP rogue-server detection at 0% through 100% loss in 10% steps. Use `make reliability-plan` with `RELIABILITY_LOSS_LEVELS`, `RELIABILITY_DELAY_MS`, `RELIABILITY_JITTER_MS`, and `RELIABILITY_RATE` when tuning custom packet loss, delay, jitter, or bandwidth limits.

Detector-overload calibration campaign:

```bash
make overload-plan
make overload-summary
```

This sends controlled ICMP background traffic with Python/Scapy, matches the detector capture filter, and splits the requested packet rate evenly across `OVERLOAD_SOURCES`, for example victim and attacker. Runs are short by default (`OVERLOAD_DURATION_SECONDS=20`, `OVERLOAD_TRAFFIC_SECONDS=12`) and use OVS snooping truth unless pcaps are explicitly enabled.

Typical report build:

```bash
make experiment-report
```

## Run Counts

The intended local full dataset is:

- main evaluation:
  - baseline reference is collected separately with `make baseline`
  - 1 warm-up run per scenario
  - 5 measured runs per scenario
- supplementary evaluation:
  - 1 warm-up run per scenario
  - 5 measured runs per scenario

Warm-up runs are excluded from the normal plots unless `--include-warmups` is passed to the report builder.

To run only one scenario through the main pipeline, override `PLAN_SCENARIOS`. Example:

```bash
WARMUP_RUNS=0 MEASURED_RUNS=5 PLAN_SCENARIOS="dhcp-spoof" make experiment-plan
```

## Timing Windows

Main attack scenarios use fixed windows so time-to-detection and recovery metrics are comparable.

- ARP attack runs:
  - `t=0..5 s`: clean prefix
  - `t=5..35 s`: attack active
  - `t=35..45 s`: recovery tail
- DHCP spoof runs:
  - `t=0..5 s`: clean prefix
  - `t=5..25 s`: attack active
  - `t=25..30 s`: recovery tail
- standalone mitigation-recovery:
  - `t=0..5 s`: clean prefix
  - `t=5..30 s`: attack active
  - `t=30 s`: mitigation
  - `t=30..75 s`: recovery observation

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
  - synthetic probe packet counts
  - optional `curl time_total`
  - optional `iperf3` throughput

Scenario windows use a synthetic Python/Scapy traffic probe by default. It produces predictable ICMP packets and UDP DNS queries, which makes the background load easier to reason about than `curl` or `iperf3`. `curl` and `iperf3` are still useful diagnostics, but they are opt-in rather than core evidence.

Timing comparisons between detector, Zeek, and Suricata use the first supported ground-truth attack evidence for each tool rather than the nominal planned attack start.

When packet capture is enabled, the preferred observed-wire basis is the mirrored switch capture on `results/<run>/pcap/sensor.pcap`. Per-port captures under `results/<run>/pcap/ports/` keep gateway, victim, and attacker switch-port traffic separate for focused debugging. For compact reliability and overload runs, pcaps are optional: OVS snooping artifacts record ARP, DNS, and DHCP trust violations from non-gateway ports and are materialized into `ground-truth/trusted-observations.sqlite` before metrics are computed.

By default, raw per-run files are only temporary. After each run is evaluated, the durable rows are inserted into `results/experiment-results.sqlite` and raw artifacts are pruned. Set `KEEP_DEBUG_ARTIFACTS=1` when a run needs full files for packet-level debugging or report development.

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
make scenario-reliability-arp-mitm-dns LOSS=5
make scenario-reliability-dhcp-spoof LOSS=5
make scenario-mitigation-recovery
```
