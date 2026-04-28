# Experiments

This page explains the experiment set implemented in the repository and how to rebuild reports from the local result database.

## Evaluation Structure

The repo uses two layers of evaluation:

- main evaluation:
  - the core scenarios that form the main thesis-style comparison
- reliability evaluation:
  - repeated NetEm packet-loss runs used to study degraded sensor reliability

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

Canonical command:

```bash
make experiment-plan
```

Typical report build:

```bash
make experiment-report
```

## Reliability Evaluation

Reliability scenarios exist because the obvious attack cases are easy when every packet reaches every tool. They test what happens when the monitored feed is lossy.

The reliability scenarios are:

- `reliability-arp-mitm-dns`
  - the ARP/DNS attack family under NetEm-impaired sensor traffic
- `reliability-dhcp-spoof`
  - the rogue-DHCP attack family under NetEm-impaired sensor traffic

Reliability-degradation campaign:

```bash
make reliability RUNS=3
make reliability-plan
```

Use `make reliability RUNS=3` for the thesis packet-loss sweep: ARP/DNS MITM and focused DHCP rogue-server detection at 0% through 100% loss in 10% steps. Use `make reliability-plan` with `RELIABILITY_LOSS_LEVELS`, `RELIABILITY_DELAY_MS`, `RELIABILITY_JITTER_MS`, and `RELIABILITY_RATE` when tuning custom packet loss, delay, jitter, or bandwidth limits.

Typical report build:

```bash
make experiment-report
```

## Run Counts

The intended local full dataset is:

- main evaluation:
  - baseline reference is collected separately with `make baseline`
  - 5 runs per scenario when a repeated local sample is needed
- reliability evaluation:
  - reliability campaigns use `RUNS=N` repetitions per loss level

To run only one scenario through the main pipeline, override `PLAN_SCENARIOS`. Example:

```bash
RUNS=5 PLAN_SCENARIOS="dhcp-spoof" make experiment-plan
```

## Timing Windows

Main attack scenarios use fixed windows so time-to-detection metrics are comparable.

- ARP-only attack runs:
  - `t=0..5 s`: clean prefix
  - `t=5..25 s`: attack active
  - `t=25..30 s`: clean tail
- ARP/DNS attack runs:
  - `t=0..5 s`: clean prefix
  - `t=5..35 s`: attack active
  - `t=35..45 s`: clean tail
- DHCP spoof runs:
  - `t=0..5 s`: clean prefix
  - `t=5..25 s`: attack active
  - `t=25..30 s`: clean tail
The exact per-scenario timing descriptions are in [Scenario Definitions](./scenario-definitions.md).

## Metrics Used

The generated reports focus on:

- run-level detection
- attack-type coverage
- event recall
- time to first supported alert
- detector packet-alert composition
- victim-side operational metrics:
  - gateway ping latency
  - attacker ping latency
  - synthetic probe packet counts
  - optional `curl time_total`
  - optional `iperf3` throughput

Scenario windows use a synthetic Python/Scapy traffic probe by default. It produces predictable ICMP packets and UDP DNS queries, which makes the background load easier to reason about than `curl` or `iperf3`. `curl` and `iperf3` are still useful diagnostics, but they are opt-in rather than core evidence.

Timing comparisons between detector, Zeek, and Suricata use the first supported ground-truth attack evidence for each tool rather than the nominal planned attack start.

The preferred ground-truth basis is the trusted observation database materialized from OVS snooping artifacts. Packet captures are optional debugging evidence: `results/<run>/pcap/sensor.pcap` keeps the mirrored switch feed, and `results/<run>/pcap/ports/` keeps gateway, victim, and attacker switch-port traffic separate when per-port capture is enabled.

By default, raw per-run files are only temporary. After each run is evaluated, the durable rows are inserted into `results/experiment-results.sqlite` and raw artifacts are pruned. Set `KEEP_DEBUG_ARTIFACTS=1` when a run needs full files for packet-level debugging or report development.

The full metric definition page is [Evaluation Metrics](./evaluation-metrics.md).

## Figures Produced

The report focuses on the figures used in the thesis:

- DNS packet recall by detector under NetEm loss
- rogue-DHCP packet recall by detector under NetEm loss
- detection survival under NetEm loss
- time-to-detection heatmaps
- detector processed-packet-rate context
- basic scenario timing heatmaps

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
```
