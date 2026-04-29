# MITM Diploma Lab

This repository builds an isolated libvirt/Open vSwitch lab for studying local-LAN
man-in-the-middle behavior. It runs repeatable ARP, DNS, and DHCP spoofing
scenarios, compares a custom packet detector with Zeek and Suricata, and stores the
results in a compact SQLite database for plots and thesis tables.

The lab is intentionally local and isolated. Do not point these scripts at a real
network.

## What Is In The Lab

- `mitm-gateway`: trusted gateway, DNS server, DHCP server, and NAT point
- `mitm-victim`: ordinary client, addressed by DHCP
- `mitm-attacker`: attack VM, addressed by DHCP
- `br-mitm-lab`: isolated Open vSwitch bridge
- `mitm-sensor0`: mirrored host sensor port used by Detector, Zeek, and Suricata

The gateway has a fixed lab identity:

- IP: `10.20.20.1`
- MAC: `52:54:00:aa:20:01`

Victim and attacker IPs are not fixed. The scripts learn them from DHCP leases,
traffic, and attacker-side discovery.

## Current Experiment Set

Main runs:

- `baseline`
- `arp-poison-no-forward`
- `arp-mitm-forward`
- `arp-mitm-dns`
- `dhcp-spoof`

Reliability runs:

- `reliability-arp-mitm-dns`
- `reliability-dhcp-spoof`

Reliability campaigns send the mirrored sensor feed through a NetEm path and sweep
packet loss from 0% to 100% in 10% steps by default.

## Ground Truth

Ground truth is based on switch-side trusted observations, not on the detector's own
alerts. OVS knows which ingress port belongs to the trusted gateway and records
ARP/DNS/DHCP trust violations as compact observations. Packet captures are optional
debug evidence.

The detector, Zeek, and Suricata are compared on the same mirrored packet feed.
OVS port-aware truth is kept separate because Zeek and Suricata do not receive OVS
ingress-port metadata in this setup.

## Quick Start

Install host dependencies:

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager cpu-checker \
  wireshark tshark tcpdump python3-pip python3-scapy git jq curl iperf3 dnsutils \
  openvswitch-switch cloud-image-utils
sudo adduser "$USER" libvirt
```

Log out and back in if you changed group membership, then run:

```bash
make prereqs
make setup
make status
```

## Common Commands

Run the clean baseline:

```bash
make baseline
```

Run the main scenario plan:

```bash
RUNS=5 make experiment-plan
```

Run one scenario:

```bash
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
```

Run thesis reliability campaigns:

```bash
RUNS=3 make reliability
RUNS=3 make reliability-arp-dns
RUNS=3 LOSS_LEVELS="70 80 90 100" make reliability-dhcp
```

Build summaries and plots:

```bash
make summarize
make results-db-overview
make experiment-report
```

Open the browser demo:

```bash
make demo-ui
```

## Useful Flags

- `DEBUG=1`: keep raw run artifacts and pcaps that were enabled
- `PCAP=1`: keep aggregate sensor pcap
- `PORT_PCAP=1`: keep per-port pcaps for gateway, victim, and attacker ports
- `GUEST_PCAP=1`: keep guest-side captures
- `ZEEK_ENABLE=0`: disable Zeek comparator
- `SURICATA_ENABLE=0`: disable Suricata comparator
- `LOSS_LEVELS="0 10 20"`: choose reliability packet-loss levels
- `RUNS=5`: repeat each selected planned scenario
- `SCENARIOS="dhcp-spoof"`: restrict the main plan to selected scenarios

Raw per-run files are pruned by default after evaluation. Durable results live in:

```text
results/experiment-results.sqlite
results/experiment-report/
```

## Repository Map

- `mk/`: grouped make targets
- `shell/lab/`: lab lifecycle scripts
- `shell/experiments/`: baseline, scenario-window, and campaign orchestration
- `shell/scenarios/`: focused scenario wrappers
- `python/detector/`: live detector
- `python/mitm/`: attacker-side ARP/DNS/DHCP actions
- `python/metrics/`: evaluation and SQLite result storage
- `python/reporting/`: CSV, plot, and markdown report generation
- `python/demo_dashboard/`: localhost demo dashboard
- `docs/`: topology, scenarios, metrics, commands, and architecture notes
- `results/`: SQLite database, optional debug runs, and generated report outputs

## Reading Order

1. [Topology](docs/topology.md)
2. [Scenario Definitions](docs/scenario-definitions.md)
3. [Experiments](docs/experiments.md)
4. [Evaluation Metrics](docs/evaluation-metrics.md)
5. [Command Reference](docs/command-reference.md)
6. [Repo Architecture](docs/repo-architecture.md)
