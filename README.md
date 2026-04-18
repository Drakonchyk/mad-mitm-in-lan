# MITM Diploma Lab

## What This Project Is

This repository builds a small, isolated libvirt lab for studying LAN man-in-the-middle behavior and evaluating a victim-side detector against optional Zeek and Suricata comparators.

The lab contains three virtual machines:

- `mitm-gateway`
- `mitm-victim`
- `mitm-attacker`

The project automates:

- lab provisioning and teardown;
- repeatable scenario execution for the main experiment set;
- supplementary stress scenarios for extra analysis;
- collection of the per-run artifacts needed for plots and interpretation;
- dataset export, tables, and figures for the main, supplementary, and demo reports.

Useful companion docs:

- [Topology](docs/topology.md)
- [Repo Architecture](docs/repo-architecture.md)
- [Experiments](docs/experiments.md)
- [Scenario Definitions](docs/scenario-definitions.md)
- [Evaluation Metrics](docs/evaluation-metrics.md)
- [Artifact Map](docs/artifact-map.md)
- [Command Reference](docs/command-reference.md)

## Threat Model

The detector is meant to observe signs of local-LAN MITM behavior from the victim side inside a controlled research environment.

The main attack families modeled here are:

- ARP poisoning without forwarding;
- transparent ARP MITM with forwarding enabled;
- ARP MITM plus focused DNS spoofing;
- mitigation and recovery after the victim restores the legitimate gateway neighbor entry.

This is a research testbed, not a production hardening framework.

## Topology

The lab uses two libvirt networks:

- `default`: upstream NAT network for host-provided connectivity;
- `mitm-lab`: isolated lab network on `virbr11`.

Address plan:

- gateway: `10.20.20.1/24`
- victim: `10.20.20.10/24`
- attacker: `10.20.20.66/24`

Where components live:

- detector: victim VM, always enabled during experiment runs;
- Zeek comparator: victim VM, optional, disabled by default;
- Suricata comparator: victim VM, optional, disabled by default;
- packet captures: optional per run;
- orchestration and report generation: host machine.

The architecture diagram is in [docs/topology.md](docs/topology.md).

## Scenario Set

Main evaluation scenarios:

- `baseline`
- `arp-poison-no-forward`
- `arp-mitm-forward`
- `arp-mitm-dns`
- `mitigation-recovery`

Supplementary scenarios:

- `intermittent-arp-mitm-dns`
- `noisy-benign-baseline`
- `reduced-observability`

The explanatory experiment overview is in [docs/experiments.md](docs/experiments.md), and the exact timing windows are in [docs/scenario-definitions.md](docs/scenario-definitions.md).

## Quick Start

Install the host prerequisites first:

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager cpu-checker \
  wireshark tshark tcpdump python3-pip git jq curl iperf3 dnsutils
sudo apt install cloud-image-utils
```

If needed, add your user to the `libvirt` group and log back in:

```bash
sudo adduser "$USER" libvirt
```

Then from the repository root:

```bash
make prereqs
make setup
make status
```

Common run toggles:

- detector: always on for experiment runs;
- Zeek: `ZEEK_ENABLE=1` to enable, default is disabled;
- Suricata: `SURICATA_ENABLE=1` to enable, default is disabled;
- pcap capture: enabled by default, disable with `PCAP_ENABLE=0`.

Example:

```bash
ZEEK_ENABLE=1 SURICATA_ENABLE=1 make baseline
PCAP_ENABLE=0 make baseline
```

## Demo Path

The repo has one compact demo path that mirrors the retained sample dataset:

```bash
make demo-start
make demo-scenario
make demo-report
make demo-capture HOST=victim IFACE=vnic0 FILTER="arp or icmp or port 53"
```

What these do:

- `make demo-start`: provisions the lab if needed and ensures it is running;
- `make demo-scenario`: runs the focused `arp-mitm-dns` scenario used as the canonical live demo path;
- `make demo-report`: builds a small deterministic report from at most one retained measured run per scenario into `results/demo-report/`;
- `make demo-capture`: opens a live `tcpdump` stream on a chosen VM until `Ctrl-C`.

## Dangerous Operations Warning

This repository is for an isolated local lab only.

- Do not point these scripts at a real network.
- Do not run the direct scenario commands outside the dedicated lab.
- The attacker-side automation is intentionally limited to the isolated VMs created by this repo.
- The high-risk scenario entry points now live under `shell/scenarios/` and are exposed through a small set of top-level `make scenario-*` targets.

## Artifact Layout

Top-level layout:

- `Makefile`: common entry points;
- `mk/`: grouped make target definitions;
- `shell/lab/`: lab lifecycle and provisioning scripts;
- `shell/experiments/`: experiment-plan and scenario-window orchestration;
- `shell/scenarios/`: direct automated scenario helpers;
- `shell/tools/`: live-capture and demo-report helpers;
- `python/lab/`: template rendering and shell-facing Python helpers;
- `python/detector/`: detector runtime sources;
- `python/mitm/`: attacker-side MITM automation and scenario entry points;
- `python/logs/`: artifact interpretation helpers for detector, Zeek, and Suricata outputs;
- `python/metrics/`: run parsing, evaluation, and summary logic;
- `python/reporting/`: dataset export, plots, tables, and markdown report builder;
- `python/scenarios/`: scenario metadata and ordering;
- `python/`: package root and remaining shared utilities;
- `docs/`: topology, architecture, experiment, metric, artifact, and command reference pages;
- `config/`: static config inputs;
- `libvirt/`: network definitions;
- `results/`: per-run artifacts and generated reports.

Typical per-run outputs worth keeping:

- `run-meta.json`
- `summary.txt`
- `evaluation-summary.txt`
- `evaluation.json`
- `victim/detector.delta.jsonl`
- `victim/detector-explained.txt`
- `victim/traffic-window.txt`
- `victim/iperf3.json`
- `zeek/` when enabled
- `suricata/` when enabled
- `pcap/victim.pcap` when packet capture is enabled

By default the run cleanup drops most host, gateway, attacker, and debug-only leftovers. If you want the full raw collection for troubleshooting, run with:

```bash
KEEP_DEBUG_ARTIFACTS=1 make ...
```

## Report Generation

Main evaluation flow:

```bash
make experiment-plan
make experiment-report
```

Supplementary evaluation flow:

```bash
make experiment-plan-extra
make experiment-report-extra
```

Resume or trim a plan:

```bash
make experiment-plan ARGS="--skip 2"
make experiment-plan ARGS="--start 11"
make experiment-plan ARGS="--skip-scenario baseline"
make experiment-plan-extra ARGS="--start-scenario noisy-benign-baseline"
```

Single-scenario commands with the canonical names:

```bash
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-mitigation-recovery
```

The generated markdown report now includes a detection-summary section with TP, FP, TN, FN, TPR, FPR, precision, and F1, so the main workflow does not need a separate `make evaluate` command.

## Deterministic Sample Dataset Note

The repository is meant to stay lightweight and reproducible, so it keeps only a small retained sample dataset rather than every measured repetition.

In practice, that means the committed sample/report path is based on at most one retained measured run per scenario.

Why this is intentional:

- it keeps the repository size manageable;
- it makes the sample report deterministic for readers and reviewers;
- it avoids committing large local artifact trees that are easy to regenerate from the plan commands.

For the full thesis dataset, keep your complete `results/` tree locally and rebuild reports from that local data.

## What Is Committed vs Generated Locally

Typically committed:

- source code under `python/`, `shell/`, and `config/`;
- docs under `docs/`;
- a small retained sample dataset and demo-report-friendly structure.

Generated locally:

- `generated/` cloud-init and helper assets;
- `storage/` VM disks and downloaded base images;
- full `results/` trees from repeated experiments;
- regenerated report directories such as `results/experiment-report/`, `results/experiment-report-extra/`, and `results/demo-report/`.

## Day-To-Day Commands

```bash
make help
make setup
make start
make status
make baseline
make smoke-test
make summarize
make experiment-plan
make experiment-plan-extra
make experiment-report
make experiment-report-extra
make demo-report
make destroy
```
