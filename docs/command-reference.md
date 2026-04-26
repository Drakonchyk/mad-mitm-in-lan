# Command Reference

This page collects the commands that are most useful when operating the lab and rebuilding reports.

## Lab Lifecycle

```bash
make prereqs
make setup
make start
make status
make destroy
make rebuild
```

## Single Runs

```bash
make baseline
make smoke-test
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
make scenario-dhcp-starvation
make scenario-dhcp-starvation-rogue-dhcp
```

## Planned Evaluations

```bash
make experiment-plan
make experiment-plan-extra
make visibility-plan
make starvation-takeover-plan
```

Run only DHCP starvation through the main pipeline:

```bash
WARMUP_RUNS=0 MEASURED_RUNS=10 PLAN_SCENARIOS="dhcp-starvation" make experiment-plan
```

Keep the default warm-up and still do 10 measured DHCP-starvation runs:

```bash
WARMUP_RUNS=1 MEASURED_RUNS=10 PLAN_SCENARIOS="dhcp-starvation" make experiment-plan
```

Resume or trim a plan:

```bash
make experiment-plan ARGS="--skip 2"
make experiment-plan ARGS="--start 11"
make experiment-plan ARGS="--skip-scenario baseline"
make experiment-plan-extra ARGS="--start-scenario dhcp-starvation-rogue-dhcp"
```

## Report Generation

```bash
make summarize
make experiment-report
make experiment-report-extra
```

`make experiment-report-extra` is now just a compatibility alias of `make experiment-report`.

## Direct Scenario Commands

```bash
make scenario-verify
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
make scenario-dhcp-starvation
make scenario-dhcp-starvation-rogue-dhcp
make scenario-mitigation-recovery
```

Run just one focused scenario:

```bash
make scenario-arp-mitm-dns DURATION=90
make scenario-dhcp-spoof DURATION=60
make scenario-dhcp-starvation DURATION=20 WORKERS=1
make scenario-dhcp-starvation-rogue-dhcp DURATION=90 WORKERS=32 TAKEOVER=1
```

Those commands create a single run under `results/` without running the full smoke matrix or experiment plan.

Use `TAKEOVER=0` for the single-scenario DHCP lease-pool flood without the rogue-DHCP takeover phase. Use `TAKEOVER_ENABLE=0 make starvation-takeover-plan` for the planned worker sweep without takeover.

## Quick Validation

```bash
make rebuild
make status
make baseline
make scenario-arp-mitm-dns
make summarize
```

After `make status`, the expected steady state is:

- only the libvirt `default` network remains;
- `br-mitm-lab` contains the gateway, victim, attacker, and `mitm-sensor0`;
- `mitm-lab-mirror` exists in the Open vSwitch output.

During runs, the detector, Zeek, and Suricata all observe `mitm-sensor0` on the host. Disable the comparators only with explicit flags:

```bash
ZEEK_ENABLE=0 make baseline
SURICATA_ENABLE=0 make baseline
ZEEK_ENABLE=0 SURICATA_ENABLE=0 make baseline
```

Current Suricata note:

- On some host builds, the ARP comparison rule path is unavailable even though DHCP+DNS+ICMP comparison still works.
- When that happens, the run summary prints `Suricata ARP coverage: ... DHCP+DNS+ICMP only`.

## Useful Environment Toggles

- `ZEEK_ENABLE=0`
- `SURICATA_ENABLE=0`
- `PCAP_ENABLE=0`
- `KEEP_DEBUG_ARTIFACTS=1`
- `WARMUP_RUNS=0` / `MEASURED_RUNS=10` for focused pipeline subsets
- `PLAN_SCENARIOS="dhcp-starvation"` to restrict the main plan to one scenario

Packet-capture retention notes:

- single scenario commands keep full pcaps by default
- planned experiment runs keep compact `pcap/wire-truth.json` by default and prune the full pcap afterward
- visibility and starvation-worker campaigns keep only the first full pcap per scenario by default
- guest pcaps and extra `tshark` summaries are off by default in the main and supplementary plans
- planned runs also disable `iperf` and the post-attack settle tail by default unless explicitly re-enabled
