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
make scenario-intermittent-dhcp-spoof
make scenario-dhcp-offer-only
```

## Planned Evaluations

```bash
make experiment-plan
make experiment-plan-extra
```

Resume or trim a plan:

```bash
make experiment-plan ARGS="--skip 2"
make experiment-plan ARGS="--start 11"
make experiment-plan ARGS="--skip-scenario baseline"
make experiment-plan-extra ARGS="--start-scenario intermittent-arp-mitm-dns"
```

## Report Generation

```bash
make summarize
make experiment-report
make experiment-report-extra
make demo-report
```

`make experiment-report-extra` is now just a compatibility alias of `make experiment-report`.

## Direct Scenario Commands

```bash
make scenario-verify
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
make scenario-mitigation-recovery
make scenario-compare TARGET=results
```

Run just one focused scenario:

```bash
make scenario-arp-mitm-dns DURATION=90
make scenario-dhcp-spoof DURATION=60
make scenario-intermittent-dhcp-spoof DURATION=90
make scenario-dhcp-offer-only DURATION=60
```

Those commands create a single run under `results/` without running the full smoke matrix or experiment plan.

## Live Capture

```bash
make demo-capture HOST=sensor IFACE=mitm-sensor0 FILTER="arp or icmp or port 53 or port 67 or port 68"
make demo-capture HOST=gateway IFACE=any FILTER="arp or icmp or port 53"
```

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
- `MAX_RUNS_PER_SCENARIO=1` for `make demo-report`

Packet-capture retention notes:

- single scenario commands keep full pcaps by default
- planned experiment runs keep only one exemplar pcap per scenario by default
- all planned runs still keep `pcap/wire-truth.json`, a compact switch-truth artifact used by the evaluator when the full pcap is pruned
