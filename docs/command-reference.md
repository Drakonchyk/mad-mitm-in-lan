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
make scenario-reliability-arp-mitm-dns LOSS=5
make scenario-reliability-dhcp-spoof LOSS=5
```

## Planned Evaluations

```bash
make experiment-plan
make reliability RUNS=3
make reliability-plan
```

Resume or trim a plan:

```bash
make experiment-plan ARGS="--skip 2"
make experiment-plan ARGS="--start 11"
make experiment-plan ARGS="--skip-scenario arp-mitm-forward"
```

## Report Generation

```bash
make summarize
make results-db-overview
make experiment-report
```

## Direct Scenario Commands

```bash
make scenario-verify
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-dhcp-spoof
make scenario-reliability-arp-mitm-dns
make scenario-reliability-dhcp-spoof
```

Run just one focused scenario:

```bash
make scenario-arp-mitm-dns DURATION=45
make scenario-dhcp-spoof DURATION=30
make scenario-reliability-arp-mitm-dns DURATION=30 LOSS=10
make scenario-reliability-dhcp-spoof DURATION=20 LOSS=10
```

Those commands create a single run under `results/` without running the full smoke matrix or experiment plan.

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
- `PCAP_ENABLE=1` to enable the aggregate sensor pcap
- `PORT_PCAP_ENABLE=1` to enable per-switch-port pcaps
- `PORT_PCAP_ROLES="gateway victim attacker"` to choose which OVS/libvirt ports get individual pcaps
- `KEEP_DEBUG_ARTIFACTS=1`
- `RUNS=5` or `MEASURED_RUNS=5` for repeated main-plan runs
- `PLAN_SCENARIOS="dhcp-spoof"` to restrict the main plan to one scenario
- `RUNS=3 make reliability` to run the thesis reliability set with three repetitions per loss level
- `RELIABILITY_LOSS_LEVELS="0 10 20"` to choose NetEm loss levels for the reliability plan
- `RELIABILITY_DELAY_MS=20` / `RELIABILITY_JITTER_MS=5` / `RELIABILITY_RATE=1mbit` to add NetEm delay, jitter, or rate limits
- `TRAFFIC_PROBE_MODE=synthetic` for the default Scapy/UDP background probe, or `TRAFFIC_PROBE_MODE=legacy` for ping/dig-only background traffic
- `BASELINE_PERF_PROBES_ENABLE=1` to collect optional baseline `curl` and `iperf3` diagnostics
- `KEEP_DEBUG_ARTIFACTS=1` to retain raw per-run files; otherwise the durable result is written to `results/experiment-results.sqlite`
- `LAB_DHCP_SNOOPING_MODE=monitor` to count DHCP server replies from non-gateway ports without blocking them
- `LAB_DHCP_SNOOPING_MODE=enforce` or legacy `LAB_DHCP_SNOOPING_ENFORCE=1` to make OVS drop DHCP server replies from non-gateway ports

Packet-capture retention notes:

- pcap capture is off by default for single scenarios, planned runs, and reliability campaigns
- runs use `ground-truth/trusted-observations.sqlite`, built from OVS snooping artifacts, as compact ARP/DNS/DHCP ground truth when pcaps are absent
- set `PCAP_ENABLE=1 PORT_PCAP_ENABLE=1` when you want full aggregate and per-port pcaps for a focused run
- guest pcaps and extra `tshark` summaries are off by default in the main and reliability plans
- planned runs also disable `iperf`, `curl` baseline diagnostics, and the post-attack settle tail by default unless explicitly re-enabled
- raw run files are pruned after each run unless `KEEP_DEBUG_ARTIFACTS=1`; use `make summarize` or `make results-db-overview` to read the SQLite result table
