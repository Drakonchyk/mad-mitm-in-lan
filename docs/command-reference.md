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
make reliability-arp-dns RUNS=3
make reliability-dhcp RUNS=3 LOSS_LEVELS="70 80 90 100"
```

Resume or trim a plan:

```bash
SKIP=2 make experiment-plan
START=11 make experiment-plan
SKIP_SCENARIO=arp-mitm-forward make experiment-plan
SCENARIOS="dhcp-spoof" RUNS=5 make experiment-plan
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

- The automation expects the apt-packaged Suricata binary. If Suricata is
  missing, it adds `ppa:oisf/suricata-stable` and installs `suricata`.
- Do not use the snap package for this lab.
- On some host builds, the ARP comparison rule path is unavailable even though DHCP+DNS+ICMP comparison still works.
- When that happens, the run summary prints `Suricata ARP coverage: ... DHCP+DNS+ICMP only`.

## Useful Environment Toggles

- `ZEEK_ENABLE=0`
- `SURICATA_ENABLE=0`
- `DEBUG=1` to retain raw run artifacts
- `PCAP=1` to enable the aggregate sensor pcap
- `PORT_PCAP=1` to enable per-switch-port pcaps
- `PORT_PCAP_ROLES="gateway victim attacker"` to choose which OVS/libvirt ports get individual pcaps
- `GUEST_PCAP=1` to enable guest-side pcaps
- `PCAP_SUMMARIES=1` to run pcap summaries
- `RUNS=5` for repeated main-plan runs
- `SCENARIOS="dhcp-spoof"` to restrict the main plan to one scenario
- `RUNS=3 make reliability` to run the thesis reliability set with three repetitions per loss level
- `LOSS_LEVELS="0 10 20"` to choose NetEm loss levels for reliability runs
- `DELAY_MS=20` / `JITTER_MS=5` / `RATE=1mbit` to add NetEm delay, jitter, or rate limits
- `TRAFFIC_PROBE_MODE=synthetic` for the default Scapy/UDP background probe, or `TRAFFIC_PROBE_MODE=legacy` for ping/dig-only background traffic
- `BASELINE_PERF_PROBES_ENABLE=1` to collect optional baseline `curl` and `iperf3` diagnostics
- `LAB_DHCP_SNOOPING_MODE=monitor` to count DHCP server replies from non-gateway ports without blocking them
- `LAB_DHCP_SNOOPING_MODE=enforce` to make OVS drop DHCP server replies from non-gateway ports

Packet-capture retention notes:

- pcap capture is off by default for single scenarios, planned runs, and reliability campaigns
- runs use `ground-truth/trusted-observations.sqlite`, built from OVS snooping artifacts, as compact ARP/DNS/DHCP ground truth when pcaps are absent
- set `PCAP=1 PORT_PCAP=1` when you want full aggregate and per-port pcaps for a focused run
- guest pcaps and extra `tshark` summaries are off by default in the main and reliability plans
- planned runs also disable `iperf`, `curl` baseline diagnostics, and the post-attack settle tail by default unless explicitly re-enabled
- raw run files are pruned after each run unless `DEBUG=1`; use `make summarize` or `make results-db-overview` to read the SQLite result table
