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

## Direct Scenario Commands

```bash
make scenario-verify
make scenario-arp-poison-no-forward
make scenario-arp-mitm-forward
make scenario-arp-mitm-dns
make scenario-mitigation-recovery
make scenario-compare TARGET=results
```

## Live Capture

```bash
make demo-capture HOST=victim IFACE=vnic0 FILTER="arp or icmp or port 53"
make demo-capture HOST=gateway IFACE=any FILTER="arp or icmp or port 53"
```

## Useful Environment Toggles

- `ZEEK_ENABLE=1`
- `SURICATA_ENABLE=1`
- `PCAP_ENABLE=0`
- `KEEP_DEBUG_ARTIFACTS=1`
- `MAX_RUNS_PER_SCENARIO=1` for `make demo-report`
