# Experiment Report

Result source: `results/experiment-results.sqlite`

## Tables

- Reliability packet recall: `reliability-packet-recall.csv`
- Reliability detection survival: `reliability-detection-survival.csv`
- Reliability summary: `reliability-summary.csv`
- Basic scenario summary: `basic-scenario-summary.csv`

## Figures

- DNS packet recall by detector: `dns-packet-recall.png`
- DHCP packet recall by detector: `dhcp-packet-recall.png`
- Detection survival: `detection-survival.png`
- Detector processed pps: `detector-processed-pps.png`

## Notes

- ARP packet-level recall is intentionally excluded: OVS ARP counters prove attack presence, but their unit is a switch-level trust violation rather than a one-to-one semantic alert.
- DHCP untrusted-switch-port evidence is intentionally excluded from equal detector comparison because it uses OVS ingress-port context unavailable to Zeek and Suricata on the packet-only feed.
- Zeek and Suricata pps telemetry is intentionally not plotted because their pps values are derived from tool log/stat intervals and are not measured on the same packet-processing loop as Detector telemetry.
- Detector pps is shown only as detector telemetry, not as a cross-tool throughput comparison.

## Run Coverage

- ARP MITM + DNS: 0%=15, 10%=15, 20%=15, 30%=15, 40%=15, 50%=15, 60%=15, 70%=15, 80%=15, 90%=15, 100%=15
- DHCP spoof: 0%=15, 10%=15, 20%=15, 30%=15, 40%=15, 50%=15, 60%=15, 70%=15, 80%=15, 90%=15, 100%=15

## Basic Scenario Coverage

- Baseline: 3 runs
- ARP poison: 5 runs
- ARP MITM: 5 runs
- ARP MITM + DNS: 5 runs
- DHCP spoof: 5 runs
