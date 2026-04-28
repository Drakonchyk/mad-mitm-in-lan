# SQLite Experiment Report

Source database: `results/experiment-results.sqlite`

## Figures

- DNS packet recall by detector: `figure-db-02a-dns-packet-recall-by-detector.png`
- DHCP packet recall by detector: `figure-db-02b-dhcp-packet-recall-by-detector.png`
- Detection survival: `figure-db-03-detection-survival.png`
- Time to detection: `figure-db-04-time-to-detection.png`
- Detector processed pps: `figure-db-05-detector-processed-pps.png`
- Basic scenario mean time to first detection: `figure-db-07-basic-scenario-ttd-heatmap.png`
- Normal scenario attack-type time to first alert: `figure-db-09-normal-scenario-attack-ttd-heatmap.png`

## Notes

- ARP packet-level recall is intentionally excluded: OVS ARP counters prove attack presence, but their unit is a switch-level trust violation rather than a one-to-one semantic alert.
- DHCP untrusted-switch-port evidence is intentionally excluded from equal detector comparison because it uses OVS ingress-port context unavailable to Zeek and Suricata on the packet-only feed.
- Zeek and Suricata pps telemetry is intentionally not plotted because their pps values are derived from tool log/stat intervals and are not measured on the same packet-processing loop as Detector telemetry.
- Detector pps is shown only as detector telemetry, not as a cross-tool throughput comparison.

## Run Coverage

- ARP MITM + DNS: 0%=15, 10%=15, 20%=15, 30%=15, 40%=15, 50%=15, 60%=15, 70%=15, 80%=15, 90%=15, 100%=15
- Rogue DHCP: 0%=15, 10%=15, 20%=15, 30%=15, 40%=15, 50%=15, 60%=15, 70%=15, 80%=15, 90%=15, 100%=15

## Basic Scenario TTD Coverage

- ARP poison: 1 runs
- ARP MITM: 1 runs
- ARP MITM + DNS: 1 runs
- Rogue DHCP: 1 runs
