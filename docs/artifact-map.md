# Artifact Map

This page maps generated artifacts to the parts of the thesis they are most useful for.

| Artifact | Thesis use |
| --- | --- |
| `run-meta.json` | experimental design, timing windows, scenario metadata |
| `summary.txt` | quick sanity check while collecting runs |
| `evaluation-summary.txt` | per-run interpretation and comparison snapshots |
| `evaluation.json` | machine-readable input for tables and plots |
| `results/experiment-results.sqlite` | compact durable results table for runs, truth counts, sensor counts, trusted observations, and artifact references |
| `detector/detector.delta.jsonl` | detector behavior analysis and semantic alert breakdown |
| `detector/detector-explained.txt` | illustrative narrative examples in the results chapter |
| `pcap/sensor.pcap` | optional switch-mirror packet truth for attack timing and packet-level validation |
| `pcap/ports/*.pcap` | optional per-switch-port packet captures from the gateway, victim, and attacker OVS/libvirt interfaces |
| `pcap/port-map.json` | mapping from capture role to host interface and per-port pcap path |
| `pcap/wire-truth.json` | compact switch-truth counts, timings, and rates when full pcaps are pruned |
| `ground-truth/trusted-observations.sqlite` | trusted-source database for ARP/DNS/DHCP ground truth and sensor comparisons |
| `detector/ovs-switch-truth-snooping.txt` | compact OVS counters for ARP/DNS trust violations from non-gateway ports |
| `detector/ovs-dhcp-snooping.txt` | compact OVS counters for DHCP server replies from non-gateway ports |
| `gateway/dhcp-leases-before.json` | DHCP lease-pool state at the start of the run |
| `victim/traffic-window.txt` | synthetic ICMP/DNS background traffic summary, or legacy ping/dig probe output |
| `victim/iperf3.json` | optional throughput comparison when `IPERF_ENABLE=1` or baseline performance probes are enabled |
| `zeek/host/` | Zeek comparator output from the mirrored switch sensor |
| `suricata/host/` | Suricata comparator output from the mirrored switch sensor |
| `pcap/` | switch-truth plus guest-side debugging captures |
| `results/experiment-report/` | main evaluation figures and tables |

## Suggested Chapter Mapping

- methodology:
  - `docs/experiments.md`
  - `docs/scenario-definitions.md`
  - `run-meta.json`
- implementation:
  - `docs/topology.md`
  - `docs/repo-architecture.md`
  - detector and orchestration source files
- main results:
  - `results/experiment-report/`
- supplementary comparison:
  - `results/experiment-report/`
- appendix / reproducibility:
  - `docs/evaluation-metrics.md`
  - `docs/artifact-map.md`
  - `docs/command-reference.md`
