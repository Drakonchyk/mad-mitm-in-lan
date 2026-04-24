# Artifact Map

This page maps generated artifacts to the parts of the thesis they are most useful for.

| Artifact | Thesis use |
| --- | --- |
| `run-meta.json` | experimental design, timing windows, scenario metadata |
| `summary.txt` | quick sanity check while collecting runs |
| `evaluation-summary.txt` | per-run interpretation and comparison snapshots |
| `evaluation.json` | machine-readable input for tables and plots |
| `detector/detector.delta.jsonl` | detector behavior analysis and semantic alert breakdown |
| `detector/detector-explained.txt` | illustrative narrative examples in the results chapter |
| `pcap/sensor.pcap` | switch-mirror packet truth for attack timing and packet-level validation |
| `pcap/wire-truth.json` | compact switch-truth counts, timings, and rates when full pcaps are pruned |
| `victim/traffic-window.txt` | latency and response-time analysis |
| `victim/iperf3.json` | throughput comparison |
| `zeek/host/` | Zeek comparator output from the mirrored switch sensor |
| `suricata/host/` | Suricata comparator output from the mirrored switch sensor |
| `pcap/` | switch-truth plus guest-side debugging captures |
| `results/experiment-report/` | main evaluation figures and tables |
| `results/demo-report/` | small deterministic sample-report set for demos and repo readers |

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
