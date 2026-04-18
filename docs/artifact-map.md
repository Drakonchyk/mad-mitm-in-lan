# Artifact Map

This page maps generated artifacts to the parts of the thesis they are most useful for.

| Artifact | Thesis use |
| --- | --- |
| `run-meta.json` | experimental design, timing windows, scenario metadata |
| `summary.txt` | quick sanity check while collecting runs |
| `evaluation-summary.txt` | per-run interpretation and comparison snapshots |
| `evaluation.json` | machine-readable input for tables and plots |
| `victim/detector.delta.jsonl` | detector behavior analysis and semantic alert breakdown |
| `victim/detector-explained.txt` | illustrative narrative examples in the results chapter |
| `victim/traffic-window.txt` | latency and response-time analysis |
| `victim/iperf3.json` | throughput comparison |
| `zeek/` | comparator section for Zeek |
| `suricata/` | comparator section for Suricata |
| `pcap/` | packet-level validation and debugging appendix |
| `results/experiment-report/` | main evaluation figures and tables |
| `results/experiment-report-extra/` | supplementary evaluation figures and tables |
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
  - `results/experiment-report-extra/`
- appendix / reproducibility:
  - `docs/evaluation-metrics.md`
  - `docs/artifact-map.md`
  - `docs/command-reference.md`
