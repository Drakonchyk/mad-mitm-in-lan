# Repo Architecture

This page explains how the repository is split so a new reader can find the right layer quickly.

## Top-Level Structure

- `Makefile`
  - thin root entry point that includes grouped make fragments from `mk/`
- `mk/`
  - target groups for help, lab lifecycle, experiments, reports, and scenarios
- `shell/`
  - host-side orchestration scripts
- `python/`
  - detector code, attacker-side research helpers, and analysis packages
- `docs/`
  - topology, scenario, metrics, command, and artifact reference pages
- `config/`, `libvirt/`
  - static configuration inputs
- `results/`
  - per-run artifacts and generated reports

## Shell Layout

The shell side is now grouped by responsibility instead of historical numbering.

### `shell/lab/`

Infrastructure lifecycle for the libvirt testbed:

- `host-prereqs.sh`
- `define-networks.sh`
- `prepare-storage.sh`
- `build-cloud-init.sh`
- `create-vms.sh`
- `start-lab.sh`
- `status.sh`
- `destroy-lab.sh`
- `setup-lab.sh`

### `shell/experiments/`

Experiment orchestration and timed recording:

- `run-baseline.sh`
- `run-scenario-window.sh`
- `run-experiment-plan.sh`
- `run-reliability-plan.sh`
- `smoke-test.sh`

### `shell/scenarios/`

Direct automated scenario wrappers used for focused runs:

- `record-arp-poison-no-forward.sh`
- `record-arp-mitm-forward.sh`
- `record-arp-mitm-dns.sh`
- `record-dhcp-spoof.sh`
- `record-reliability-arp-mitm-dns.sh`
- `record-reliability-dhcp-spoof.sh`
- `verify-isolated-lab.sh`
- `compare-runs.sh`
- `common.sh`

### `shell/tools/`

Small operator helpers:

- `open-live-capture.sh`

### Shared Shell Libraries

- `shell/common.sh`
  - repo-wide shell helpers, lab paths, and config loading
- `shell/experiment-common.sh`
  - the main experiment orchestration library used by baseline and scenario runners

## Python Layout

The Python code is split into packages that match the main project concerns.

### `python/lab/`

Host-side Python helpers used by shell orchestration:

- `templates.py`
  - renders detector and Zeek configs from repo templates
- `cli.py`
  - small module entry point for shell-friendly helper commands

### `python/scenarios/`

Scenario metadata in one place:

- `definitions.py`
  - scenario labels, ordering, supported detector events, and attack-type mappings

### `python/metrics/`

Run parsing and evaluation logic:

- `run_artifacts.py`
  - generic loaders and per-run parsing helpers
- `primitives.py`
  - reusable metric and plotting primitives
- `evaluator.py`
  - per-run evaluation, cache handling, and aggregate detection summaries
- `summary_cli.py`
  - lightweight run summary command used by `make summarize`

### `python/reporting/`

Report generation is database-first. `make experiment-report` reads
`results/experiment-results.sqlite` and regenerates the thesis-facing CSVs,
figures, and markdown index.

- `db_report.py`
  - SQLite-backed report tables, plots, and markdown index
- `dataset.py`
  - report-output cleanup helper
- `plots.py`
  - shared Matplotlib style helpers used by the database report
- `cli.py`
  - module entry point used by `make experiment-report`

### `python/detector/`

Detector runtime code:

- `live.py`
  - the deployed detector runtime used on the mirrored switch sensor port

### `python/mitm/`

Attacker-side research code:

- `attacks.py`
  - ARP poisoning, DNS spoofing, and DHCP-spoofing primitives
- `research.py`
  - lab-scoped runner that builds attack helpers safely
- `cli.py`
  - module entry point used by the attacker automation commands

### `python/logs/`

Run-interpretation helpers for captured artifacts:

- `explain_run.py`
- `zeek_notice.py`
- `suricata_eve.py`

### Other Python Files

The remaining top-level Python package directories mainly hold the analysis and orchestration layers already described above, so there is no longer a large pile of unrelated standalone scripts at the package root.

## Command Flow

A typical full workflow looks like this:

1. `make setup`
   - provisions networks, storage, guests, and cloud-init artifacts
2. `make experiment-plan` or `make reliability RUNS=3`
   - runs timed scenario windows and stores artifacts under `results/`
3. `make experiment-report`
   - builds dataset exports, figures, tables, and the markdown report from all retained runs
4. `results/experiment-report/`
   - holds the generated outputs

The generated markdown report now includes run coverage, reliability summaries, and thesis-facing figure references directly, so the normal analysis path does not depend on a separate top-level evaluation make target.

## Reading Order

If someone is new to the repo, this order usually gives the clearest picture:

1. `README.md`
2. `docs/topology.md`
3. `docs/scenario-definitions.md`
4. `docs/experiments.md`
5. `docs/evaluation-metrics.md`
6. `Makefile`
7. `shell/experiments/run-experiment-plan.sh`
8. `python/reporting/cli.py`
9. `python/metrics/evaluator.py`
10. `python/mitm/cli.py`
