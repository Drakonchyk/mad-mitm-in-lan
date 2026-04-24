#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scenarios/common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SMOKE_DURATION_SECONDS="${SMOKE_DURATION_SECONDS:-30}"
SMOKE_CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT:-0}"
SMOKE_KEEP_DEBUG_ARTIFACTS="${SMOKE_KEEP_DEBUG_ARTIFACTS:-1}"
SMOKE_IPERF_ENABLE="${SMOKE_IPERF_ENABLE:-0}"
REMOTE_ROOT="$(research_workspace_root)"

if (( SMOKE_DURATION_SECONDS < 8 )); then
  warn "SMOKE_DURATION_SECONDS=${SMOKE_DURATION_SECONDS} is too short for reliable attack validation; using 8s instead"
  SMOKE_DURATION_SECONDS=8
fi

run_short_recording() {
  local scenario_name="$1"
  local scenario_note="$2"
  local attack_label="$3"
  local attack_cmd="$4"
  local plan_forwarding_enabled="${5:-0}"
  local plan_dns_spoof_enabled="${6:-0}"
  local plan_spoofed_domains="${7:-}"

  info "Running smoke scenario '${scenario_name}' for ${SMOKE_DURATION_SECONDS}s"
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="attacker" \
  ATTACK_JOB_LABEL="${attack_label}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  PLAN_DURATION_SECONDS="${SMOKE_DURATION_SECONDS}" \
  PLAN_FORWARDING_ENABLED="${plan_forwarding_enabled}" \
  PLAN_DNS_SPOOF_ENABLED="${plan_dns_spoof_enabled}" \
  PLAN_SPOOFED_DOMAINS="${plan_spoofed_domains}" \
  CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT}" \
  KEEP_DEBUG_ARTIFACTS="${SMOKE_KEEP_DEBUG_ARTIFACTS}" \
  IPERF_ENABLE="${SMOKE_IPERF_ENABLE}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario_name}" "${SMOKE_DURATION_SECONDS}" "${scenario_note}"
}

latest_run_dir() {
  ls -1dt "$(results_root)"/20* 2>/dev/null | head -n 1
}

validate_run() {
  local scenario="$1"
  local expectation="$2"
  local run_dir

  run_dir="$(latest_run_dir)"
  [[ -n "${run_dir}" ]] || {
    warn "Smoke validation could not find any run directory"
    return 1
  }

  python3 - "${run_dir}" "${scenario}" "${expectation}" <<'PY'
from pathlib import Path
import json
import sys

run_dir = Path(sys.argv[1])
scenario = sys.argv[2]
expectation = sys.argv[3]
evaluation = json.loads((run_dir / "evaluation.json").read_text(encoding="utf-8"))

if evaluation.get("scenario") != scenario:
    raise SystemExit(f"latest run is {evaluation.get('scenario')}, expected {scenario}")

detector = int(evaluation.get("detector_alert_events", 0) or 0)
zeek = int(evaluation.get("zeek_alert_events", 0) or 0)
suricata = int(evaluation.get("suricata_alert_events", 0) or 0)
truth = int(evaluation.get("ground_truth_attack_events", 0) or 0)

if expectation == "baseline":
    if detector != 0 or zeek != 0 or suricata != 0:
        raise SystemExit(
            f"baseline produced alerts unexpectedly: detector={detector} zeek={zeek} suricata={suricata}"
        )
elif expectation == "attack":
    if truth <= 0:
        raise SystemExit(
            f"attack run did not produce ground-truth attack events; detector={detector} zeek={zeek} suricata={suricata}"
        )
    if detector <= 0 and zeek <= 0 and suricata <= 0:
        raise SystemExit(
            f"attack run produced no alerts from detector or comparators; truth={truth}"
        )
else:
    raise SystemExit(f"unknown expectation {expectation}")
PY
}

info "Starting smoke test for the isolated ${LAB_NAME} lab"
require_experiment_tools
start_lab_and_wait_for_access
verify_isolated_lab
prepare_attacker_research_workspace

info "Step 1/3: baseline"
CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT}" \
KEEP_DEBUG_ARTIFACTS="${SMOKE_KEEP_DEBUG_ARTIFACTS}" \
IPERF_ENABLE="${SMOKE_IPERF_ENABLE}" \
  "${EXPERIMENT_SCRIPT_DIR}/run-baseline.sh"
validate_run "baseline" "baseline"

info "Step 2/3: automated ARP MITM"
run_short_recording \
  "smoke-arp-mitm-auto" \
  "Smoke test: short automated ARP MITM run in isolated lab" \
  "smoke-arp-mitm-auto" \
  "cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding" \
  "1" \
  "0"
validate_run "smoke-arp-mitm-auto" "attack"

info "Step 3/3: automated ARP + DNS"
run_short_recording \
  "smoke-arp-mitm-dns-auto" \
  "Smoke test: short automated ARP plus DNS run in isolated lab" \
  "smoke-arp-mitm-dns-auto" \
  "cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding" \
  "1" \
  "1" \
  "example.com example.org iana.org"
validate_run "smoke-arp-mitm-dns-auto" "attack"

info "Smoke test finished. Review the newest directories under $(results_root)"
