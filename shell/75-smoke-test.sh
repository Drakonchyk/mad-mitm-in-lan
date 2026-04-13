#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dangerous/common.sh"

SMOKE_DURATION_SECONDS="${SMOKE_DURATION_SECONDS:-15}"
SMOKE_CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT:-5000}"
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

  info "Running smoke scenario '${scenario_name}' for ${SMOKE_DURATION_SECONDS}s"
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="attacker" \
  ATTACK_JOB_LABEL="${attack_label}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT}" \
    "${SCRIPT_DIR}/80-record-manual-scenario.sh" "${scenario_name}" "${SMOKE_DURATION_SECONDS}" "${scenario_note}"
}

info "Starting smoke test for the isolated ${LAB_NAME} lab"
verify_isolated_lab
require_experiment_tools
start_lab_and_wait_for_access
prepare_attacker_research_workspace

info "Step 1/3: baseline"
CAPTURE_PACKET_COUNT="${SMOKE_CAPTURE_PACKET_COUNT}" "${SCRIPT_DIR}/70-run-baseline.sh"

info "Step 2/3: automated ARP MITM"
run_short_recording \
  "smoke-arp-mitm-auto" \
  "Smoke test: short automated ARP MITM run in isolated lab" \
  "smoke-arp-mitm-auto" \
  "cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding"

info "Step 3/3: automated ARP + DNS"
run_short_recording \
  "smoke-arp-mitm-dns-auto" \
  "Smoke test: short automated ARP plus DNS run in isolated lab" \
  "smoke-arp-mitm-dns-auto" \
  "cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding"

info "Smoke test finished. Review the newest directories under $(results_root)"
