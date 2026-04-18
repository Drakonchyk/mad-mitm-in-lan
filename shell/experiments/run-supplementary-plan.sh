#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WARMUP_RUNS="${WARMUP_RUNS:-1}"
MEASURED_RUNS="${MEASURED_RUNS:-5}"
SUPPLEMENTARY_SCENARIOS="${SUPPLEMENTARY_SCENARIOS:-intermittent-arp-mitm-dns noisy-benign-baseline reduced-observability}"
REMOTE_ROOT="$(research_workspace_root)"
PLAN_SKIP_RUNS=0
PLAN_START_RUN=1
PLAN_START_SCENARIO=""
PLAN_SKIP_SCENARIOS=()

usage() {
  cat <<'EOF'
Usage: ./shell/experiments/run-supplementary-plan.sh [options]

Options:
  --skip N                  Skip the first N planned run windows
  --start N                 Start from the Nth planned run window (1-based)
  --start-scenario NAME     Start when NAME is reached in SUPPLEMENTARY_SCENARIOS
  --skip-scenario NAME      Exclude NAME from the planned scenarios (repeatable)
  --help                    Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip)
      PLAN_SKIP_RUNS="${2:?missing value for --skip}"
      shift 2
      ;;
    --start)
      PLAN_START_RUN="${2:?missing value for --start}"
      shift 2
      ;;
    --start-scenario)
      PLAN_START_SCENARIO="${2:?missing value for --start-scenario}"
      shift 2
      ;;
    --skip-scenario)
      PLAN_SKIP_SCENARIOS+=("${2:?missing value for --skip-scenario}")
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      warn "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if ! [[ "${PLAN_SKIP_RUNS}" =~ ^[0-9]+$ ]] || ! [[ "${PLAN_START_RUN}" =~ ^[0-9]+$ ]] || (( PLAN_START_RUN < 1 )); then
  warn "--skip must be >= 0 and --start must be >= 1"
  exit 1
fi

START_AT_RUN_INDEX=$((PLAN_START_RUN + PLAN_SKIP_RUNS))

require_experiment_tools
mkdir -p "$(results_root)"
start_lab_and_wait_for_access
prepare_attacker_research_workspace

run_window() {
  local scenario="$1"
  local duration="$2"
  local note="$3"
  local run_index="$4"
  local warmup="$5"
  local attack_start_offset="$6"
  local attack_stop_offset="$7"
  local mitigation_offset="$8"
  local forwarding_enabled="$9"
  local dns_spoof_enabled="${10}"
  local spoofed_domains="${11}"
  local attack_cmd="${12}"
  local aux_cmd="${13}"
  local packet_sample_rate="${14}"

  info "Supplementary run: scenario=${scenario} run_index=${run_index} warmup=${warmup}"
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="${ATTACK_JOB_HOST_OVERRIDE:-attacker}" \
  ATTACK_JOB_LABEL="${scenario}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  AUX_JOB_HOST="${AUX_JOB_HOST_OVERRIDE:-victim}" \
  AUX_JOB_LABEL="${scenario}-aux" \
  AUX_JOB_CMD="${aux_cmd}" \
  PLAN_RUN_INDEX="${run_index}" \
  PLAN_WARMUP="${warmup}" \
  PLAN_DURATION_SECONDS="${duration}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${attack_start_offset}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="${attack_stop_offset}" \
  PLAN_MITIGATION_START_OFFSET_SECONDS="${mitigation_offset}" \
  PLAN_FORWARDING_ENABLED="${forwarding_enabled}" \
  PLAN_DNS_SPOOF_ENABLED="${dns_spoof_enabled}" \
  PLAN_SPOOFED_DOMAINS="${spoofed_domains}" \
  DETECTOR_PACKET_SAMPLE_RATE="${packet_sample_rate}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

run_scenario() {
  local scenario="$1"
  local run_index="$2"
  local warmup="$3"

  case "${scenario}" in
    intermittent-arp-mitm-dns)
      run_window \
        "intermittent-arp-mitm-dns" \
        "90" \
        "Supplementary pulsed ARP MITM with focused DNS spoofing for iana.org" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "60" \
        "" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 10; cd '${REMOTE_ROOT}' && for pulse in 1 2 3 4; do timeout -s INT 5 sudo env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org || true; if [[ \"\$pulse\" -lt 4 ]]; then sleep 10; fi; done" \
        "" \
        "1"
      ;;
    noisy-benign-baseline)
      run_window \
        "noisy-benign-baseline" \
        "90" \
        "Supplementary benign LAN churn with neighbor refreshes and extra DNS traffic" \
        "${run_index}" \
        "${warmup}" \
        "" \
        "" \
        "" \
        "0" \
        "0" \
        "" \
        "" \
        "sleep 10; end=\$(( \$(date +%s) + 50 )); while [[ \$(date +%s) -lt \"\$end\" ]]; do sudo ip neigh del '${GATEWAY_IP}' dev vnic0 2>/dev/null || true; ping -c 1 -W 1 '${GATEWAY_IP}' >/dev/null 2>&1 || true; for domain in ${DETECTOR_DOMAINS}; do dig +time=1 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}' >/dev/null 2>&1 || true; done; curl -sS -o /dev/null https://example.com || true; sleep 8; done" \
        "1"
      ;;
    reduced-observability)
      run_window \
        "reduced-observability" \
        "90" \
        "Supplementary ARP MITM with focused DNS spoofing while the detector samples only part of the observed traffic" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "70" \
        "" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 60 sudo env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org" \
        "" \
        "0.25"
      ;;
    *)
      warn "Unknown supplementary scenario: ${scenario}"
      return 1
      ;;
  esac
}

scenario_selected() {
  local scenario="$1"
  local skipped

  for skipped in "${PLAN_SKIP_SCENARIOS[@]}"; do
    if [[ "${scenario}" == "${skipped}" ]]; then
      return 1
    fi
  done
  return 0
}

started=0
planned_run=0

for scenario in ${SUPPLEMENTARY_SCENARIOS}; do
  if ! scenario_selected "${scenario}"; then
    info "Skipping supplementary scenario=${scenario} because it was excluded by --skip-scenario"
    continue
  fi

  if [[ -n "${PLAN_START_SCENARIO}" && "${started}" -eq 0 ]]; then
    if [[ "${scenario}" != "${PLAN_START_SCENARIO}" ]]; then
      info "Skipping supplementary scenario=${scenario} until start scenario ${PLAN_START_SCENARIO} is reached"
      continue
    fi
    started=1
  fi

  for ((run = 1; run <= WARMUP_RUNS; run++)); do
    planned_run=$((planned_run + 1))
    if (( planned_run < START_AT_RUN_INDEX )); then
      info "Skipping supplementary planned run #${planned_run}: scenario=${scenario} run_index=${run} warmup=1"
      continue
    fi
    run_scenario "${scenario}" "${run}" "1"
  done
  for ((run = 1; run <= MEASURED_RUNS; run++)); do
    planned_run=$((planned_run + 1))
    if (( planned_run < START_AT_RUN_INDEX )); then
      info "Skipping supplementary planned run #${planned_run}: scenario=${scenario} run_index=${run} warmup=0"
      continue
    fi
    run_scenario "${scenario}" "${run}" "0"
  done
done

if [[ -n "${PLAN_START_SCENARIO}" && "${started}" -eq 0 ]]; then
  warn "Requested supplementary start scenario '${PLAN_START_SCENARIO}' was not found in the selected plan"
  exit 1
fi

info "Supplementary experiment execution finished. Review $(results_root)"
