#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WARMUP_RUNS="${WARMUP_RUNS:-0}"
MEASURED_RUNS="${MEASURED_RUNS:-${RUNS:-1}}"
PLAN_SCENARIOS="${PLAN_SCENARIOS:-arp-poison-no-forward arp-mitm-forward arp-mitm-dns dhcp-spoof}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-0}"
PORT_PCAP_ENABLE="${USER_PORT_PCAP_ENABLE:-0}"
if [[ -n "${USER_PCAP_RETENTION_POLICY}" ]]; then
  PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY}"
elif [[ "${PCAP_ENABLE}" == "1" ]]; then
  PCAP_RETENTION_POLICY="all"
else
  PCAP_RETENTION_POLICY="none"
fi
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"
IPERF_ENABLE="${IPERF_ENABLE:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-2}"
REMOTE_ROOT="$(research_workspace_root)"
PLAN_SKIP_RUNS=0
PLAN_START_RUN=1
PLAN_START_SCENARIO=""
PLAN_SKIP_SCENARIOS=()

usage() {
  cat <<'EOF'
Usage: ./shell/experiments/run-experiment-plan.sh [options]

Options:
  --skip N                  Skip the first N planned run windows
  --start N                 Start from the Nth planned run window (1-based)
  --start-scenario NAME     Start when NAME is reached in PLAN_SCENARIOS
  --skip-scenario NAME      Exclude NAME from the planned scenarios (repeatable)
  --runs N                  Measured runs per scenario (default: 1)
  --warmups N               Warmup runs per scenario (default: 0)
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
    --runs|--measured-runs)
      MEASURED_RUNS="${2:?missing value for --runs}"
      shift 2
      ;;
    --warmups|--warmup-runs)
      WARMUP_RUNS="${2:?missing value for --warmups}"
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

if ! [[ "${PLAN_SKIP_RUNS}" =~ ^[0-9]+$ ]] \
  || ! [[ "${PLAN_START_RUN}" =~ ^[0-9]+$ ]] \
  || ! [[ "${WARMUP_RUNS}" =~ ^[0-9]+$ ]] \
  || ! [[ "${MEASURED_RUNS}" =~ ^[0-9]+$ ]] \
  || (( PLAN_START_RUN < 1 )) \
  || (( MEASURED_RUNS < 1 )); then
  warn "--skip and --warmups must be >= 0; --start and --runs must be >= 1"
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
  local post_cleanup_host="${14:-}"
  local post_cleanup_label="${15:-post-cleanup}"
  local post_cleanup_cmd="${16:-}"
  local post_cleanup_use_sudo="${17:-0}"
  local run_slug_suffix=""

  info "Planned run: scenario=${scenario} run_index=${run_index} warmup=${warmup}"
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="${ATTACK_JOB_HOST_OVERRIDE:-attacker}" \
  ATTACK_JOB_LABEL="${scenario}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  AUX_JOB_HOST="${AUX_JOB_HOST_OVERRIDE:-victim}" \
  AUX_JOB_LABEL="${scenario}-aux" \
  AUX_JOB_CMD="${aux_cmd}" \
  AUX_JOB_USE_SUDO="$([[ -n "${aux_cmd}" ]] && printf '1' || printf '0')" \
  POST_CLEANUP_HOST="${post_cleanup_host}" \
  POST_CLEANUP_LABEL="${post_cleanup_label}" \
  POST_CLEANUP_CMD="${post_cleanup_cmd}" \
  POST_CLEANUP_USE_SUDO="${post_cleanup_use_sudo}" \
  PLAN_RUN_INDEX="${run_index}" \
  PLAN_WARMUP="${warmup}" \
  PLAN_DURATION_SECONDS="${duration}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${attack_start_offset}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="${attack_stop_offset}" \
  PLAN_MITIGATION_START_OFFSET_SECONDS="${mitigation_offset}" \
  PLAN_FORWARDING_ENABLED="${forwarding_enabled}" \
  PLAN_DNS_SPOOF_ENABLED="${dns_spoof_enabled}" \
  PLAN_SPOOFED_DOMAINS="${spoofed_domains}" \
  RUN_SLUG_SUFFIX="${run_slug_suffix}" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
  DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

run_scenario() {
  local scenario="$1"
  local run_index="$2"
  local warmup="$3"

  case "${scenario}" in
    baseline)
      run_window \
        "baseline" \
        "20" \
        "Planned baseline run for the diploma experiment set" \
        "${run_index}" \
        "${warmup}" \
        "" \
        "" \
        "" \
        "0" \
        "0" \
        "" \
        "" \
        ""
      ;;
    arp-poison-no-forward)
      run_window \
        "arp-poison-no-forward" \
        "30" \
        "Planned ARP poisoning without forwarding" \
        "${run_index}" \
        "${warmup}" \
        "5" \
        "25" \
        "" \
        "0" \
        "0" \
        "" \
        "sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT 20 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0" \
        ""
      ;;
    arp-mitm-forward)
      run_window \
        "arp-mitm-forward" \
        "30" \
        "Planned ARP MITM with forwarding enabled" \
        "${run_index}" \
        "${warmup}" \
        "5" \
        "25" \
        "" \
        "1" \
        "0" \
        "" \
        "sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT 20 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding" \
        ""
      ;;
    arp-mitm-dns)
      run_window \
        "arp-mitm-dns" \
        "45" \
        "Planned ARP MITM with forwarding plus focused DNS spoofing for iana.org" \
        "${run_index}" \
        "${warmup}" \
        "5" \
        "35" \
        "" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT 30 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org" \
        ""
      ;;
    dhcp-spoof)
      run_window \
        "dhcp-spoof" \
        "30" \
        "Planned rogue DHCP offer and ACK broadcast run" \
        "${run_index}" \
        "${warmup}" \
        "5" \
        "25" \
        "" \
        "0" \
        "0" \
        "" \
        "sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT 20 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 1.0" \
        ""
      ;;
    mitigation-recovery)
      run_window \
        "mitigation-recovery" \
        "60" \
        "Planned mitigation and recovery run with ARP MITM plus DNS spoofing followed by victim-side restoration" \
        "${run_index}" \
        "${warmup}" \
        "5" \
        "30" \
        "30" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT 25 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org" \
        "sleep 30; ip neigh replace '${GATEWAY_IP}' lladdr '${GATEWAY_LAB_MAC}' nud permanent dev vnic0"
      ;;
    *)
      warn "Unknown planned scenario: ${scenario}"
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

for scenario in ${PLAN_SCENARIOS}; do
  if ! scenario_selected "${scenario}"; then
    info "Skipping scenario=${scenario} because it was excluded by --skip-scenario"
    continue
  fi

  if [[ -n "${PLAN_START_SCENARIO}" && "${started}" -eq 0 ]]; then
    if [[ "${scenario}" != "${PLAN_START_SCENARIO}" ]]; then
      info "Skipping scenario=${scenario} until start scenario ${PLAN_START_SCENARIO} is reached"
      continue
    fi
    started=1
  fi

  for ((run = 1; run <= WARMUP_RUNS; run++)); do
    planned_run=$((planned_run + 1))
    if (( planned_run < START_AT_RUN_INDEX )); then
      info "Skipping planned run #${planned_run}: scenario=${scenario} run_index=${run} warmup=1"
      continue
    fi
    run_scenario "${scenario}" "${run}" "1"
  done
  for ((run = 1; run <= MEASURED_RUNS; run++)); do
    planned_run=$((planned_run + 1))
    if (( planned_run < START_AT_RUN_INDEX )); then
      info "Skipping planned run #${planned_run}: scenario=${scenario} run_index=${run} warmup=0"
      continue
    fi
    run_scenario "${scenario}" "${run}" "0"
  done
done

if [[ -n "${PLAN_START_SCENARIO}" && "${started}" -eq 0 ]]; then
  warn "Requested start scenario '${PLAN_START_SCENARIO}' was not found in the selected plan"
  exit 1
fi

info "Experiment plan execution finished. Review $(results_root)"
