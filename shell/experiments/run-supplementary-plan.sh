#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WARMUP_RUNS="${WARMUP_RUNS:-1}"
MEASURED_RUNS="${MEASURED_RUNS:-5}"
SUPPLEMENTARY_SCENARIOS="${SUPPLEMENTARY_SCENARIOS:-dhcp-starvation-rogue-dhcp}"
PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-none}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-1}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"
IPERF_ENABLE="${IPERF_ENABLE:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
DHCP_STARVATION_WORKERS="${DHCP_STARVATION_WORKERS:-1}"
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
  local post_cleanup_host="${15:-}"
  local post_cleanup_label="${16:-post-cleanup}"
  local post_cleanup_cmd="${17:-}"
  local post_cleanup_use_sudo="${18:-0}"

  info "Supplementary run: scenario=${scenario} run_index=${run_index} warmup=${warmup}"
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
  RUN_SLUG_SUFFIX="param-workers-${DHCP_STARVATION_WORKERS}" \
  DHCP_STARVATION_WORKERS="${DHCP_STARVATION_WORKERS}" \
  DETECTOR_PACKET_SAMPLE_RATE="${packet_sample_rate}" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

run_scenario() {
  local scenario="$1"
  local run_index="$2"
  local warmup="$3"

  case "${scenario}" in
    dhcp-starvation-rogue-dhcp)
      run_window \
        "dhcp-starvation-rogue-dhcp" \
        "90" \
        "Supplementary DHCP starvation followed by rogue DHCP replies to stress pool exhaustion plus attacker takeover" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "70" \
        "" \
        "0" \
        "0" \
        "" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 60 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval 0.2 --request-timeout 5.0 --workers ${DHCP_STARVATION_WORKERS}" \
        "sleep 30; cd '${REMOTE_ROOT}' && exec timeout -s INT 40 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0" \
        "1" \
        "gateway" \
        "dhcp-starvation-cleanup" \
        "python3 - '${DHCP_STARVATION_MAC_PREFIX,,}' <<'PY'
from pathlib import Path
import sys
prefix = sys.argv[1].lower()
changed = False
for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
    if not candidate.exists():
        continue
    kept = []
    for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
        parts = raw_line.split()
        if len(parts) >= 2 and parts[1].lower().startswith(prefix):
            changed = True
            continue
        kept.append(raw_line)
    if changed:
        candidate.write_text(('\\n'.join(kept) + '\\n') if kept else '', encoding='utf-8')
if changed:
    print(f'purged DHCP starvation leases for prefix {prefix}')
else:
    print(f'no DHCP starvation leases found for prefix {prefix}')
PY
systemctl restart dnsmasq" \
        "1"
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
