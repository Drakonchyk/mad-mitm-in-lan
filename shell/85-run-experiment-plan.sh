#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/experiment-common.sh"

WARMUP_RUNS="${WARMUP_RUNS:-1}"
MEASURED_RUNS="${MEASURED_RUNS:-10}"
PLAN_SCENARIOS="${PLAN_SCENARIOS:-baseline arp-poison-no-forward arp-mitm-forward arp-mitm-dns mitigation-recovery}"
REMOTE_ROOT="$(research_workspace_root)"

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

  info "Planned run: scenario=${scenario} run_index=${run_index} warmup=${warmup}"
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
    "${SCRIPT_DIR}/80-record-manual-scenario.sh" "${scenario}" "${duration}" "${note}"
}

run_scenario() {
  local scenario="$1"
  local run_index="$2"
  local warmup="$3"

  case "${scenario}" in
    baseline)
      run_window \
        "baseline" \
        "90" \
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
        "90" \
        "Planned ARP poisoning without forwarding" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "70" \
        "" \
        "0" \
        "0" \
        "" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 60 sudo python3 ./python/setup_all.py --config ./lab.conf arp-poison --interface vnic0" \
        ""
      ;;
    arp-mitm-forward)
      run_window \
        "arp-mitm-forward" \
        "90" \
        "Planned ARP MITM with forwarding enabled" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "70" \
        "" \
        "1" \
        "0" \
        "" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 60 sudo python3 ./python/setup_all.py --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding" \
        ""
      ;;
    arp-mitm-dns)
      run_window \
        "arp-mitm-dns" \
        "90" \
        "Planned ARP MITM with forwarding plus focused DNS spoofing for iana.org" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "70" \
        "" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 60 sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org" \
        ""
      ;;
    mitigation-recovery)
      run_window \
        "mitigation-recovery" \
        "120" \
        "Planned mitigation and recovery run with ARP MITM plus DNS spoofing followed by victim-side restoration" \
        "${run_index}" \
        "${warmup}" \
        "10" \
        "45" \
        "45" \
        "1" \
        "1" \
        "iana.org" \
        "sleep 10; cd '${REMOTE_ROOT}' && exec timeout -s INT 35 sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org" \
        "sleep 45; sudo ip neigh replace '${GATEWAY_IP}' lladdr '${GATEWAY_LAB_MAC}' nud permanent dev vnic0"
      ;;
    *)
      warn "Unknown planned scenario: ${scenario}"
      return 1
      ;;
  esac
}

for scenario in ${PLAN_SCENARIOS}; do
  for ((run = 1; run <= WARMUP_RUNS; run++)); do
    run_scenario "${scenario}" "${run}" "1"
  done
  for ((run = 1; run <= MEASURED_RUNS; run++)); do
    run_scenario "${scenario}" "${run}" "0"
  done
done

info "Experiment plan execution finished. Review $(results_root)"
