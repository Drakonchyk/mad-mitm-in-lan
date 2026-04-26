#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAMILIES="${FAMILIES:-arp-mitm-dns dhcp-spoof}"
COARSE_VISIBILITY_LEVELS="${COARSE_VISIBILITY_LEVELS:-100 90 80 70 60 50 40 30 20 10}"
FINE_VISIBILITY_MIN="${FINE_VISIBILITY_MIN:-0}"
STOP_AFTER_ALL_MISS="${STOP_AFTER_ALL_MISS:-1}"
FINE_VISIBILITY_ENABLE="${FINE_VISIBILITY_ENABLE:-1}"
PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-first-run-per-scenario}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-1}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"
IPERF_ENABLE="${IPERF_ENABLE:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE:-0}"
REPORT_ENABLE="${REPORT_ENABLE:-0}"

usage() {
  cat <<'EOF'
Usage: ./shell/experiments/run-visibility-plan.sh

Environment:
  FAMILIES="arp-mitm-dns dhcp-spoof"
  COARSE_VISIBILITY_LEVELS="100 90 80 70 60 50 40 30 20 10"
  FINE_VISIBILITY_MIN=0
  FINE_VISIBILITY_ENABLE=1
  STOP_AFTER_ALL_MISS=1
  RUN_SUMMARY_ENABLE=0
  REPORT_ENABLE=0

The plan keeps one full switch pcap per scenario by default and uses compact
wire-truth summaries for the rest while Detector, Zeek, and Suricata listen on
a live sampled sensor feed.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_experiment_tools
mkdir -p "$(results_root)"
start_lab_and_wait_for_access
prepare_attacker_research_workspace

latest_run_for() {
  local scenario="$1"
  find "$(results_root)" -maxdepth 1 -type d \( -name "*-${scenario}" -o -name "*-${scenario}-*" \) -printf '%T@ %p\n' \
    | sort -nr \
    | awk 'NR==1 {print $2}'
}

run_visibility_family() {
  local family="$1"
  local visibility="$2"
  local remote_root attack_cmd scenario duration note attack_start attack_stop forwarding dns_spoof domains

  remote_root="$(research_workspace_root)"
  case "${family}" in
    arp-mitm-dns)
      scenario="visibility-arp-mitm-dns"
      duration="90"
      note="Visibility degradation run: ARP MITM with focused DNS spoofing while all sensors receive ${visibility}% of mirrored packets"
      attack_start="10"
      attack_stop="70"
      forwarding="1"
      dns_spoof="1"
      domains="iana.org"
      attack_cmd="sleep 10; cd '${remote_root}' && exec timeout -s INT 60 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"
      ;;
    dhcp-spoof)
      scenario="visibility-dhcp-spoof"
      duration="60"
      note="Visibility degradation run: rogue DHCP spoofing while all sensors receive ${visibility}% of mirrored packets"
      attack_start="10"
      attack_stop="50"
      forwarding="0"
      dns_spoof="0"
      domains=""
      attack_cmd="sleep 10; cd '${remote_root}' && exec timeout -s INT 40 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0"
      ;;
    *)
      warn "Unknown visibility family: ${family}"
      return 1
      ;;
  esac

  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="${ATTACK_JOB_HOST_OVERRIDE:-attacker}" \
  ATTACK_JOB_LABEL="${scenario}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  PLAN_RUN_INDEX="${visibility}" \
  PLAN_WARMUP="0" \
  PLAN_DURATION_SECONDS="${duration}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${attack_start}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="${attack_stop}" \
  PLAN_FORWARDING_ENABLED="${forwarding}" \
  PLAN_DNS_SPOOF_ENABLED="${dns_spoof}" \
  PLAN_SPOOFED_DOMAINS="${domains}" \
  RUN_SLUG_SUFFIX="param-visibility-${visibility}pct" \
  SENSOR_VISIBILITY_PERCENT="${visibility}" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
  RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

latest_visibility_run_for() {
  local family="$1"
  case "${family}" in
    arp-mitm-dns)
      latest_run_for "visibility-arp-mitm-dns"
      ;;
    dhcp-spoof)
      latest_run_for "visibility-dhcp-spoof"
      ;;
  esac
}

evaluate_latest_visibility() {
  local family="$1"
  local run_dir

  run_dir="$(latest_visibility_run_for "${family}")"
  if [[ -z "${run_dir}" ]]; then
    warn "Could not find newest visibility run for ${family}"
    return 1
  fi

  PYTHONPATH=./python python3 - "${run_dir}" <<'PY'
import json
import sys
from pathlib import Path
from metrics.core import load_or_evaluate_single_run

run_dir = Path(sys.argv[1])
evaluation = load_or_evaluate_single_run(run_dir, use_cache=False, write_cache=True)
payload = {
    "run_dir": str(run_dir),
    "scenario": evaluation.scenario,
    "detector_alert_events": evaluation.detector_alert_events,
    "zeek_alert_events": evaluation.zeek_alert_events,
    "suricata_alert_events": evaluation.suricata_alert_events,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

detected_count_from_result() {
  python3 -c '
import json, sys
payload = json.load(sys.stdin)
print(sum(1 for key in ("detector_alert_events", "zeek_alert_events", "suricata_alert_events") if int(payload.get(key) or 0) > 0))
'
}

run_visibility_level() {
  local family="$1"
  local visibility="$2"
  local result_json detected

  info "Visibility campaign: family=${family} visibility=${visibility}%"
  run_visibility_family "${family}" "${visibility}"
  result_json="$(evaluate_latest_visibility "${family}")"
  printf '%s\n' "${result_json}" > "$(latest_visibility_run_for "${family}")/visibility-result.json"
  detected="$(printf '%s\n' "${result_json}" | detected_count_from_result)"
  info "Visibility result: family=${family} visibility=${visibility}% detectors_with_alerts=${detected}/3"
  if [[ "${detected}" == "0" ]]; then
    return 10
  fi
  if [[ "${detected}" != "3" ]]; then
    return 11
  fi
  return 0
}

run_family_campaign() {
  local family="$1"
  local first_partial=""
  local visibility rc start fine

  for visibility in ${COARSE_VISIBILITY_LEVELS}; do
    set +e
    run_visibility_level "${family}" "${visibility}"
    rc=$?
    set -e
    if [[ "${rc}" == "10" || "${rc}" == "11" ]]; then
      first_partial="${visibility}"
      break
    fi
  done

  if [[ -z "${first_partial}" ]]; then
    first_partial="10"
  fi

  if [[ "${FINE_VISIBILITY_ENABLE}" != "1" ]]; then
    return 0
  fi

  start=$((first_partial - 1))
  for ((fine=start; fine>=FINE_VISIBILITY_MIN; fine--)); do
    set +e
    run_visibility_level "${family}" "${fine}"
    rc=$?
    set -e
    if [[ "${rc}" == "10" && "${STOP_AFTER_ALL_MISS}" == "1" ]]; then
      return 0
    fi
  done
}

for family in ${FAMILIES}; do
  run_family_campaign "${family}"
done

if [[ "${REPORT_ENABLE}" == "1" ]]; then
  PYTHONPATH=./python python3 -m reporting.cli "$(results_root)" --profile all --output-dir "$(results_root)/experiment-report"
fi
