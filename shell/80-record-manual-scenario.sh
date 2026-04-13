#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/experiment-common.sh"

SCENARIO_NAME="${1:-manual-scenario}"
DURATION_SECONDS="${2:-60}"
SCENARIO_NOTES="${3:-Manual attack, detection, or mitigation steps performed inside the isolated lab during the capture window}"
SKIP_LAB_START="${SKIP_LAB_START:-0}"
ATTACK_JOB_HOST="${ATTACK_JOB_HOST:-}"
ATTACK_JOB_LABEL="${ATTACK_JOB_LABEL:-scenario-job}"
ATTACK_JOB_CMD="${ATTACK_JOB_CMD:-}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-4}"

require_experiment_tools
prepare_run_dir "${SCENARIO_NAME}"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

info "Starting scenario '${SCENARIO_NAME}' for ${DURATION_SECONDS}s"
mkdir -p "$(results_root)"
if [[ "${SKIP_LAB_START}" == "1" ]]; then
  info "Using existing lab access prepared by the caller"
else
  start_lab_and_wait_for_access
fi

prepare_victim_detector

DETECTOR_OFFSET="$(remote_file_size victim /var/log/mitm-lab-detector.jsonl)"
DNSMASQ_OFFSET="$(remote_file_size gateway /var/log/dnsmasq-mitm-lab.log)"

save_common_state
save_tool_versions

start_remote_capture gateway any gateway >/dev/null
start_remote_capture victim vnic0 victim >/dev/null
start_remote_capture attacker vnic0 attacker >/dev/null

remote_bash_lc victim \
  "nohup bash -lc '
      out=/tmp/${RUN_ID}-${RUN_SLUG}-traffic.log
      rm -f \"\$out\"
      end=\$(( \$(date +%s) + ${DURATION_SECONDS} ))
      while [ \$(date +%s) -lt \"\$end\" ]; do
        echo \"ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        ping -c 1 -W 1 ${GATEWAY_IP} || true
        ping -c 1 -W 1 $(cidr_addr "${ATTACKER_CIDR}") || true
        for domain in ${DETECTOR_DOMAINS}; do
          echo \"domain=\$domain\"
          dig +time=1 +tries=1 +short A \"\$domain\" @${DNS_SERVER} || true
        done
        curl -sS -o /dev/null -w \"curl http_code=%{http_code} time_total=%{time_total}\n\" https://example.com || true
        sleep 2
      done
    ' >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.stdout 2>&1 </dev/null & echo \$! >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid" \
  >/dev/null

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  info "Starting automated scenario job '${ATTACK_JOB_LABEL}' on ${ATTACK_JOB_HOST}"
  printf '%s\n' "${ATTACK_JOB_CMD}" > "${RUN_DIR}/${ATTACK_JOB_HOST}/${ATTACK_JOB_LABEL}.command.txt"
  start_remote_background_job "${ATTACK_JOB_HOST}" "${ATTACK_JOB_LABEL}" "${ATTACK_JOB_CMD}"
fi

info "Capture window is open. Perform the manual scenario now."
sleep "${DURATION_SECONDS}"

remote_bash_lc victim \
  "if test -f /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid; then kill \$(cat /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid) 2>/dev/null || true; fi" \
  >/dev/null 2>&1 || true

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  stop_remote_background_job "${ATTACK_JOB_HOST}" "${ATTACK_JOB_LABEL}"
fi

if [[ "${POST_ATTACK_SETTLE_SECONDS}" -gt 0 ]]; then
  info "Running post-window victim probe and waiting ${POST_ATTACK_SETTLE_SECONDS}s for detector recovery logs"
  remote_bash_lc victim \
    "bash -lc '
      out=/tmp/${RUN_ID}-${RUN_SLUG}-post-window-probe.txt
      {
        echo \"ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        ping -c 1 -W 1 ${GATEWAY_IP} || true
        for domain in ${DETECTOR_DOMAINS}; do
          echo \"domain=\$domain\"
          dig +time=1 +tries=1 +short A \"\$domain\" @${DNS_SERVER} || true
        done
      } >\"\$out\" 2>&1
    '" >/dev/null 2>&1 || true
  sleep "${POST_ATTACK_SETTLE_SECONDS}"
fi

stop_remote_capture attacker attacker
stop_remote_capture victim victim
stop_remote_capture gateway gateway

save_capture_files
summarize_saved_pcaps
fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-traffic.stdout" "${RUN_DIR}/victim/traffic-window.txt" || true
fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-post-window-probe.txt" "${RUN_DIR}/victim/post-window-probe.txt" || true
capture_remote_command victim "${RUN_DIR}/victim/ip-neigh-after.txt" "ip neigh show"
capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh-after.txt" "ip neigh show"
capture_remote_command attacker "${RUN_DIR}/attacker/ip-neigh-after.txt" "ip neigh show"
capture_remote_delta victim /var/log/mitm-lab-detector.jsonl "${DETECTOR_OFFSET}" "${RUN_DIR}/victim/detector.delta.jsonl"
capture_remote_delta gateway /var/log/dnsmasq-mitm-lab.log "${DNSMASQ_OFFSET}" "${RUN_DIR}/gateway/dnsmasq.delta.log"
fetch_remote_file victim "/var/lib/mitm-lab-detector/state.json" "${RUN_DIR}/victim/detector.state.json" || true

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  fetch_remote_file "${ATTACK_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${ATTACK_JOB_LABEL}.stdout" "${RUN_DIR}/${ATTACK_JOB_HOST}/${ATTACK_JOB_LABEL}.stdout" || true
  fetch_remote_file "${ATTACK_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${ATTACK_JOB_LABEL}.stderr" "${RUN_DIR}/${ATTACK_JOB_HOST}/${ATTACK_JOB_LABEL}.stderr" || true
fi

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_run_meta "manual-window" "${STARTED_AT}" "${ENDED_AT}" "${SCENARIO_NOTES}"
analyze_saved_pcaps_with_suricata
explain_saved_run

info "Scenario artifacts saved under ${RUN_DIR}"
write_summary "${RUN_DIR}"
