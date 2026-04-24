#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

SCENARIO_NAME="${1:-scenario-window}"
DURATION_SECONDS="${2:-60}"
SCENARIO_NOTES="${3:-Time-boxed scenario window in the isolated lab}"
SKIP_LAB_START="${SKIP_LAB_START:-0}"
ATTACK_JOB_HOST="${ATTACK_JOB_HOST:-}"
ATTACK_JOB_LABEL="${ATTACK_JOB_LABEL:-scenario-job}"
ATTACK_JOB_CMD="${ATTACK_JOB_CMD:-}"
ATTACK_JOB_USE_SUDO="${ATTACK_JOB_USE_SUDO:-0}"
AUX_JOB_HOST="${AUX_JOB_HOST:-}"
AUX_JOB_LABEL="${AUX_JOB_LABEL:-aux-job}"
AUX_JOB_CMD="${AUX_JOB_CMD:-}"
AUX_JOB_USE_SUDO="${AUX_JOB_USE_SUDO:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-4}"
POST_WINDOW_PROBE_SSH_ATTEMPTS="${POST_WINDOW_PROBE_SSH_ATTEMPTS:-6}"
POST_WINDOW_PROBE_SSH_DELAY_SECONDS="${POST_WINDOW_PROBE_SSH_DELAY_SECONDS:-1}"
POST_WINDOW_PROBE_SSH_CONNECT_TIMEOUT="${POST_WINDOW_PROBE_SSH_CONNECT_TIMEOUT:-2}"
PLAN_DURATION_SECONDS="${PLAN_DURATION_SECONDS:-${DURATION_SECONDS}}"
IPERF_ENABLE="${IPERF_ENABLE:-1}"
IPERF_OFFSET_SECONDS="${IPERF_OFFSET_SECONDS:-20}"
IPERF_DURATION_SECONDS="${IPERF_DURATION_SECONDS:-5}"

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
prepare_victim_zeek
prepare_victim_suricata

DETECTOR_OFFSET="$(local_file_size /tmp/mitm-lab-detector-host.jsonl)"
DNSMASQ_OFFSET="$(remote_file_size gateway /var/log/dnsmasq-mitm-lab.log)"

save_common_state
save_tool_versions

if guest_pcaps_requested; then
  start_remote_capture gateway any gateway >/dev/null
  start_remote_capture victim vnic0 victim >/dev/null
  start_remote_capture attacker vnic0 attacker >/dev/null
fi
start_local_capture "${LAB_SWITCH_SENSOR_PORT}" sensor >/dev/null

if [[ "${IPERF_ENABLE}" == "1" ]]; then
  remote_sudo_bash_lc gateway \
    "pkill -x iperf3 2>/dev/null || true; nohup iperf3 -s --one-off >'/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log' 2>&1 </dev/null &" \
    >/dev/null 2>&1 || true
  remote_bash_lc victim \
    "nohup bash -lc '
        sleep ${IPERF_OFFSET_SECONDS}
        iperf3 -c ${GATEWAY_IP} -t ${IPERF_DURATION_SECONDS} --json > /tmp/${RUN_ID}-${RUN_SLUG}-iperf3.json
      ' >/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.stdout 2>/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.stderr </dev/null & echo \$! >/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.pid" \
    >/dev/null 2>&1 || true
fi

remote_bash_lc victim \
  "nohup bash -lc '
      out=/tmp/${RUN_ID}-${RUN_SLUG}-traffic.log
      rm -f \"\$out\"
      end=\$(( \$(date +%s) + ${DURATION_SECONDS} ))
      while [ \$(date +%s) -lt \"\$end\" ]; do
        echo \"ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        ping -c 1 -W 1 ${GATEWAY_IP} || true
        ping -c 1 -W 1 $(lab_host_ip attacker) || true
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
  start_remote_background_job "${ATTACK_JOB_HOST}" "${ATTACK_JOB_LABEL}" "${ATTACK_JOB_CMD}" "${ATTACK_JOB_USE_SUDO}"
fi

if [[ -n "${AUX_JOB_CMD}" ]]; then
  info "Starting auxiliary scenario job '${AUX_JOB_LABEL}' on ${AUX_JOB_HOST}"
  printf '%s\n' "${AUX_JOB_CMD}" > "${RUN_DIR}/${AUX_JOB_HOST}/${AUX_JOB_LABEL}.command.txt"
  start_remote_background_job "${AUX_JOB_HOST}" "${AUX_JOB_LABEL}" "${AUX_JOB_CMD}" "${AUX_JOB_USE_SUDO}"
fi

info "Capture window is open. Scenario jobs and victim probes are running."
sleep "${DURATION_SECONDS}"

remote_bash_lc victim \
  "if test -f /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid; then kill \$(cat /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid) 2>/dev/null || true; fi" \
  >/dev/null 2>&1 || true

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  stop_remote_background_job "${ATTACK_JOB_HOST}" "${ATTACK_JOB_LABEL}" "${ATTACK_JOB_USE_SUDO}"
fi

if [[ -n "${AUX_JOB_CMD}" ]]; then
  stop_remote_background_job "${AUX_JOB_HOST}" "${AUX_JOB_LABEL}" "${AUX_JOB_USE_SUDO}"
fi

if [[ "${POST_ATTACK_SETTLE_SECONDS}" -gt 0 ]]; then
  info "Running post-window victim probe and waiting ${POST_ATTACK_SETTLE_SECONDS}s for detector recovery logs"
  sleep "${POST_ATTACK_SETTLE_SECONDS}"
  LAB_SSH_CONNECT_TIMEOUT="${POST_WINDOW_PROBE_SSH_CONNECT_TIMEOUT}" \
  capture_remote_command_retry victim "${RUN_DIR}/victim/post-window-probe.txt" \
    "echo \"ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"; ping -c 1 -W 1 '${GATEWAY_IP}' || true; for domain in ${DETECTOR_DOMAINS}; do echo \"domain=\$domain\"; dig +time=1 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}' || true; done" \
    "${POST_WINDOW_PROBE_SSH_ATTEMPTS}" "${POST_WINDOW_PROBE_SSH_DELAY_SECONDS}"
fi

if guest_pcaps_requested; then
  stop_remote_capture attacker attacker
  stop_remote_capture victim victim
  stop_remote_capture gateway gateway
fi
stop_local_capture sensor
stop_local_detector
stop_local_zeek
stop_local_suricata

save_capture_files
summarize_saved_pcaps
fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-traffic.stdout" "${RUN_DIR}/victim/traffic-window.txt" || true
if [[ "${IPERF_ENABLE}" == "1" ]]; then
  wait_for_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.json" 10 1 || true
  if remote_file_exists victim "/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.json"; then
    fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.json" "${RUN_DIR}/victim/iperf3.json" || true
  else
    warn "Victim iperf3 client did not produce a JSON artifact"
    if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
      fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.stdout" "${RUN_DIR}/victim/iperf3.stdout" || true
      fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-iperf3.stderr" "${RUN_DIR}/victim/iperf3.stderr" || true
    fi
  fi
fi
capture_remote_command victim "${RUN_DIR}/victim/ip-neigh-after.txt" "ip neigh show"
capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh-after.txt" "ip neigh show"
capture_remote_command attacker "${RUN_DIR}/attacker/ip-neigh-after.txt" "ip neigh show"
capture_local_delta /tmp/mitm-lab-detector-host.jsonl "${DETECTOR_OFFSET}" "${RUN_DIR}/detector/detector.delta.jsonl"
capture_remote_delta gateway /var/log/dnsmasq-mitm-lab.log "${DNSMASQ_OFFSET}" "${RUN_DIR}/gateway/dnsmasq.delta.log"
cp /tmp/mitm-lab-detector-host-state.json "${RUN_DIR}/detector/detector.state.json" 2>/dev/null || true
capture_victim_zeek_artifacts
capture_victim_suricata_artifacts

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  wait_for_remote_file "${ATTACK_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${ATTACK_JOB_LABEL}.stdout" 5 1 || true
  fetch_remote_file "${ATTACK_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${ATTACK_JOB_LABEL}.stdout" "${RUN_DIR}/${ATTACK_JOB_HOST}/${ATTACK_JOB_LABEL}.stdout" || true
  fetch_remote_file "${ATTACK_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${ATTACK_JOB_LABEL}.stderr" "${RUN_DIR}/${ATTACK_JOB_HOST}/${ATTACK_JOB_LABEL}.stderr" || true
fi

if [[ -n "${AUX_JOB_CMD}" ]]; then
  wait_for_remote_file "${AUX_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${AUX_JOB_LABEL}.stdout" 5 1 || true
  fetch_remote_file "${AUX_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${AUX_JOB_LABEL}.stdout" "${RUN_DIR}/${AUX_JOB_HOST}/${AUX_JOB_LABEL}.stdout" || true
  fetch_remote_file "${AUX_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${AUX_JOB_LABEL}.stderr" "${RUN_DIR}/${AUX_JOB_HOST}/${AUX_JOB_LABEL}.stderr" || true
fi

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_run_meta "scenario-window" "${STARTED_AT}" "${ENDED_AT}" "${SCENARIO_NOTES}"
lab_python_module metrics.wire_truth_cli "${RUN_DIR}" --out "${RUN_DIR}/pcap/wire-truth.json" >/dev/null 2>&1 || true
explain_saved_run
evaluate_saved_run

info "Scenario artifacts saved under ${RUN_DIR}"
write_summary "${RUN_DIR}"
prune_run_artifacts
