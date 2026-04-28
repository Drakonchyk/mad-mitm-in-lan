#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

require_experiment_tools
prepare_run_dir "baseline"
trap cleanup_run_tmp_capture_files EXIT

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

info "Starting automated baseline run"
mkdir -p "$(results_root)"
start_lab_and_wait_for_access
prepare_victim_detector
prepare_victim_zeek
prepare_victim_suricata
BASELINE_PERF_PROBES_ENABLE="${BASELINE_PERF_PROBES_ENABLE:-0}"

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
start_switch_port_captures

sleep 2

capture_remote_command victim "${RUN_DIR}/victim/ping-gateway.txt" "ping -c 4 '${GATEWAY_IP}'"
capture_remote_command victim "${RUN_DIR}/victim/ping-attacker.txt" "ping -c 4 '$(lab_host_ip attacker)'"
capture_remote_command victim "${RUN_DIR}/victim/dns.txt" \
  "for domain in ${DETECTOR_DOMAINS}; do echo \"== \$domain ==\"; dig +time=2 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}'; done"

if [[ "${BASELINE_PERF_PROBES_ENABLE}" == "1" ]]; then
  capture_remote_command victim "${RUN_DIR}/victim/curl.txt" \
    "curl -sS -o /dev/null -w 'http_code=%{http_code}\ntime_connect=%{time_connect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' https://example.com"

  remote_sudo_bash_lc gateway \
    "pkill -x iperf3 2>/dev/null || true; nohup iperf3 -s --one-off >'/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log' 2>&1 </dev/null &" \
    >/dev/null 2>&1
  sleep 1
  capture_remote_command victim "${RUN_DIR}/victim/iperf3.json" "iperf3 -c '${GATEWAY_IP}' -t 5 --json"
fi

if guest_pcaps_requested; then
  stop_remote_capture attacker attacker
  stop_remote_capture victim victim
  stop_remote_capture gateway gateway
fi
stop_local_capture sensor
stop_switch_port_captures
stop_local_detector
stop_local_zeek
stop_local_suricata
capture_ovs_dhcp_snooping_stats
capture_ovs_switch_truth_snooping_stats

save_capture_files
summarize_saved_pcaps
capture_remote_command victim "${RUN_DIR}/victim/ip-neigh-after.txt" "ip neigh show"
capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh-after.txt" "ip neigh show"
capture_local_delta /tmp/mitm-lab-detector-host.jsonl "${DETECTOR_OFFSET}" "${RUN_DIR}/detector/detector.delta.jsonl"
capture_remote_delta gateway /var/log/dnsmasq-mitm-lab.log "${DNSMASQ_OFFSET}" "${RUN_DIR}/gateway/dnsmasq.delta.log"
cp /tmp/mitm-lab-detector-host-state.json "${RUN_DIR}/detector/detector.state.json" 2>/dev/null || true
capture_victim_zeek_artifacts
capture_victim_suricata_artifacts

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_run_meta "automated-baseline" "${STARTED_AT}" "${ENDED_AT}" "Clean traffic run generated entirely by the host automation"
lab_python_module metrics.truth_db "${RUN_DIR}" >/dev/null 2>&1 || true
lab_python_module metrics.wire_truth_cli "${RUN_DIR}" --out "${RUN_DIR}/pcap/wire-truth.json" >/dev/null 2>&1 || true
explain_saved_run
evaluate_saved_run
upsert_results_db

info "Baseline results saved to $(results_root)/experiment-results.sqlite"
write_summary "${RUN_DIR}"
prune_run_artifacts
