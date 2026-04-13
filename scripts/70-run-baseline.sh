#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/experiment-common.sh"

require_experiment_tools
prepare_run_dir "baseline"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

info "Starting automated baseline run"
mkdir -p "$(results_root)"
start_lab_and_wait_for_access

DETECTOR_OFFSET="$(remote_file_size victim /var/log/mitm-lab-detector.jsonl)"
DNSMASQ_OFFSET="$(remote_file_size gateway /var/log/dnsmasq-mitm-lab.log)"

save_common_state

start_remote_capture gateway any gateway >/dev/null
start_remote_capture victim vnic0 victim >/dev/null
start_remote_capture attacker vnic0 attacker >/dev/null

sleep 2

capture_remote_command victim "${RUN_DIR}/victim/ping-gateway.txt" "ping -c 4 '${GATEWAY_IP}'"
capture_remote_command victim "${RUN_DIR}/victim/ping-attacker.txt" "ping -c 4 '$(cidr_addr "${ATTACKER_CIDR}")'"
capture_remote_command victim "${RUN_DIR}/victim/dns.txt" \
  "for domain in ${DETECTOR_DOMAINS}; do echo \"== \$domain ==\"; dig +time=2 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}'; done"
capture_remote_command victim "${RUN_DIR}/victim/curl.txt" \
  "curl -sS -o /dev/null -w 'http_code=%{http_code}\ntime_connect=%{time_connect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' https://example.com"

remote_sudo_bash_lc gateway \
  "pkill -x iperf3 2>/dev/null || true; nohup iperf3 -s --one-off >'/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log' 2>&1 </dev/null &" \
  >/dev/null 2>&1
sleep 1
capture_remote_command victim "${RUN_DIR}/victim/iperf3.json" "iperf3 -c '${GATEWAY_IP}' -t 5 --json"

stop_remote_capture attacker attacker
stop_remote_capture victim victim
stop_remote_capture gateway gateway

save_capture_files
capture_remote_command victim "${RUN_DIR}/victim/ip-neigh-after.txt" "ip neigh show"
capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh-after.txt" "ip neigh show"
capture_remote_delta victim /var/log/mitm-lab-detector.jsonl "${DETECTOR_OFFSET}" "${RUN_DIR}/victim/detector.delta.jsonl"
capture_remote_delta gateway /var/log/dnsmasq-mitm-lab.log "${DNSMASQ_OFFSET}" "${RUN_DIR}/gateway/dnsmasq.delta.log"

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_run_meta "automated-baseline" "${STARTED_AT}" "${ENDED_AT}" "Clean traffic run generated entirely by the host automation"

info "Baseline artifacts saved under ${RUN_DIR}"
write_summary "${RUN_DIR}"
