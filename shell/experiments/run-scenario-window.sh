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
MONITOR_JOB_HOST="${MONITOR_JOB_HOST:-}"
MONITOR_JOB_LABEL="${MONITOR_JOB_LABEL:-monitor-job}"
MONITOR_JOB_CMD="${MONITOR_JOB_CMD:-}"
MONITOR_JOB_USE_SUDO="${MONITOR_JOB_USE_SUDO:-0}"
VICTIM_JOB_HOST="${VICTIM_JOB_HOST:-}"
VICTIM_JOB_LABEL="${VICTIM_JOB_LABEL:-victim-job}"
VICTIM_JOB_CMD="${VICTIM_JOB_CMD:-}"
VICTIM_JOB_USE_SUDO="${VICTIM_JOB_USE_SUDO:-0}"
POST_CLEANUP_HOST="${POST_CLEANUP_HOST:-}"
POST_CLEANUP_LABEL="${POST_CLEANUP_LABEL:-post-cleanup}"
POST_CLEANUP_CMD="${POST_CLEANUP_CMD:-}"
POST_CLEANUP_USE_SUDO="${POST_CLEANUP_USE_SUDO:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
POST_WINDOW_PROBE_SSH_ATTEMPTS="${POST_WINDOW_PROBE_SSH_ATTEMPTS:-6}"
POST_WINDOW_PROBE_SSH_DELAY_SECONDS="${POST_WINDOW_PROBE_SSH_DELAY_SECONDS:-1}"
POST_WINDOW_PROBE_SSH_CONNECT_TIMEOUT="${POST_WINDOW_PROBE_SSH_CONNECT_TIMEOUT:-2}"
PLAN_DURATION_SECONDS="${PLAN_DURATION_SECONDS:-${DURATION_SECONDS}}"
TRAFFIC_PROBE_ENABLE="${TRAFFIC_PROBE_ENABLE:-1}"
TRAFFIC_PROBE_MODE="${TRAFFIC_PROBE_MODE:-synthetic}"
TRAFFIC_PROBE_PPS="${TRAFFIC_PROBE_PPS:-4}"
TRAFFIC_PROBE_DNS_INTERVAL_SECONDS="${TRAFFIC_PROBE_DNS_INTERVAL_SECONDS:-2}"
TRAFFIC_PROBE_PACKET_BYTES="${TRAFFIC_PROBE_PACKET_BYTES:-96}"
IPERF_ENABLE="${IPERF_ENABLE:-0}"
IPERF_OFFSET_SECONDS="${IPERF_OFFSET_SECONDS:-20}"
IPERF_DURATION_SECONDS="${IPERF_DURATION_SECONDS:-5}"
RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE:-1}"

require_experiment_tools
prepare_run_dir "${SCENARIO_NAME}"
trap cleanup_run_tmp_capture_files EXIT

info "Starting scenario '${SCENARIO_NAME}' for ${DURATION_SECONDS}s"
mkdir -p "$(results_root)"
if [[ "${SKIP_LAB_START}" == "1" ]]; then
  info "Using existing lab access prepared by the caller"
  refresh_switch_counters_for_run
else
  start_lab_and_wait_for_access
fi

prepare_reliability_netem
prepare_victim_detector
prepare_victim_zeek
prepare_victim_suricata

DETECTOR_OFFSET="$(local_file_size /tmp/mitm-lab-detector-host.jsonl)"
DNSMASQ_OFFSET="$(remote_file_size gateway /var/log/dnsmasq-mitm-lab.log)"

save_common_state
save_tool_versions
capture_remote_command gateway "${RUN_DIR}/gateway/dhcp-leases-before.json" "$(dhcp_lease_snapshot_cmd)" || true

if guest_pcaps_requested; then
  start_remote_capture gateway any gateway >/dev/null
  start_remote_capture victim vnic0 victim >/dev/null
  start_remote_capture attacker vnic0 attacker >/dev/null
fi
start_local_capture "${LAB_SWITCH_SENSOR_PORT}" sensor >/dev/null
start_switch_port_captures

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

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

if [[ "${TRAFFIC_PROBE_ENABLE}" == "1" ]]; then
  case "${TRAFFIC_PROBE_MODE}" in
    synthetic|scapy)
      remote_bash_lc victim "cat > /tmp/${RUN_ID}-${RUN_SLUG}-traffic-probe.py <<'PY'
from __future__ import annotations

import json
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone

try:
    from scapy.all import ICMP, IP, Raw, send
    SCAPY_ERROR = None
except Exception as exc:
    ICMP = IP = Raw = send = None
    SCAPY_ERROR = str(exc)


def dns_query(name: str, ident: int) -> bytes:
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.rstrip('.').split('.') if part)
    header = struct.pack('!HHHHHH', ident & 0xffff, 0x0100, 1, 0, 0, 0)
    return header + labels + b'\x00' + struct.pack('!HH', 1, 1)


duration = max(float(sys.argv[1]), 1.0)
gateway_ip = sys.argv[2]
attacker_ip = sys.argv[3]
dns_server = sys.argv[4]
pps = max(float(sys.argv[5]), 0.0)
dns_interval = max(float(sys.argv[6]), 0.2)
packet_bytes = max(int(sys.argv[7]), 64)
domains = [domain for domain in os.environ.get('MITM_TRAFFIC_DOMAINS', '').split() if domain]
targets = [target for target in (gateway_ip, attacker_ip) if target]
payload_len = max(packet_bytes - 42, 1)
payload = bytes(index % 251 for index in range(payload_len))
icmp_interval = (1.0 / pps) if pps > 0 and targets and SCAPY_ERROR is None else None
deadline = time.monotonic() + duration
next_icmp = time.monotonic()
next_dns = time.monotonic()
sent_icmp = 0
sent_dns = 0
dns_errors = 0
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.15)

while time.monotonic() < deadline:
    now = time.monotonic()
    if icmp_interval is not None and now >= next_icmp:
        target = targets[sent_icmp % len(targets)]
        send(IP(dst=target) / ICMP(type=8) / Raw(load=payload), verbose=False)
        sent_icmp += 1
        next_icmp += icmp_interval
        continue

    if domains and now >= next_dns:
        for domain in domains:
            try:
                sock.sendto(dns_query(domain, random.randrange(0, 65536)), (dns_server, 53))
                sent_dns += 1
            except OSError:
                dns_errors += 1
        next_dns += dns_interval
        continue

    wakeups = [deadline]
    if icmp_interval is not None:
        wakeups.append(next_icmp)
    if domains:
        wakeups.append(next_dns)
    time.sleep(max(0.01, min(wakeups) - time.monotonic()))

print(json.dumps({
    'event': 'synthetic_traffic_finished',
    'ts': datetime.now(timezone.utc).isoformat(),
    'duration_seconds': duration,
    'icmp_requested_pps': pps,
    'packet_bytes': packet_bytes,
    'dns_interval_seconds': dns_interval,
    'domains': domains,
    'sent_icmp': sent_icmp,
    'sent_dns_queries': sent_dns,
    'dns_send_errors': dns_errors,
    'scapy_error': SCAPY_ERROR,
}, sort_keys=True))
PY"
      remote_sudo_bash_lc victim \
        "nohup env MITM_TRAFFIC_DOMAINS='${DETECTOR_DOMAINS}' python3 /tmp/${RUN_ID}-${RUN_SLUG}-traffic-probe.py '${DURATION_SECONDS}' '${GATEWAY_IP}' '$(lab_host_ip attacker)' '${DNS_SERVER}' '${TRAFFIC_PROBE_PPS}' '${TRAFFIC_PROBE_DNS_INTERVAL_SECONDS}' '${TRAFFIC_PROBE_PACKET_BYTES}' >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.stdout 2>&1 </dev/null & echo \$! >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid" \
        >/dev/null
      ;;
    legacy)
      remote_bash_lc victim \
        "nohup bash -lc '
            end=\$(( \$(date +%s) + ${DURATION_SECONDS} ))
            while [ \$(date +%s) -lt \"\$end\" ]; do
              echo \"ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
              ping -c 1 -W 1 ${GATEWAY_IP} || true
              ping -c 1 -W 1 $(lab_host_ip attacker) || true
              for domain in ${DETECTOR_DOMAINS}; do
                echo \"domain=\$domain\"
                dig +time=1 +tries=1 +short A \"\$domain\" @${DNS_SERVER} || true
              done
              sleep 2
            done
          ' >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.stdout 2>&1 </dev/null & echo \$! >/tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid" \
        >/dev/null
      ;;
    *)
      warn "Unknown TRAFFIC_PROBE_MODE=${TRAFFIC_PROBE_MODE}; skipping background traffic"
      ;;
  esac
fi

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

if [[ -n "${MONITOR_JOB_CMD}" ]]; then
  info "Starting monitor scenario job '${MONITOR_JOB_LABEL}' on ${MONITOR_JOB_HOST}"
  printf '%s\n' "${MONITOR_JOB_CMD}" > "${RUN_DIR}/${MONITOR_JOB_HOST}/${MONITOR_JOB_LABEL}.command.txt"
  start_remote_background_job "${MONITOR_JOB_HOST}" "${MONITOR_JOB_LABEL}" "${MONITOR_JOB_CMD}" "${MONITOR_JOB_USE_SUDO}"
fi

if [[ -n "${VICTIM_JOB_CMD}" ]]; then
  info "Starting victim-side scenario job '${VICTIM_JOB_LABEL}' on ${VICTIM_JOB_HOST}"
  printf '%s\n' "${VICTIM_JOB_CMD}" > "${RUN_DIR}/${VICTIM_JOB_HOST}/${VICTIM_JOB_LABEL}.command.txt"
  start_remote_background_job "${VICTIM_JOB_HOST}" "${VICTIM_JOB_LABEL}" "${VICTIM_JOB_CMD}" "${VICTIM_JOB_USE_SUDO}"
fi

info "Capture window is open. Scenario jobs and victim probes are running."
sleep "${DURATION_SECONDS}"

if [[ "${TRAFFIC_PROBE_ENABLE}" == "1" ]]; then
  remote_sudo_bash_lc victim \
    "if test -f /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid; then kill \$(cat /tmp/${RUN_ID}-${RUN_SLUG}-traffic.pid) 2>/dev/null || true; fi" \
    >/dev/null 2>&1 || true
fi

if [[ -n "${ATTACK_JOB_CMD}" ]]; then
  stop_remote_background_job "${ATTACK_JOB_HOST}" "${ATTACK_JOB_LABEL}" "${ATTACK_JOB_USE_SUDO}"
fi

if [[ -n "${AUX_JOB_CMD}" ]]; then
  stop_remote_background_job "${AUX_JOB_HOST}" "${AUX_JOB_LABEL}" "${AUX_JOB_USE_SUDO}"
fi

if [[ -n "${VICTIM_JOB_CMD}" ]]; then
  stop_remote_background_job "${VICTIM_JOB_HOST}" "${VICTIM_JOB_LABEL}" "${VICTIM_JOB_USE_SUDO}"
fi

if [[ -n "${MONITOR_JOB_CMD}" ]]; then
  stop_remote_background_job "${MONITOR_JOB_HOST}" "${MONITOR_JOB_LABEL}" "${MONITOR_JOB_USE_SUDO}"
fi

capture_remote_command gateway "${RUN_DIR}/gateway/dhcp-leases-before-cleanup.json" "$(dhcp_lease_snapshot_cmd)" || true

if [[ -n "${POST_CLEANUP_CMD}" ]]; then
  info "Running post-attack cleanup '${POST_CLEANUP_LABEL}' on ${POST_CLEANUP_HOST}"
  printf '%s\n' "${POST_CLEANUP_CMD}" > "${RUN_DIR}/${POST_CLEANUP_HOST}/${POST_CLEANUP_LABEL}.command.txt"
  if [[ "${POST_CLEANUP_USE_SUDO}" == "1" ]]; then
    remote_sudo_bash_lc "${POST_CLEANUP_HOST}" "${POST_CLEANUP_CMD}" \
      > "${RUN_DIR}/${POST_CLEANUP_HOST}/${POST_CLEANUP_LABEL}.stdout" \
      2> "${RUN_DIR}/${POST_CLEANUP_HOST}/${POST_CLEANUP_LABEL}.stderr" || true
  else
    remote_bash_lc "${POST_CLEANUP_HOST}" "${POST_CLEANUP_CMD}" \
      > "${RUN_DIR}/${POST_CLEANUP_HOST}/${POST_CLEANUP_LABEL}.stdout" \
      2> "${RUN_DIR}/${POST_CLEANUP_HOST}/${POST_CLEANUP_LABEL}.stderr" || true
  fi
  capture_remote_command gateway "${RUN_DIR}/gateway/dhcp-leases-after-cleanup.json" "$(dhcp_lease_snapshot_cmd)" || true
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
stop_switch_port_captures
stop_local_detector
stop_local_zeek
stop_local_suricata
capture_ovs_dhcp_snooping_stats
capture_ovs_switch_truth_snooping_stats
capture_reliability_netem_stats
stop_reliability_netem

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

if [[ -n "${MONITOR_JOB_CMD}" ]]; then
  wait_for_remote_file "${MONITOR_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${MONITOR_JOB_LABEL}.stdout" 5 1 || true
  fetch_remote_file "${MONITOR_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${MONITOR_JOB_LABEL}.stdout" "${RUN_DIR}/${MONITOR_JOB_HOST}/${MONITOR_JOB_LABEL}.stdout" || true
  fetch_remote_file "${MONITOR_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${MONITOR_JOB_LABEL}.stderr" "${RUN_DIR}/${MONITOR_JOB_HOST}/${MONITOR_JOB_LABEL}.stderr" || true
fi

if [[ -n "${VICTIM_JOB_CMD}" ]]; then
  wait_for_remote_file "${VICTIM_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${VICTIM_JOB_LABEL}.stdout" 5 1 || true
  fetch_remote_file "${VICTIM_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${VICTIM_JOB_LABEL}.stdout" "${RUN_DIR}/${VICTIM_JOB_HOST}/${VICTIM_JOB_LABEL}.stdout" || true
  fetch_remote_file "${VICTIM_JOB_HOST}" "/tmp/${RUN_ID}-${RUN_SLUG}-${VICTIM_JOB_LABEL}.stderr" "${RUN_DIR}/${VICTIM_JOB_HOST}/${VICTIM_JOB_LABEL}.stderr" || true
fi

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_run_meta "scenario-window" "${STARTED_AT}" "${ENDED_AT}" "${SCENARIO_NOTES}"
lab_python_module metrics.truth_db "${RUN_DIR}" >/dev/null 2>&1 || true
lab_python_module metrics.wire_truth_cli "${RUN_DIR}" --out "${RUN_DIR}/pcap/wire-truth.json" >/dev/null 2>&1 || true
explain_saved_run
evaluate_saved_run
upsert_results_db

info "Scenario results saved to $(results_root)/experiment-results.sqlite"
if [[ "${RUN_SUMMARY_ENABLE}" == "1" ]]; then
  write_summary "${RUN_DIR}"
else
  info "Run summary skipped; results saved to $(results_root)/experiment-results.sqlite"
fi
prune_run_artifacts
