#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_ENABLE="${PCAP_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scenarios/common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARVATION_TAKEOVER_LEVELS="${STARVATION_TAKEOVER_LEVELS:-1 2 4 8 12 16 24 32 48 64 72 96 108}"
STARVATION_TAKEOVER_RUNS="${STARVATION_TAKEOVER_RUNS:-1}"
STARVATION_TAKEOVER_DURATION="${STARVATION_TAKEOVER_DURATION:-90}"
STARVATION_ATTACK_OFFSET="${STARVATION_ATTACK_OFFSET:-10}"
STARVATION_ATTACK_SECONDS="${STARVATION_ATTACK_SECONDS:-70}"
STARVATION_RAPID_INTERVAL="${STARVATION_RAPID_INTERVAL:-2.0}"
STARVATION_RAPID_PASSES="${STARVATION_RAPID_PASSES:-1}"
STARVATION_MODE="${STARVATION_MODE:-confirmed}"
case "${STARVATION_MODE}" in
  confirmed|rapid) ;;
  *) STARVATION_MODE="confirmed" ;;
esac
STARVATION_TARGET_LEASES="${STARVATION_TARGET_LEASES:-98}"
STARVATION_CONFIRMED_INTERVAL="${STARVATION_CONFIRMED_INTERVAL:-0.05}"
STARVATION_REQUEST_TIMEOUT="${STARVATION_REQUEST_TIMEOUT:-3.0}"
ROGUE_DHCP_START_OFFSET_SECONDS="${ROGUE_DHCP_START_OFFSET_SECONDS:-10}"
ROGUE_DHCP_OFFERED_IP="${ROGUE_DHCP_OFFERED_IP:-10.20.20.254}"
TAKEOVER_START_MODE="${TAKEOVER_START_MODE:-pool-full}"
case "${TAKEOVER_START_MODE}" in
  pool-full|fixed) ;;
  *) TAKEOVER_START_MODE="pool-full" ;;
esac
ROGUE_DHCP_START_DELAY_SECONDS="${ROGUE_DHCP_START_DELAY_SECONDS:-2}"
TAKEOVER_RENEW_DELAY_SECONDS="${TAKEOVER_RENEW_DELAY_SECONDS:-3}"
TAKEOVER_RENEW_INTERVAL_SECONDS="${TAKEOVER_RENEW_INTERVAL_SECONDS:-5}"
TAKEOVER_ENABLE="${TAKEOVER_ENABLE:-1}"
case "${TAKEOVER_ENABLE}" in
  1|true|TRUE|yes|YES|on|ON) TAKEOVER_ENABLE="1" ;;
  *) TAKEOVER_ENABLE="0" ;;
esac
PCAP_ENABLE="${USER_PCAP_ENABLE:-1}"
case "${FULL_PCAPS:-0}" in
  1|true|TRUE|yes|YES|on|ON)
    PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY:-all}"
    GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE:-1}"
    PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE:-1}"
    ;;
  *)
    PCAP_RETENTION_POLICY="first-run-per-scenario"
    GUEST_PCAP_ENABLE="0"
    PCAP_SUMMARIES_ENABLE="0"
    ;;
esac
IPERF_ENABLE="${IPERF_ENABLE:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE:-0}"
REPORT_ENABLE="${REPORT_ENABLE:-0}"

usage() {
  cat <<'EOF'
Usage: ./shell/experiments/run-starvation-takeover-plan.sh

Environment:
  STARVATION_TAKEOVER_LEVELS="1 2 4 8 12 16 24 32 48 64 72 96 108"
  STARVATION_TAKEOVER_RUNS=1
  STARVATION_TAKEOVER_DURATION=90
  STARVATION_ATTACK_OFFSET=10
  STARVATION_ATTACK_SECONDS=70
  STARVATION_MODE=confirmed
  STARVATION_TARGET_LEASES=98
  STARVATION_CONFIRMED_INTERVAL=0.05
  STARVATION_REQUEST_TIMEOUT=3.0
  STARVATION_RAPID_INTERVAL=2.0
  STARVATION_RAPID_PASSES=1
  ROGUE_DHCP_START_OFFSET_SECONDS=10
  ROGUE_DHCP_OFFERED_IP=10.20.20.254
  TAKEOVER_START_MODE=pool-full
  ROGUE_DHCP_START_DELAY_SECONDS=2
  TAKEOVER_RENEW_DELAY_SECONDS=3
  TAKEOVER_RENEW_INTERVAL_SECONDS=5
  TAKEOVER_ENABLE=1

The plan scales DHCP starvation workers from the low baseline through levels
above the old 16-worker ceiling, records DHCP lease-pool occupancy once per
second. With TAKEOVER_ENABLE=1 and TAKEOVER_START_MODE=pool-full, it starts
the reactive rogue DHCP phase only after the gateway lease pool is full, then
retries victim DHCP renews so exhaustion and takeover timing can be measured
from the same runs. With TAKEOVER_ENABLE=0, it only measures the lease-pool
flood.
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

victim_takeover_probe_cmd() {
  local start_offset="$1"
  local rogue_ip="$2"
  local duration="$3"
  local interval="$4"
  cat <<EOF
sleep ${start_offset}
python3 - '${rogue_ip}' '${duration}' '${interval}' <<'PY'
from datetime import datetime, timezone
import json
import subprocess
import sys
import time

rogue_ip = sys.argv[1]
duration = float(sys.argv[2])
interval = max(float(sys.argv[3]), 1.0)

def emit(event, **payload):
    print(json.dumps({'ts': datetime.now(timezone.utc).isoformat(), 'event': event, **payload}, sort_keys=True), flush=True)

def run(command):
    return subprocess.run(command, shell=True, text=True, capture_output=True, timeout=25)

deadline = time.time() + max(duration - ${start_offset}, interval)
attempt = 0
while True:
    attempt += 1
    emit('dhcp_takeover_renew_started', rogue_ip=rogue_ip, attempt=attempt)
    run('dhclient -r vnic0 >/dev/null 2>&1 || true')
    renew = run('(dhclient -v vnic0 || networkctl renew vnic0 || true) 2>&1')
    addr = run("ip -4 -o addr show dev vnic0 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1")
    route = run('ip route show default || true')
    dns = run('resolvectl dns vnic0 2>/dev/null || true')
    ips = [line.strip() for line in addr.stdout.splitlines() if line.strip()]
    takeover_observed = rogue_ip in ips
    emit(
        'dhcp_takeover_renew_finished',
        rogue_ip=rogue_ip,
        attempt=attempt,
        victim_ips=ips,
        takeover_observed=takeover_observed,
        default_route=route.stdout.strip(),
        dns=dns.stdout.strip(),
        renew_returncode=renew.returncode,
    )
    if takeover_observed or time.time() >= deadline:
        break
    time.sleep(interval)
PY
EOF
}

score_latest_takeover_run() {
  local run_dir
  run_dir="$(latest_run_for "dhcp-starvation-rogue-dhcp")"
  if [[ -z "${run_dir}" ]]; then
    warn "Could not find newest dhcp-starvation-rogue-dhcp run"
    return 1
  fi

  PYTHONPATH=./python python3 - "${run_dir}" <<'PY'
import json
import sys
from pathlib import Path

from metrics.core import load_or_evaluate_single_run
from metrics.run_artifacts import load_json, load_jsonl

run_dir = Path(sys.argv[1])
meta = load_json(run_dir / "run-meta.json")
evaluation = load_or_evaluate_single_run(run_dir, use_cache=False, write_cache=True)
lease_rows = []
for path in (
    run_dir / "gateway" / "dhcp-leases-before-cleanup.json",
    run_dir / "gateway" / "dhcp-lease-monitor.stdout",
):
    if path.suffix == ".json" and path.exists():
        try:
            lease_rows.append(load_json(path))
        except Exception:
            pass
    elif path.exists():
        lease_rows.extend(load_jsonl(path))
payload = {
    "run_dir": str(run_dir),
    "scenario": evaluation.scenario,
    "workers": meta.get("dhcp_starvation_workers"),
    "takeover_enabled": meta.get("takeover_enabled"),
    "takeover_start_mode": meta.get("takeover_start_mode"),
    "takeover_renew_delay_seconds": meta.get("takeover_renew_delay_seconds"),
    "rogue_dhcp_start_offset_seconds": meta.get("rogue_dhcp_start_offset_seconds"),
    "rogue_dhcp_offered_ip": meta.get("rogue_dhcp_offered_ip"),
    "dhcp_pool_total": max((int(row.get("pool_total") or 0) for row in lease_rows), default=None),
    "dhcp_attack_leases_max": max((int(row.get("attack_taken") or 0) for row in lease_rows), default=None),
    "dhcp_pool_taken_max": max((int(row.get("taken") or 0) for row in lease_rows), default=None),
    "dhcp_pool_free_min": min((int(row.get("free") or 0) for row in lease_rows), default=None),
    "ground_truth_attack_events": evaluation.ground_truth_attack_events,
    "detector_alert_events": evaluation.detector_alert_events,
    "zeek_alert_events": evaluation.zeek_alert_events,
    "suricata_alert_events": evaluation.suricata_alert_events,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

run_takeover_level() {
  local workers="$1"
  local repeat="$2"
  local remote_root attack_cmd rogue_cmd monitor_cmd victim_cmd cleanup_cmd renew_offset result_json run_dir run_suffix run_notes rogue_offset rogue_ip aux_trigger_mode victim_trigger_mode

  remote_root="$(research_workspace_root)"
  if [[ "${STARVATION_MODE}" == "rapid" ]]; then
    attack_cmd="sleep ${STARVATION_ATTACK_OFFSET}; cd '${remote_root}' && exec timeout -s INT ${STARVATION_ATTACK_SECONDS} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval ${STARVATION_RAPID_INTERVAL} --request-timeout ${STARVATION_REQUEST_TIMEOUT} --workers ${workers} --no-release-on-exit --rapid-pool --pool-start ${LAB_DHCP_RANGE_START} --pool-end ${LAB_DHCP_RANGE_END} --rapid-passes ${STARVATION_RAPID_PASSES}"
  else
    attack_cmd="sleep ${STARVATION_ATTACK_OFFSET}; cd '${remote_root}' && exec timeout -s INT ${STARVATION_ATTACK_SECONDS} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval ${STARVATION_CONFIRMED_INTERVAL} --request-timeout ${STARVATION_REQUEST_TIMEOUT} --workers ${workers} --cycles ${STARVATION_TARGET_LEASES} --no-release-on-exit"
  fi
  rogue_cmd=""
  monitor_cmd="$(dhcp_lease_monitor_cmd "${STARVATION_TAKEOVER_DURATION}" 1)"
  victim_cmd=""
  run_suffix="param-workers-${workers}-lease-flood"
  run_notes="DHCP starvation lease-pool flood worker-scaling run"
  rogue_offset=""
  rogue_ip=""
  aux_trigger_mode=""
  victim_trigger_mode=""
  if [[ "${TAKEOVER_ENABLE}" == "1" ]]; then
    rogue_offset="${ROGUE_DHCP_START_OFFSET_SECONDS}"
    rogue_ip="${ROGUE_DHCP_OFFERED_IP}"
    renew_offset="$((ROGUE_DHCP_START_OFFSET_SECONDS + 5))"
    if [[ "${TAKEOVER_START_MODE}" == "pool-full" ]]; then
      rogue_offset=""
      renew_offset="${TAKEOVER_RENEW_DELAY_SECONDS}"
      aux_trigger_mode="dhcp-pool-full"
      victim_trigger_mode="dhcp-pool-full"
      rogue_cmd="sleep ${ROGUE_DHCP_START_DELAY_SECONDS}; cd '${remote_root}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0 --reactive --offered-ip ${ROGUE_DHCP_OFFERED_IP}"
    else
      rogue_cmd="sleep ${ROGUE_DHCP_START_OFFSET_SECONDS}; cd '${remote_root}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0 --reactive --offered-ip ${ROGUE_DHCP_OFFERED_IP}"
    fi
    victim_cmd="$(victim_takeover_probe_cmd "${renew_offset}" "${ROGUE_DHCP_OFFERED_IP}" "${STARVATION_TAKEOVER_DURATION}" "${TAKEOVER_RENEW_INTERVAL_SECONDS}")"
    run_suffix="param-workers-${workers}-takeover"
    run_notes="DHCP starvation worker-scaling run followed by pool-full-gated reactive rogue DHCP takeover attempt"
  fi
  cleanup_cmd="$(dhcp_starvation_gateway_cleanup_cmd)"
  cleanup_cmd="${cleanup_cmd//__PREFIX__/${DHCP_STARVATION_MAC_PREFIX,,}}"

  info "DHCP starvation campaign: workers=${workers} takeover=${TAKEOVER_ENABLE} repeat=${repeat}/${STARVATION_TAKEOVER_RUNS}"
  remote_sudo_bash_lc gateway "${cleanup_cmd}" >/dev/null 2>&1 || true
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="attacker" \
  ATTACK_JOB_LABEL="dhcp-starvation" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  AUX_JOB_HOST="attacker" \
  AUX_JOB_LABEL="dhcp-spoof" \
  AUX_JOB_CMD="${rogue_cmd}" \
  AUX_JOB_USE_SUDO="1" \
  AUX_JOB_TRIGGER_MODE="${aux_trigger_mode}" \
  MONITOR_JOB_HOST="gateway" \
  MONITOR_JOB_LABEL="dhcp-lease-monitor" \
  MONITOR_JOB_CMD="${monitor_cmd}" \
  MONITOR_JOB_USE_SUDO="1" \
  VICTIM_JOB_HOST="victim" \
  VICTIM_JOB_LABEL="dhcp-takeover-probe" \
  VICTIM_JOB_CMD="${victim_cmd}" \
  VICTIM_JOB_USE_SUDO="1" \
  VICTIM_JOB_TRIGGER_MODE="${victim_trigger_mode}" \
  POST_CLEANUP_HOST="gateway" \
  POST_CLEANUP_LABEL="dhcp-starvation-cleanup" \
  POST_CLEANUP_CMD="${cleanup_cmd}" \
  POST_CLEANUP_USE_SUDO="1" \
  PLAN_RUN_INDEX="${workers}" \
  PLAN_WARMUP="0" \
  PLAN_DURATION_SECONDS="${STARVATION_TAKEOVER_DURATION}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${STARVATION_ATTACK_OFFSET}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="$((STARVATION_ATTACK_OFFSET + STARVATION_ATTACK_SECONDS))" \
  PLAN_FORWARDING_ENABLED="0" \
  PLAN_DNS_SPOOF_ENABLED="0" \
  PLAN_SPOOFED_DOMAINS="" \
  RUN_SLUG_SUFFIX="${run_suffix}" \
  DHCP_STARVATION_WORKERS="${workers}" \
  ROGUE_DHCP_START_OFFSET_SECONDS="${rogue_offset}" \
  ROGUE_DHCP_OFFERED_IP="${rogue_ip}" \
  TAKEOVER_ENABLE="${TAKEOVER_ENABLE}" \
  TAKEOVER_START_MODE="${TAKEOVER_START_MODE}" \
  TAKEOVER_RENEW_DELAY_SECONDS="${TAKEOVER_RENEW_DELAY_SECONDS}" \
  SENSOR_VISIBILITY_PERCENT="100" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
  RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" \
      "dhcp-starvation-rogue-dhcp" \
      "${STARVATION_TAKEOVER_DURATION}" \
      "${run_notes}"

  run_dir="$(latest_run_for "dhcp-starvation-rogue-dhcp")"
  result_json="$(score_latest_takeover_run)"
  printf '%s\n' "${result_json}" > "${run_dir}/starvation-takeover-result.json"
}

for workers in ${STARVATION_TAKEOVER_LEVELS}; do
  for ((repeat=1; repeat<=STARVATION_TAKEOVER_RUNS; repeat++)); do
    run_takeover_level "${workers}" "${repeat}"
  done
done

if [[ "${REPORT_ENABLE}" == "1" ]]; then
  PYTHONPATH=./python python3 -m reporting.cli "$(results_root)" --profile all --output-dir "$(results_root)/experiment-report"
fi
