#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-60}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_START_SECONDS="${ATTACK_START_SECONDS:-5}"
ATTACK_ACTIVE_SECONDS="${ATTACK_ACTIVE_SECONDS:-25}"
MITIGATION_START_SECONDS="${MITIGATION_START_SECONDS:-$((ATTACK_START_SECONDS + ATTACK_ACTIVE_SECONDS))}"

start_lab_and_wait_for_access
verify_isolated_lab
prepare_attacker_research_workspace

ATTACK_CMD="sleep ${ATTACK_START_SECONDS}; cd '${REMOTE_ROOT}' && exec timeout -s INT ${ATTACK_ACTIVE_SECONDS} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"
AUX_CMD="sleep ${MITIGATION_START_SECONDS}; ip neigh replace '${GATEWAY_IP}' lladdr '${GATEWAY_LAB_MAC}' nud permanent dev vnic0"

SKIP_LAB_START="1" \
ATTACK_JOB_HOST="attacker" \
ATTACK_JOB_LABEL="mitigation-recovery" \
ATTACK_JOB_CMD="${ATTACK_CMD}" \
ATTACK_JOB_USE_SUDO="1" \
AUX_JOB_HOST="victim" \
AUX_JOB_LABEL="mitigation-step" \
AUX_JOB_CMD="${AUX_CMD}" \
AUX_JOB_USE_SUDO="1" \
PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_ATTACK_START_OFFSET_SECONDS="${ATTACK_START_SECONDS}" \
PLAN_ATTACK_STOP_OFFSET_SECONDS="${MITIGATION_START_SECONDS}" \
PLAN_MITIGATION_START_OFFSET_SECONDS="${MITIGATION_START_SECONDS}" \
PLAN_FORWARDING_ENABLED="1" \
PLAN_DNS_SPOOF_ENABLED="1" \
PLAN_SPOOFED_DOMAINS="iana.org" \
  "${REPO_ROOT}/shell/experiments/run-scenario-window.sh" \
  "mitigation-recovery" \
  "${DURATION}" \
  "Automated mitigation scenario with ARP MITM, DNS spoofing, and victim-side neighbor restoration"
