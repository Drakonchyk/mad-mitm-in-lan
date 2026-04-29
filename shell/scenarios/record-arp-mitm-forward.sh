#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-30}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_RUNTIME=$((DURATION - 10))
ATTACK_CMD="sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT ${ATTACK_RUNTIME} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0 --victim-ip __VICTIM_IP__ --gateway-ip __GATEWAY_IP__ --interval 1.0 --enable-forwarding"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_ATTACK_START_OFFSET_SECONDS="5" \
PLAN_ATTACK_STOP_OFFSET_SECONDS="$((DURATION - 5))" \
PLAN_FORWARDING_ENABLED="1" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "arp-mitm-forward" \
  "${DURATION}" \
  "Automated ARP MITM with forwarding enabled in the isolated lab" \
  "arp-mitm-forward" \
  "${ATTACK_CMD}"
