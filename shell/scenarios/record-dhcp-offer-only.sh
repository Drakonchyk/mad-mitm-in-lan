#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-60}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0 --no-ack"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "dhcp-offer-only" \
  "${DURATION}" \
  "Automated rogue DHCP offer-only verification run in the isolated lab" \
  "dhcp-offer-only" \
  "${ATTACK_CMD}"
