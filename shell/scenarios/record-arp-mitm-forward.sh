#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="1" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "arp-mitm-forward" \
  "${DURATION}" \
  "Automated ARP MITM with forwarding enabled in the isolated lab" \
  "arp-mitm-forward" \
  "${ATTACK_CMD}"
