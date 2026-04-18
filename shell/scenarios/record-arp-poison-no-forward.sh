#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf arp-poison --interface vnic0"

run_automated_scenario_recording \
  "arp-poison-no-forward" \
  "${DURATION}" \
  "Automated ARP poisoning without forwarding in isolated lab" \
  "arp-poison-no-forward" \
  "${ATTACK_CMD}"
