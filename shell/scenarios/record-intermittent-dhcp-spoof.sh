#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && for pulse in 1 2 3 4; do timeout -s INT 5 env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 1.0 || true; if [[ \"\$pulse\" -lt 4 ]]; then sleep 10; fi; done"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "intermittent-dhcp-spoof" \
  "${DURATION}" \
  "Automated pulsed rogue DHCP spoofing run in the isolated lab" \
  "intermittent-dhcp-spoof" \
  "${ATTACK_CMD}"
