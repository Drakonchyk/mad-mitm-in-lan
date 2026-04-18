#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"

run_automated_scenario_recording \
  "arp-mitm-dns" \
  "${DURATION}" \
  "Automated ARP MITM plus focused DNS spoofing for iana.org in the isolated lab" \
  "arp-mitm-dns" \
  "${ATTACK_CMD}"
