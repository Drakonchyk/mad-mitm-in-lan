#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf arp-poison --interface vnic0 --enable-forwarding"

start_danger_python_recording \
  "arp-mitm-auto" \
  "${DURATION}" \
  "Automated ARP MITM run in isolated lab via attacker-side Python research helper" \
  "arp-mitm-auto" \
  "${ATTACK_CMD}"
