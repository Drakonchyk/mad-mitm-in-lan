#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding"

start_danger_python_recording \
  "arp-mitm-dns-auto" \
  "${DURATION}" \
  "Automated ARP plus DNS scenario in isolated lab via attacker-side Python research helper" \
  "arp-mitm-dns-auto" \
  "${ATTACK_CMD}"
