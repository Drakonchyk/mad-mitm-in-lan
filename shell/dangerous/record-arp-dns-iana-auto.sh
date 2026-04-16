#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"

start_danger_python_recording \
  "arp-mitm-dns-iana-auto" \
  "${DURATION}" \
  "Automated ARP plus DNS scenario for iana.org in isolated lab" \
  "arp-mitm-dns-iana-auto" \
  "${ATTACK_CMD}"
