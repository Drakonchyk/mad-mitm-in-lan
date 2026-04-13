#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"

start_danger_recording \
  "arp-mitm-dns" \
  "${DURATION}" \
  "Manual ARP plus DNS scenario in isolated lab" \
  "${REPO_ROOT}/dangerous-scenarios/manual-steps/arp-dns.todo.sh"
