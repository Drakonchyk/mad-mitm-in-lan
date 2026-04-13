#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"

start_danger_recording \
  "mitigation" \
  "${DURATION}" \
  "Manual mitigation scenario in isolated lab" \
  "${REPO_ROOT}/dangerous-scenarios/manual-steps/mitigation.todo.sh"
