#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf '[info] experiment-plan-extra now runs the reliability campaign\n' >&2
exec "${SCRIPT_DIR}/run-reliability-plan.sh" "$@"
