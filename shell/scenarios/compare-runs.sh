#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${1:-${REPO_ROOT}/results}"

PYTHONPATH="${REPO_ROOT}/python${PYTHONPATH:+:${PYTHONPATH}}" \
  python3 -m metrics.summary_cli "${TARGET}"
