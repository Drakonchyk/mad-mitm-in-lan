#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${1:-${REPO_ROOT}/results}"

python3 "${REPO_ROOT}/python/summarize_results.py" "${TARGET}"
