#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${1:-${TARGET:-results}}"
OUTPUT_ROOT="${2:-${OUTPUT_ROOT:-results/demo-report}}"
MAX_RUNS_PER_SCENARIO="${MAX_RUNS_PER_SCENARIO:-1}"

build_profile_if_present() {
  local profile="$1"
  local output_dir="$2"

  if PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m reporting.cli "${TARGET}" \
    --profile "${profile}" \
    --output-dir "${output_dir}" \
    --max-runs-per-scenario "${MAX_RUNS_PER_SCENARIO}" >/tmp/mitm-lab-demo-report-"${profile}".log 2>&1; then
    cat /tmp/mitm-lab-demo-report-"${profile}".log
    return 0
  fi

  if grep -q "No evaluated runs found" /tmp/mitm-lab-demo-report-"${profile}".log; then
    printf '[*] Skipping %s demo report because no matching retained runs were found under %s\n' "${profile}" "${TARGET}"
    return 0
  fi

  cat /tmp/mitm-lab-demo-report-"${profile}".log >&2
  return 1
}

rm -rf "${OUTPUT_ROOT}"
mkdir -p "${OUTPUT_ROOT}"

build_profile_if_present main "${OUTPUT_ROOT}/main"
build_profile_if_present supplementary "${OUTPUT_ROOT}/supplementary"

cat > "${OUTPUT_ROOT}/README.md" <<EOF
# Demo Report

This directory holds small deterministic reports built from at most ${MAX_RUNS_PER_SCENARIO} retained measured run per scenario.

- Main evaluation report: \`main/experiment-report.md\`
- Supplementary evaluation report: \`supplementary/experiment-report.md\`

Rebuild with:

\`\`\`bash
make demo-report
\`\`\`
EOF
