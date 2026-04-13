#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/00-host-prereqs.sh"
"${SCRIPT_DIR}/10-define-networks.sh"
"${SCRIPT_DIR}/20-prepare-storage.sh"
"${SCRIPT_DIR}/30-build-cloud-init.sh"
"${SCRIPT_DIR}/40-create-vms.sh"
"${SCRIPT_DIR}/60-status.sh"
