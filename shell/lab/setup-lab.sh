#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/host-prereqs.sh"
"${SCRIPT_DIR}/define-networks.sh"
"${SCRIPT_DIR}/prepare-storage.sh"
"${SCRIPT_DIR}/build-cloud-init.sh"
"${SCRIPT_DIR}/create-vms.sh"
"${SCRIPT_DIR}/status.sh"
