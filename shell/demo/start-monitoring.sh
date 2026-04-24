#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

require_experiment_tools
start_lab_and_wait_for_access
prepare_victim_detector
prepare_victim_zeek
prepare_victim_suricata

info "Demo monitoring stack is ready on ${LAB_SWITCH_SENSOR_PORT}"
