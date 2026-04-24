#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

stop_local_detector
stop_local_zeek
stop_local_suricata

info "Demo monitoring stack has been stopped"
