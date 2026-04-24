#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/shell/experiment-common.sh"

virsh_direct() {
  virsh -c "${LIBVIRT_URI}" "$@" 2>/dev/null || true
}

vm_state() {
  local vm="$1"
  virsh_direct domstate "${vm}" | head -n 1 | xargs || true
}

quick_gateway_ip() {
  virsh_direct net-dhcp-leases default \
    | awk -v mac="${GATEWAY_UP_MAC,,}" '
        BEGIN { IGNORECASE = 1 }
        index(tolower($0), mac) {
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
              sub(/\/.*/, "", $i)
              print $i
              exit
            }
          }
        }
      '
}

default_net_present=0
bridge_present=0

if virsh -c "${LIBVIRT_URI}" net-info default >/dev/null 2>&1; then
  default_net_present=1
fi

if command -v ovs-vsctl >/dev/null 2>&1; then
  if ovs-vsctl br-exists "${LAB_SWITCH_BRIDGE}" >/dev/null 2>&1; then
    bridge_present=1
  elif sudo -n ovs-vsctl br-exists "${LAB_SWITCH_BRIDGE}" >/dev/null 2>&1; then
    bridge_present=1
  fi
fi

gateway_state="$(vm_state "${GATEWAY_NAME}")"
victim_state="$(vm_state "${VICTIM_NAME}")"
attacker_state="$(vm_state "${ATTACKER_NAME}")"
gateway_ip=""
victim_ip=""
attacker_ip=""

if [[ "${gateway_state,,}" == *"running"* ]]; then
  gateway_ip="$(quick_gateway_ip)"
fi

if [[ "${victim_state,,}" == *"running"* ]]; then
  victim_ip="$(lab_guest_ip victim 2>/dev/null || true)"
fi

if [[ "${attacker_state,,}" == *"running"* ]]; then
  attacker_ip="$(lab_guest_ip attacker 2>/dev/null || true)"
fi

python3 - <<PY
import json
from datetime import datetime, timezone

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "lab_name": ${LAB_NAME@Q},
    "switch_bridge": ${LAB_SWITCH_BRIDGE@Q},
    "sensor_interface": ${LAB_SWITCH_SENSOR_PORT@Q},
    "networks": {
        "default_present": bool(${default_net_present}),
        "switch_bridge_present": bool(${bridge_present}),
    },
    "hosts": {
        "gateway": {
            "vm_name": ${GATEWAY_NAME@Q},
            "state": ${gateway_state@Q},
            "ip": ${gateway_ip@Q},
            "mac": ${GATEWAY_LAB_MAC@Q},
        },
        "victim": {
            "vm_name": ${VICTIM_NAME@Q},
            "state": ${victim_state@Q},
            "ip": ${victim_ip@Q},
            "mac": ${VICTIM_MAC@Q},
        },
        "attacker": {
            "vm_name": ${ATTACKER_NAME@Q},
            "state": ${attacker_state@Q},
            "ip": ${attacker_ip@Q},
            "mac": ${ATTACKER_MAC@Q},
        },
    },
}

print(json.dumps(payload, sort_keys=True))
PY
