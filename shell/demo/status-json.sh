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
lease_snapshot_json="{}"

if [[ "${gateway_state,,}" == *"running"* ]]; then
  gateway_ip="$(quick_gateway_ip)"
  lease_snapshot_json="$(
    lab_ssh gateway "sudo python3 - '${VICTIM_MAC,,}' '${ATTACKER_MAC,,}' '${DHCP_STARVATION_MAC_PREFIX,,}' '${LAB_DHCP_RANGE_START}' '${LAB_DHCP_RANGE_END}' <<'PY'
from ipaddress import ip_address
import json
from pathlib import Path
import sys

victim_mac = sys.argv[1].lower()
attacker_mac = sys.argv[2].lower()
starvation_prefix = sys.argv[3].lower()
range_start = ip_address(sys.argv[4])
range_end = ip_address(sys.argv[5])

leases = []
for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
    if not candidate.exists():
        continue
    for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
        parts = raw_line.split()
        if len(parts) < 3:
            continue
        try:
            lease_ip = ip_address(parts[2])
        except ValueError:
            continue
        if not (range_start <= lease_ip <= range_end):
            continue
        leases.append({
            'expiry': parts[0],
            'mac': parts[1].lower(),
            'ip': str(lease_ip),
            'hostname': parts[3] if len(parts) >= 4 else '',
        })

attack_leases = [lease for lease in leases if lease['mac'].startswith(starvation_prefix)]
payload = {
    'victim_ip': next((lease['ip'] for lease in leases if lease['mac'] == victim_mac), ''),
    'attacker_ip': next((lease['ip'] for lease in leases if lease['mac'] == attacker_mac), ''),
    'pool_total': int(range_end) - int(range_start) + 1,
    'taken': len(leases),
    'attack_taken': len(attack_leases),
    'normal_taken': len(leases) - len(attack_leases),
    'free': (int(range_end) - int(range_start) + 1) - len(leases),
    'attack_ips': [lease['ip'] for lease in attack_leases[:8]],
}
print(json.dumps(payload, sort_keys=True))
PY" 2>/dev/null || printf '{}'
  )"
fi

python3 - <<PY
import json
from datetime import datetime, timezone

lease_snapshot = json.loads(${lease_snapshot_json@Q}) if ${lease_snapshot_json@Q} else {}

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
            "ip": lease_snapshot.get("victim_ip", ""),
            "mac": ${VICTIM_MAC@Q},
        },
        "attacker": {
            "vm_name": ${ATTACKER_NAME@Q},
            "state": ${attacker_state@Q},
            "ip": lease_snapshot.get("attacker_ip", ""),
            "mac": ${ATTACKER_MAC@Q},
        },
    },
    "dhcp_pool": lease_snapshot,
}

print(json.dumps(payload, sort_keys=True))
PY
