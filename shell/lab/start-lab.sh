#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

vm_interface_target_by_mac() {
  local vm="$1"
  local mac="$2"

  run_hypervisor virsh -c "${LIBVIRT_URI}" domiflist "$vm" 2>/dev/null \
    | awk -v wanted="${mac,,}" '
        BEGIN { IGNORECASE = 1 }
        $0 ~ /^[[:space:]]*$/ { next }
        tolower($5) == wanted { print $1; exit }
      '
}

refresh_lab_switch_mirror() {
  local bridge="${LAB_SWITCH_BRIDGE}"
  local sensor_port="${LAB_SWITCH_SENSOR_PORT}"
  local mirror_name="${LAB_SWITCH_MIRROR}"
  local gateway_port victim_port attacker_port

  gateway_port="$(vm_interface_target_by_mac "${GATEWAY_NAME}" "${GATEWAY_LAB_MAC}")"
  victim_port="$(vm_interface_target_by_mac "${VICTIM_NAME}" "${VICTIM_MAC}")"
  attacker_port="$(vm_interface_target_by_mac "${ATTACKER_NAME}" "${ATTACKER_MAC}")"

  if [[ -z "${gateway_port}" || -z "${victim_port}" || -z "${attacker_port}" ]]; then
    warn "Could not resolve all OVS lab ports; skipping mirror refresh"
    return 0
  fi

  info "Refreshing Open vSwitch mirror ${mirror_name} on ${bridge}"
  run_root ip link set dev "${sensor_port}" up promisc on
  run_root ovs-vsctl set Bridge "${bridge}" fail_mode=standalone
  run_root ovs-vsctl \
    set Port "${gateway_port}" external_ids:mitm_lab_role=gateway external_ids:dhcp_trusted=true \
    -- set Port "${victim_port}" external_ids:mitm_lab_role=victim external_ids:dhcp_trusted=false \
    -- set Port "${attacker_port}" external_ids:mitm_lab_role=attacker external_ids:dhcp_trusted=false \
    -- set Port "${sensor_port}" external_ids:mitm_lab_role=sensor external_ids:dhcp_trusted=false
  run_root ovs-vsctl clear Bridge "${bridge}" mirrors
  run_root ovs-vsctl \
    -- --id=@sensor get Port "${sensor_port}" \
    -- --id=@gw get Port "${gateway_port}" \
    -- --id=@victim get Port "${victim_port}" \
    -- --id=@attacker get Port "${attacker_port}" \
    -- --id=@mirror create Mirror "name=${mirror_name}" \
      select-src-port=@gw,@victim,@attacker \
      select-dst-port=@gw,@victim,@attacker \
      output-port=@sensor \
    -- set Bridge "${bridge}" mirrors=@mirror
}

for vm in "${GATEWAY_NAME}" "${VICTIM_NAME}" "${ATTACKER_NAME}"; do
  state="$(run_hypervisor virsh -c "${LIBVIRT_URI}" domstate "$vm" 2>/dev/null | tr -d '[:space:]')"

  if [[ "${state,,}" == "running" ]]; then
    info "$vm is already running"
  else
    info "Starting $vm"
    if ! output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" start "$vm" 2>&1)"; then
      if grep -qi "already active" <<< "${output}"; then
        info "$vm became active while starting"
      else
        printf '%s\n' "${output}" >&2
        exit 1
      fi
    else
      printf '%s\n' "${output}"
    fi
  fi
done

refresh_lab_switch_mirror

run_hypervisor virsh -c "${LIBVIRT_URI}" list --all
