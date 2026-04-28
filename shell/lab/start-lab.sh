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

ovs_ofport() {
  local port="$1"
  run_root ovs-vsctl get Interface "${port}" ofport 2>/dev/null | tr -d '[:space:]'
}

refresh_dhcp_snooping_flows() {
  local bridge="$1"
  local victim_port="$2"
  local attacker_port="$3"
  local sensor_port="$4"
  local gateway_port="$5"
  local cookie="0x4d49544d"
  local mode action port ofport

  if ! command -v ovs-ofctl >/dev/null 2>&1; then
    warn "ovs-ofctl is missing; cannot refresh DHCP snooping flows"
    return 0
  fi

  run_root ovs-ofctl del-flows "${bridge}" "cookie=${cookie}/-1" >/dev/null 2>&1 || true
  mode="$(dhcp_snooping_mode)"
  run_root ovs-vsctl set Bridge "${bridge}" \
    external_ids:dhcp_snooping_mode="${mode}" \
    external_ids:dhcp_trusted_server_port="${gateway_port}" \
    external_ids:dhcp_trusted_server_mac="${GATEWAY_LAB_MAC,,}" \
    external_ids:dhcp_trusted_server_ip="${GATEWAY_IP}"

  if [[ "${mode}" == "off" ]]; then
    info "OVS DHCP snooping monitor is off"
    return 0
  fi

  if [[ "${mode}" == "enforce" ]]; then
    action="drop"
    info "Installing OVS DHCP snooping flows in enforce mode: only the gateway port is DHCP-server trusted"
  else
    action="NORMAL"
    info "Installing OVS DHCP snooping flows in monitor mode: non-gateway DHCP server replies are counted and forwarded"
  fi

  for port in "${victim_port}" "${attacker_port}"; do
    ofport="$(ovs_ofport "${port}")"
    if [[ -z "${ofport}" || "${ofport}" == "-1" ]]; then
      warn "Could not resolve ofport for ${port}; skipping DHCP snooping flow"
      continue
    fi
    run_root ovs-ofctl add-flow "${bridge}" \
      "cookie=${cookie},priority=300,in_port=${ofport},udp,tp_src=67,tp_dst=68,actions=${action}"
  done
  run_root ovs-ofctl add-flow "${bridge}" "cookie=${cookie},priority=0,actions=NORMAL"
}

refresh_switch_truth_snooping_flows() {
  local bridge="$1"
  local victim_port="$2"
  local attacker_port="$3"
  local sensor_port="$4"
  local cookie="0x4d49544e"
  local port ofport

  if ! command -v ovs-ofctl >/dev/null 2>&1; then
    warn "ovs-ofctl is missing; cannot refresh switch truth snooping flows"
    return 0
  fi

  run_root ovs-ofctl del-flows "${bridge}" "cookie=${cookie}/-1" >/dev/null 2>&1 || true
  if [[ "${LAB_SWITCH_TRUTH_SNOOPING:-1}" != "1" ]]; then
    info "OVS switch truth snooping is off"
    return 0
  fi

  info "Installing OVS switch truth snooping flows for ARP and DNS trust violations"
  for port in "${victim_port}" "${attacker_port}"; do
    ofport="$(ovs_ofport "${port}")"
    if [[ -z "${ofport}" || "${ofport}" == "-1" ]]; then
      warn "Could not resolve ofport for ${port}; skipping switch truth snooping flows"
      continue
    fi
    run_root ovs-ofctl add-flow "${bridge}" \
      "cookie=${cookie},priority=290,in_port=${ofport},arp,arp_op=2,arp_spa=${GATEWAY_IP},actions=NORMAL"
    run_root ovs-ofctl add-flow "${bridge}" \
      "cookie=${cookie},priority=290,in_port=${ofport},udp,nw_src=${DNS_SERVER},tp_src=53,actions=NORMAL"
  done
  run_root ovs-ofctl add-flow "${bridge}" "cookie=${cookie},priority=0,actions=NORMAL"
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
	  refresh_dhcp_snooping_flows "${bridge}" "${victim_port}" "${attacker_port}" "${sensor_port}" "${gateway_port}"
  refresh_switch_truth_snooping_flows "${bridge}" "${victim_port}" "${attacker_port}" "${sensor_port}"
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
