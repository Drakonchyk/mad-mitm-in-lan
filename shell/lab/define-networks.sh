#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

require_cmd virsh
require_cmd ovs-vsctl
require_cmd ip

DEFAULT_XML="${LAB_DIR}/libvirt/default-nat.xml"

ensure_libvirt_network() {
  local name="$1"
  local xml="$2"
  local persistent active

  if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$name" >/dev/null 2>&1; then
    persistent="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$name" \
        | awk '/^Persistent:/ {print $2}'
    )"
    active="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$name" \
        | awk '/^Active:/ {print $2}'
    )"

    if [[ "${persistent}" == "yes" ]]; then
      info "Network $name already defined"
    else
      warn "Network $name exists as a transient network; replacing it with the persistent lab definition"
      if [[ "${active}" == "yes" ]]; then
        run_hypervisor virsh -c "${LIBVIRT_URI}" net-destroy "$name" || true
      fi
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-define "$xml"
    fi
  else
    info "Defining network $name from $xml"
    run_hypervisor virsh -c "${LIBVIRT_URI}" net-define "$xml"
  fi

  info "Autostarting network $name"
  run_hypervisor virsh -c "${LIBVIRT_URI}" net-autostart "$name"

  if run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --name | grep -qx "$name"; then
    info "Network $name already active"
  else
    info "Starting network $name"
    run_hypervisor virsh -c "${LIBVIRT_URI}" net-start "$name"
  fi
}

ensure_ovs_switch() {
  local bridge="$1"
  local sensor_port="$2"

  if run_root ovs-vsctl br-exists "$bridge" >/dev/null 2>&1; then
    info "Open vSwitch bridge ${bridge} already exists"
  else
    info "Creating Open vSwitch bridge ${bridge}"
    run_root ovs-vsctl add-br "$bridge"
  fi

  if run_root ovs-vsctl list-ports "$bridge" | grep -qx "$sensor_port"; then
    info "Open vSwitch sensor port ${sensor_port} already exists"
  else
    info "Creating Open vSwitch internal sensor port ${sensor_port}"
    run_root ovs-vsctl add-port "$bridge" "$sensor_port" -- set Interface "$sensor_port" type=internal
  fi

  run_root ip link set dev "$bridge" up
  run_root ip link set dev "$sensor_port" up promisc on
}

remove_obsolete_libvirt_lab_network() {
  local persistent

  if ! run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "${LAB_NAME}" >/dev/null 2>&1; then
    return 0
  fi

  warn "Removing obsolete libvirt network ${LAB_NAME}; the lab LAN now lives on Open vSwitch ${LAB_SWITCH_BRIDGE}"
  run_hypervisor virsh -c "${LIBVIRT_URI}" net-destroy "${LAB_NAME}" >/dev/null 2>&1 || true
  if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "${LAB_NAME}" >/dev/null 2>&1; then
    persistent="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "${LAB_NAME}" \
        | awk '/^Persistent:/ {print $2}'
    )"
    if [[ "${persistent}" == "yes" ]]; then
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-undefine "${LAB_NAME}" || true
    fi
  fi
}

ensure_libvirt_network default "$DEFAULT_XML"
remove_obsolete_libvirt_lab_network
ensure_ovs_switch "${LAB_SWITCH_BRIDGE}" "${LAB_SWITCH_SENSOR_PORT}"

info "Networks ready"
run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all
run_root ovs-vsctl show
