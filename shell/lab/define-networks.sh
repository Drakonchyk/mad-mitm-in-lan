#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

require_cmd virsh

DEFAULT_XML="${LAB_DIR}/libvirt/default-nat.xml"
LAB_XML="${LAB_DIR}/libvirt/mitm-lab.xml"

ensure_network() {
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

ensure_network default "$DEFAULT_XML"
ensure_network "${LAB_NAME}" "$LAB_XML"

info "Networks ready"
run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all
