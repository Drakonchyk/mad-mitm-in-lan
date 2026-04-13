#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_cmd virsh

DEFAULT_XML="${LAB_DIR}/libvirt/default-nat.xml"
LAB_XML="${LAB_DIR}/libvirt/mitm-lab.xml"

ensure_network() {
  local name="$1"
  local xml="$2"

  if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$name" >/dev/null 2>&1; then
    info "Network $name already defined"
  else
    info "Defining network $name from $xml"
    run_hypervisor virsh -c "${LIBVIRT_URI}" net-define "$xml"
  fi

  info "Autostarting network $name"
  run_hypervisor virsh -c "${LIBVIRT_URI}" net-autostart "$name" || true

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
