#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

GENERATED_ROOT="${LAB_DIR}/generated"

remove_path() {
  local path="$1"

  [[ -e "$path" ]] || return 0

  if rm -rf "$path" 2>/dev/null; then
    return 0
  fi

  warn "Direct removal failed for ${path}; retrying with sudo"
  run_root rm -rf "$path"
}

warn "This will destroy the MITM lab VMs, disks, networks, storage pool, and generated files."
warn "It will remove ${STORAGE_ROOT} and ${GENERATED_ROOT}."
read -r -p "Type DESTROY to continue: " answer
[[ "$answer" == "DESTROY" ]] || { warn "Teardown aborted"; exit 1; }

for vm in "${GATEWAY_NAME}" "${VICTIM_NAME}" "${ATTACKER_NAME}"; do
  if run_hypervisor virsh -c "${LIBVIRT_URI}" dominfo "$vm" >/dev/null 2>&1; then
    if run_hypervisor virsh -c "${LIBVIRT_URI}" domstate "$vm" | grep -qi running; then
      info "Stopping $vm"
      run_hypervisor virsh -c "${LIBVIRT_URI}" destroy "$vm"
    fi
    info "Undefining $vm"
    run_hypervisor virsh -c "${LIBVIRT_URI}" undefine "$vm" --nvram || run_hypervisor virsh -c "${LIBVIRT_URI}" undefine "$vm"
  fi
done

for net in "${LAB_NAME}" default; do
  if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$net" >/dev/null 2>&1; then
    PERSISTENT="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$net" \
        | awk '/^Persistent:/ {print $2}'
    )"
    if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$net" | grep -q '^Active:.*yes'; then
      info "Destroying network $net"
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-destroy "$net" || true
    fi
    if [[ "${PERSISTENT}" == "yes" ]]; then
      info "Undefining network $net"
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-undefine "$net" || true
    else
      info "Network $net was transient and has been removed by destroy"
    fi
  fi
done

for disk in \
  "$(vm_disk_path "${GATEWAY_NAME}")" \
  "$(vm_disk_path "${VICTIM_NAME}")" \
  "$(vm_disk_path "${ATTACKER_NAME}")"; do
  if test -f "$disk"; then
    info "Removing $disk"
    rm -f "$disk"
  fi
done

POOL_NAME="$(pool_name_for_path "${STORAGE_ROOT}" || true)"
if [[ -z "${POOL_NAME}" ]] && run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${STORAGE_POOL_NAME}" >/dev/null 2>&1; then
  POOL_NAME="${STORAGE_POOL_NAME}"
fi

if [[ -n "${POOL_NAME}" ]] && run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" >/dev/null 2>&1; then
  if run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" | grep -q '^State:.*running'; then
    info "Destroying storage pool ${POOL_NAME}"
    run_hypervisor virsh -c "${LIBVIRT_URI}" pool-destroy "${POOL_NAME}" || true
    sleep 1
  fi
  if run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" | grep -q '^State:.*running'; then
    warn "Storage pool ${POOL_NAME} is still active after destroy; skipping undefine for now"
  else
    info "Undefining storage pool ${POOL_NAME}"
    run_hypervisor virsh -c "${LIBVIRT_URI}" pool-undefine "${POOL_NAME}" || true
  fi
fi

if [[ -d "${STORAGE_ROOT}" ]]; then
  info "Removing storage directory ${STORAGE_ROOT}"
  remove_path "${STORAGE_ROOT}"
fi

if [[ -d "${GENERATED_ROOT}" ]]; then
  info "Removing generated directory ${GENERATED_ROOT}"
  remove_path "${GENERATED_ROOT}"
fi

info "Lab teardown complete"
