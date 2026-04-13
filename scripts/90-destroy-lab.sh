#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

warn "This will destroy the MITM lab VMs, disks, and networks created by this bundle."
read -r -p "Type DESTROY to continue: " answer
[[ "$answer" == "DESTROY" ]] || { info "Aborted"; exit 0; }

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
    if run_hypervisor virsh -c "${LIBVIRT_URI}" net-info "$net" | grep -q '^Active:.*yes'; then
      info "Destroying network $net"
      run_hypervisor virsh -c "${LIBVIRT_URI}" net-destroy "$net" || true
    fi
    info "Undefining network $net"
    run_hypervisor virsh -c "${LIBVIRT_URI}" net-undefine "$net" || true
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

if test -f "${BASE_IMAGE_PATH}"; then
  info "Keeping base image: ${BASE_IMAGE_PATH}"
fi

info "Lab teardown complete"
