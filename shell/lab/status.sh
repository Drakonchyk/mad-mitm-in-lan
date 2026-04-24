#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

info "Networks"
run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all

echo
info "VMs"
run_hypervisor virsh -c "${LIBVIRT_URI}" list --all

echo
info "Open vSwitch"
if command -v ovs-vsctl >/dev/null 2>&1; then
  if ovs-vsctl show >/dev/null 2>&1; then
    ovs-vsctl show || true
    echo
    ovs-vsctl list Mirror || true
  else
    run_root ovs-vsctl show || true
    echo
    run_root ovs-vsctl list Mirror || true
  fi
  echo
else
  warn "ovs-vsctl not found"
fi

echo
info "VM interfaces"
for vm in "${GATEWAY_NAME}" "${VICTIM_NAME}" "${ATTACKER_NAME}"; do
  echo "--- ${vm} ---"
  run_hypervisor virsh -c "${LIBVIRT_URI}" domiflist "$vm" || true
  echo
done

echo "Console examples:"
echo "  sg libvirt -c 'virsh -c ${LIBVIRT_URI} console ${GATEWAY_NAME}'"
echo "  sg libvirt -c 'virsh -c ${LIBVIRT_URI} console ${VICTIM_NAME}'"
echo "  sg libvirt -c 'virsh -c ${LIBVIRT_URI} console ${ATTACKER_NAME}'"
