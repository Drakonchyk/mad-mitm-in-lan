#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

info "Networks"
run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all

echo
info "VMs"
run_hypervisor virsh -c "${LIBVIRT_URI}" list --all

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
