#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

for vm in "${GATEWAY_NAME}" "${VICTIM_NAME}" "${ATTACKER_NAME}"; do
  if run_hypervisor virsh -c "${LIBVIRT_URI}" domstate "$vm" | grep -qi running; then
    info "$vm is already running"
  else
    info "Starting $vm"
    run_hypervisor virsh -c "${LIBVIRT_URI}" start "$vm"
  fi
done

run_hypervisor virsh -c "${LIBVIRT_URI}" list --all
