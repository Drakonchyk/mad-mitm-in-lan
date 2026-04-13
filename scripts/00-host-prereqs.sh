#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

info "Checking host prerequisites"

for cmd in virsh virt-install qemu-img curl; do
  require_cmd "$cmd"
done

info "Using libvirt URI: ${LIBVIRT_URI}"

if libvirt_direct_ok; then
  info "System libvirt is reachable directly from this shell"
elif have_libvirt_group && sg libvirt -c "virsh -c '${LIBVIRT_URI}' uri" >/dev/null 2>&1; then
  warn "System libvirt is reachable through 'sg libvirt -c', but not directly from this shell"
  warn "A logout/login usually fixes this for direct access"
else
  warn "Cannot reach ${LIBVIRT_URI} from this shell"
  warn "If needed, run: sudo adduser $USER libvirt"
  warn "Then log out and back in before running setup again"
fi

if have_libvirt_group; then
  info "User ${USER} is in the libvirt group"
else
  warn "User ${USER} is not in the libvirt group"
fi

if sudo -n true >/dev/null 2>&1; then
  info "Passwordless sudo is available"
else
  warn "Passwordless sudo is not available; setup scripts may prompt for your sudo password"
fi

info "Current libvirt networks:"
run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all || true

info "Current libvirt domains:"
run_hypervisor virsh -c "${LIBVIRT_URI}" list --all || true
