#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_cmd qemu-img
require_cmd curl
require_cmd virsh

info "Preparing storage in ${STORAGE_ROOT}"
mkdir -p "${STORAGE_ROOT}"

POOL_NAME="${STORAGE_POOL_NAME}"
if run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" >/dev/null 2>&1; then
  info "Storage pool ${POOL_NAME} already defined"
else
  EXISTING_POOL_BY_PATH="$(pool_name_for_path "${STORAGE_ROOT}" || true)"
  if [[ -n "${EXISTING_POOL_BY_PATH}" ]]; then
    POOL_NAME="${EXISTING_POOL_BY_PATH}"
    info "Reusing existing storage pool ${POOL_NAME} for ${STORAGE_ROOT}"
  fi
fi

if test -f "${BASE_IMAGE_PATH}"; then
  info "Base image already exists: ${BASE_IMAGE_PATH}"
else
  info "Downloading Ubuntu cloud image"
  curl -fL --progress-bar "${BASE_IMAGE_URL}" -o "${BASE_IMAGE_PATH}"
fi

if run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" >/dev/null 2>&1; then
  :
else
  info "Defining storage pool ${POOL_NAME}"
  run_hypervisor virsh -c "${LIBVIRT_URI}" pool-define-as "${POOL_NAME}" dir --target "${STORAGE_ROOT}"
fi

POOL_STATE="$(run_hypervisor virsh -c "${LIBVIRT_URI}" pool-info "${POOL_NAME}" | awk '/^State:/ {print $2}')"
if [[ "${POOL_STATE}" == "running" ]]; then
  info "Storage pool ${POOL_NAME} already running"
else
  run_hypervisor virsh -c "${LIBVIRT_URI}" pool-build "${POOL_NAME}" || true
  run_hypervisor virsh -c "${LIBVIRT_URI}" pool-start "${POOL_NAME}" || true
fi
run_hypervisor virsh -c "${LIBVIRT_URI}" pool-autostart "${POOL_NAME}" || true

grant_libvirt_qemu_access() {
  command -v setfacl >/dev/null 2>&1 || return 0
  getent passwd libvirt-qemu >/dev/null 2>&1 || return 0

  local path="$STORAGE_ROOT"
  while [[ "$path" != "/" ]]; do
    if [[ -d "$path" && -O "$path" ]]; then
      setfacl -m u:libvirt-qemu:rx "$path" || true
    fi
    path="$(dirname "$path")"
  done

  setfacl -m u:libvirt-qemu:rx "$STORAGE_ROOT" || true
  setfacl -m d:u:libvirt-qemu:rx "$STORAGE_ROOT" || true
  find "$STORAGE_ROOT" -maxdepth 1 -type f -exec setfacl -m u:libvirt-qemu:r {} + || true
}

grant_libvirt_qemu_access

create_overlay() {
  local vm_name="$1"
  local size="$2"
  local disk
  disk="$(vm_disk_path "$vm_name")"

  if test -f "$disk"; then
    info "Disk already exists: $disk"
  else
    info "Creating overlay disk: $disk"
    qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE_PATH}" "$disk" "$size"
  fi
}

create_overlay "${GATEWAY_NAME}" "${GATEWAY_DISK_SIZE}"
create_overlay "${VICTIM_NAME}" "${VICTIM_DISK_SIZE}"
create_overlay "${ATTACKER_NAME}" "${ATTACKER_DISK_SIZE}"

grant_libvirt_qemu_access

mkdir -p "${LAB_DIR}/generated"
info "Storage ready"
