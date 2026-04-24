#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../common.sh"

LAB_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_cmd virt-install
require_cmd virsh

"${LAB_SCRIPT_DIR}/build-cloud-init.sh"

create_vm() {
  local name="$1"
  shift

  if run_hypervisor virsh -c "${LIBVIRT_URI}" dominfo "$name" >/dev/null 2>&1; then
    info "VM $name already exists"
    return 0
  fi

  info "Creating VM $name"
  run_hypervisor virt-install --connect "${LIBVIRT_URI}" "$@"
}

create_vm "${GATEWAY_NAME}" \
  --name "${GATEWAY_NAME}" \
  --memory "${GATEWAY_RAM_MB}" \
  --vcpus "${GATEWAY_VCPUS}" \
  --cpu host-passthrough \
  --osinfo "${OS_VARIANT}" \
  --disk "path=$(vm_disk_path "${GATEWAY_NAME}"),format=qcow2,bus=virtio" \
  --network "network=default,model=virtio,mac=${GATEWAY_UP_MAC}" \
  --network "bridge=${LAB_SWITCH_BRIDGE},virtualport_type=openvswitch,model=virtio,mac=${GATEWAY_LAB_MAC}" \
  --graphics none \
  --console pty,target_type=serial \
  --import \
  --cloud-init "user-data=$(generated_dir gateway)/user-data.yaml,meta-data=$(generated_dir gateway)/meta-data.yaml,network-config=$(generated_dir gateway)/network-config.yaml,disable=on" \
  --noautoconsole

create_vm "${VICTIM_NAME}" \
  --name "${VICTIM_NAME}" \
  --memory "${VICTIM_RAM_MB}" \
  --vcpus "${VICTIM_VCPUS}" \
  --cpu host-passthrough \
  --osinfo "${OS_VARIANT}" \
  --disk "path=$(vm_disk_path "${VICTIM_NAME}"),format=qcow2,bus=virtio" \
  --network "bridge=${LAB_SWITCH_BRIDGE},virtualport_type=openvswitch,model=virtio,mac=${VICTIM_MAC}" \
  --graphics none \
  --console pty,target_type=serial \
  --import \
  --cloud-init "user-data=$(generated_dir victim)/user-data.yaml,meta-data=$(generated_dir victim)/meta-data.yaml,network-config=$(generated_dir victim)/network-config.yaml,disable=on" \
  --noautoconsole

create_vm "${ATTACKER_NAME}" \
  --name "${ATTACKER_NAME}" \
  --memory "${ATTACKER_RAM_MB}" \
  --vcpus "${ATTACKER_VCPUS}" \
  --cpu host-passthrough \
  --osinfo "${OS_VARIANT}" \
  --disk "path=$(vm_disk_path "${ATTACKER_NAME}"),format=qcow2,bus=virtio" \
  --network "bridge=${LAB_SWITCH_BRIDGE},virtualport_type=openvswitch,model=virtio,mac=${ATTACKER_MAC}" \
  --graphics none \
  --console pty,target_type=serial \
  --import \
  --cloud-init "user-data=$(generated_dir attacker)/user-data.yaml,meta-data=$(generated_dir attacker)/meta-data.yaml,network-config=$(generated_dir attacker)/network-config.yaml,disable=on" \
  --noautoconsole

info "VM creation complete"
run_hypervisor virsh -c "${LIBVIRT_URI}" list --all
