#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${LAB_DIR}/lab.conf"

info() {
  printf '[*] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    warn "Missing required command: $1"
    exit 1
  }
}

run_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

have_libvirt_group() {
  id -nG "$USER" | tr ' ' '\n' | grep -qx libvirt
}

libvirt_direct_ok() {
  virsh -c "${LIBVIRT_URI}" uri >/dev/null 2>&1
}

run_hypervisor() {
  if libvirt_direct_ok; then
    "$@"
    return
  fi

  if have_libvirt_group; then
    local quoted
    printf -v quoted '%q ' "$@"
    sg libvirt -c "$quoted"
    return
  fi

  run_root "$@"
}

vm_disk_path() {
  local name="$1"
  printf '%s/%s.qcow2\n' "$STORAGE_ROOT" "$name"
}

generated_dir() {
  local name="$1"
  printf '%s/generated/%s\n' "$LAB_DIR" "$name"
}

indent_file() {
  local file="$1"
  sed 's/^/      /' "$file"
}
