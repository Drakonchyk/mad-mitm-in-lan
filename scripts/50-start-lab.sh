#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

for vm in "${GATEWAY_NAME}" "${VICTIM_NAME}" "${ATTACKER_NAME}"; do
  state="$(run_hypervisor virsh -c "${LIBVIRT_URI}" domstate "$vm" 2>/dev/null | tr -d '[:space:]')"

  if [[ "${state,,}" == "running" ]]; then
    info "$vm is already running"
  else
    info "Starting $vm"
    if ! output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" start "$vm" 2>&1)"; then
      if grep -qi "already active" <<< "${output}"; then
        info "$vm became active while starting"
      else
        printf '%s\n' "${output}" >&2
        exit 1
      fi
    else
      printf '%s\n' "${output}"
    fi
  fi
done

run_hypervisor virsh -c "${LIBVIRT_URI}" list --all
