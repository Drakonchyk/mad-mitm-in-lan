#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/scripts/common.sh"

danger_info() {
  printf '[danger] %s\n' "$*"
}

require_sudo_refresh() {
  danger_info "Refreshing sudo credentials before continuing"
  sudo -k
  sudo -v
}

confirm_danger_run() {
  local scenario="$1"

  printf '\n'
  warn "This wrapper is only for the isolated ${LAB_NAME} lab."
  warn "Do not continue unless you intend to run a manual scenario only inside these VMs."
  read -r -p "Type ${scenario} to continue: " answer
  [[ "${answer}" == "${scenario}" ]] || {
    warn "Manual scenario aborted"
    exit 1
  }
}

verify_isolated_lab() {
  local expected_gateway expected_victim expected_attacker net_output vm_output

  expected_gateway="$(gateway_upstream_ip)"
  expected_victim="$(cidr_addr "${VICTIM_CIDR}")"
  expected_attacker="$(cidr_addr "${ATTACKER_CIDR}")"

  net_output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all)"
  vm_output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" list --all)"

  [[ "${net_output}" == *" default "* ]] || {
    warn "default network is missing"
    exit 1
  }
  [[ "${net_output}" == *" ${LAB_NAME} "* ]] || {
    warn "${LAB_NAME} network is missing"
    exit 1
  }
  [[ "${vm_output}" == *"${GATEWAY_NAME}"* ]] || {
    warn "${GATEWAY_NAME} VM is missing"
    exit 1
  }
  [[ "${vm_output}" == *"${VICTIM_NAME}"* ]] || {
    warn "${VICTIM_NAME} VM is missing"
    exit 1
  }
  [[ "${vm_output}" == *"${ATTACKER_NAME}"* ]] || {
    warn "${ATTACKER_NAME} VM is missing"
    exit 1
  }

  danger_info "Isolated lab looks present"
  danger_info "Gateway upstream IP: ${expected_gateway}"
  danger_info "Victim lab IP: ${expected_victim}"
  danger_info "Attacker lab IP: ${expected_attacker}"
}

start_danger_recording() {
  local scenario_name="$1"
  local duration="$2"
  local note="$3"
  local placeholder="$4"

  verify_isolated_lab
  require_sudo_refresh
  confirm_danger_run "${scenario_name}"

  danger_info "Manual placeholder: ${placeholder}"
  danger_info "Starting recording window for ${scenario_name}"
  "${REPO_ROOT}/scripts/80-record-manual-scenario.sh" "${scenario_name}" "${duration}" "${note}"
}
