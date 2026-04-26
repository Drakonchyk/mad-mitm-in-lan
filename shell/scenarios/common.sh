#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/shell/experiment-common.sh"

scenario_info() {
  printf '[scenario] %s\n' "$*"
}

verify_isolated_lab() {
  local expected_gateway expected_victim expected_attacker net_output vm_output

  expected_gateway="$(gateway_upstream_ip)"
  expected_victim="$(lab_host_ip victim 2>/dev/null || printf 'pending-dhcp-lease')"
  expected_attacker="$(lab_host_ip attacker 2>/dev/null || printf 'pending-dhcp-lease')"

  net_output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" net-list --all)"
  vm_output="$(run_hypervisor virsh -c "${LIBVIRT_URI}" list --all)"

  [[ "${net_output}" == *" default "* ]] || {
    warn "default network is missing"
    exit 1
  }
  if ! run_root ovs-vsctl br-exists "${LAB_SWITCH_BRIDGE}" >/dev/null 2>&1; then
    warn "Open vSwitch bridge ${LAB_SWITCH_BRIDGE} is missing"
    exit 1
  fi
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

  scenario_info "Isolated lab looks present"
  scenario_info "Gateway upstream IP: ${expected_gateway}"
  scenario_info "Victim lab IP: ${expected_victim}"
  scenario_info "Attacker lab IP: ${expected_attacker}"
}

run_automated_scenario_recording() {
  local scenario_name="$1"
  local duration="$2"
  local note="$3"
  local attack_label="$4"
  local attack_cmd="$5"

  start_lab_and_wait_for_access
  verify_isolated_lab
  prepare_attacker_research_workspace

  scenario_info "Automated attacker command: ${attack_cmd}"
  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="attacker" \
  ATTACK_JOB_LABEL="${attack_label}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  PCAP_ENABLE="${PCAP_ENABLE:-1}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE:-0}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE:-0}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY:-first-run-per-scenario}" \
  IPERF_ENABLE="${IPERF_ENABLE:-0}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}" \
  RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE:-1}" \
  AUX_JOB_HOST="${AUX_JOB_HOST:-}" \
  AUX_JOB_LABEL="${AUX_JOB_LABEL:-aux-job}" \
  AUX_JOB_CMD="${AUX_JOB_CMD:-}" \
  AUX_JOB_USE_SUDO="${AUX_JOB_USE_SUDO:-0}" \
  MONITOR_JOB_HOST="${MONITOR_JOB_HOST:-}" \
  MONITOR_JOB_LABEL="${MONITOR_JOB_LABEL:-monitor-job}" \
  MONITOR_JOB_CMD="${MONITOR_JOB_CMD:-}" \
  MONITOR_JOB_USE_SUDO="${MONITOR_JOB_USE_SUDO:-0}" \
  VICTIM_JOB_HOST="${VICTIM_JOB_HOST:-}" \
  VICTIM_JOB_LABEL="${VICTIM_JOB_LABEL:-victim-job}" \
  VICTIM_JOB_CMD="${VICTIM_JOB_CMD:-}" \
  VICTIM_JOB_USE_SUDO="${VICTIM_JOB_USE_SUDO:-0}" \
  POST_CLEANUP_HOST="${POST_CLEANUP_HOST:-}" \
  POST_CLEANUP_LABEL="${POST_CLEANUP_LABEL:-post-cleanup}" \
  POST_CLEANUP_CMD="${POST_CLEANUP_CMD:-}" \
  POST_CLEANUP_USE_SUDO="${POST_CLEANUP_USE_SUDO:-0}" \
    "${REPO_ROOT}/shell/experiments/run-scenario-window.sh" "${scenario_name}" "${duration}" "${note}"
}

dhcp_starvation_gateway_cleanup_cmd() {
  cat <<'EOF'
python3 - '__PREFIX__' <<'PY'
from pathlib import Path
import sys

prefix = sys.argv[1].lower()
changed = False

for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
    if not candidate.exists():
        continue
    kept = []
    for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
        parts = raw_line.split()
        if len(parts) >= 2 and parts[1].lower().startswith(prefix):
            changed = True
            continue
        kept.append(raw_line)
    if changed:
        candidate.write_text(('\n'.join(kept) + '\n') if kept else '', encoding='utf-8')

if changed:
    print(f"purged DHCP starvation leases for prefix {prefix}")
else:
    print(f"no DHCP starvation leases found for prefix {prefix}")
PY
systemctl restart dnsmasq
EOF
}
