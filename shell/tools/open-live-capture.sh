#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

TARGET_HOST="${1:-${HOST:-victim}}"
INTERFACE="${2:-${IFACE:-}}"
CAPTURE_FILTER="${3:-${FILTER:-arp or icmp or port 53}}"

case "${TARGET_HOST}" in
  gateway)
    : "${INTERFACE:=any}"
    ;;
  victim|attacker)
    : "${INTERFACE:=vnic0}"
    ;;
  sensor)
    : "${INTERFACE:=${LAB_SWITCH_SENSOR_PORT}}"
    ;;
  *)
    warn "Unknown capture host: ${TARGET_HOST}. Use gateway, victim, attacker, or sensor."
    exit 1
    ;;
esac

printf -v FILTER_EXPR '%q' "${CAPTURE_FILTER}"

require_experiment_tools
start_lab_and_wait_for_access

info "Opening live capture on ${TARGET_HOST}:${INTERFACE}"
info "Filter: ${CAPTURE_FILTER}"
info "Press Ctrl-C to stop"

if [[ "${TARGET_HOST}" == "sensor" ]]; then
  run_root bash -lc "
    command -v tcpdump >/dev/null 2>&1 || exit 1
    exec stdbuf -oL -eL tcpdump -ni '${INTERFACE}' -nn -l ${FILTER_EXPR}
  "
  exit 0
fi

remote_sudo_bash_lc "${TARGET_HOST}" \
  "command -v tcpdump >/dev/null 2>&1 || { apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump; }
   exec stdbuf -oL -eL tcpdump -ni '${INTERFACE}' -nn -l ${FILTER_EXPR}"
