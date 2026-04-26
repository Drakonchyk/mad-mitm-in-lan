#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"
USER_SENSOR_VISIBILITY_PERCENT="${SENSOR_VISIBILITY_PERCENT-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-first-run-per-scenario}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-1}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"

DURATION="${1:-${DURATION:-60}}"
VISIBILITY="${2:-${USER_SENSOR_VISIBILITY_PERCENT:-100}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 2.0"

SENSOR_VISIBILITY_PERCENT="${VISIBILITY}" \
RUN_SLUG_SUFFIX="param-visibility-${VISIBILITY}pct" \
PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
run_automated_scenario_recording \
  "visibility-dhcp-spoof" \
  "${DURATION}" \
  "Live visibility degradation for rogue DHCP spoofing at ${VISIBILITY}% sensor visibility" \
  "visibility-dhcp-spoof" \
  "${ATTACK_CMD}"
