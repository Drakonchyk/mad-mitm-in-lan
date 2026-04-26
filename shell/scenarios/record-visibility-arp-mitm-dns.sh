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

DURATION="${1:-${DURATION:-90}}"
VISIBILITY="${2:-${USER_SENSOR_VISIBILITY_PERCENT:-100}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"

SENSOR_VISIBILITY_PERCENT="${VISIBILITY}" \
RUN_SLUG_SUFFIX="param-visibility-${VISIBILITY}pct" \
PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="1" \
PLAN_DNS_SPOOF_ENABLED="1" \
PLAN_SPOOFED_DOMAINS="iana.org" \
run_automated_scenario_recording \
  "visibility-arp-mitm-dns" \
  "${DURATION}" \
  "Live visibility degradation for ARP MITM plus focused DNS spoofing at ${VISIBILITY}% sensor visibility" \
  "visibility-arp-mitm-dns" \
  "${ATTACK_CMD}"
