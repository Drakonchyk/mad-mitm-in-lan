#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"
USER_RELIABILITY_NETEM_LOSS_PERCENT="${RELIABILITY_NETEM_LOSS_PERCENT-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-first-run-per-scenario}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-0}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-2}"

DURATION="${1:-${DURATION:-20}}"
LOSS="${2:-${USER_RELIABILITY_NETEM_LOSS_PERCENT:-0}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT $((DURATION - 10)) env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 1.0"

RELIABILITY_NETEM_LOSS_PERCENT="${LOSS}" \
RUN_SLUG_SUFFIX="param-loss-${LOSS}pct" \
PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_ATTACK_START_OFFSET_SECONDS="5" \
PLAN_ATTACK_STOP_OFFSET_SECONDS="$((DURATION - 5))" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS}" \
run_automated_scenario_recording \
  "reliability-dhcp-spoof" \
  "${DURATION}" \
  "Reliability run for rogue DHCP spoofing with ${LOSS}% netem packet loss" \
  "reliability-dhcp-spoof" \
  "${ATTACK_CMD}"
