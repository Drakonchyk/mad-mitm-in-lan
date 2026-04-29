#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP="${PCAP-}"
USER_GUEST_PCAP="${GUEST_PCAP-}"
USER_PCAP_SUMMARIES="${PCAP_SUMMARIES-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-first-run-per-scenario}"
PCAP_ENABLE="${USER_PCAP:-0}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES:-0}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-2}"

DURATION="${1:-${DURATION:-30}}"
LOSS="${2:-${LOSS:-0}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_RUNTIME=$((DURATION - 10))
ATTACK_CMD="sleep 5; cd '${REMOTE_ROOT}' && exec timeout -s INT ${ATTACK_RUNTIME} env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --victim-ip __VICTIM_IP__ --gateway-ip __GATEWAY_IP__ --answer-ip __ATTACKER_IP__ --interval 1.0 --enable-forwarding --domains iana.org"

RELIABILITY_NETEM_LOSS_PERCENT="${LOSS}" \
RUN_SLUG_SUFFIX="param-loss-${LOSS}pct" \
PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_ATTACK_START_OFFSET_SECONDS="5" \
PLAN_ATTACK_STOP_OFFSET_SECONDS="$((DURATION - 5))" \
PLAN_FORWARDING_ENABLED="1" \
PLAN_DNS_SPOOF_ENABLED="1" \
PLAN_SPOOFED_DOMAINS="iana.org" \
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS}" \
run_automated_scenario_recording \
  "reliability-arp-mitm-dns" \
  "${DURATION}" \
  "Reliability run for ARP MITM plus focused DNS spoofing with ${LOSS}% netem packet loss" \
  "reliability-arp-mitm-dns" \
  "${ATTACK_CMD}"
