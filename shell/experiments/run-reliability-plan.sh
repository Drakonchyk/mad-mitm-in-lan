#!/usr/bin/env bash
set -euo pipefail

USER_PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY-}"
USER_PCAP_ENABLE="${PCAP_ENABLE-}"
USER_PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE-}"
USER_GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE-}"
USER_PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE-}"

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../experiment-common.sh"

EXPERIMENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAMILIES="${FAMILIES:-arp-mitm-dns dhcp-spoof}"
LOSS_LEVELS_EXPLICIT=0
if [[ -v RELIABILITY_LOSS_LEVELS ]]; then
  LOSS_LEVELS_EXPLICIT=1
fi
RELIABILITY_LOSS_LEVELS="${RELIABILITY_LOSS_LEVELS:-0 10 20 30 40 50 60 70 80 90 100}"
RELIABILITY_DHCP_ROGUE_ONLY="${RELIABILITY_DHCP_ROGUE_ONLY:-0}"
RELIABILITY_DHCP_ROGUE_FOCUSED="${RELIABILITY_DHCP_ROGUE_FOCUSED:-${RELIABILITY_DHCP_ROGUE_ONLY}}"
RELIABILITY_SENSOR_ATTACK_TYPE="${RELIABILITY_SENSOR_ATTACK_TYPE:-}"
RELIABILITY_DELAY_MS="${RELIABILITY_DELAY_MS:-0}"
RELIABILITY_JITTER_MS="${RELIABILITY_JITTER_MS:-0}"
RELIABILITY_RATE="${RELIABILITY_RATE:-}"
RELIABILITY_DUPLICATE_PERCENT="${RELIABILITY_DUPLICATE_PERCENT:-0}"
RELIABILITY_REORDER_PERCENT="${RELIABILITY_REORDER_PERCENT:-0}"
RELIABILITY_CORRUPT_PERCENT="${RELIABILITY_CORRUPT_PERCENT:-0}"
RELIABILITY_ARP_DNS_DURATION_SECONDS="${RELIABILITY_ARP_DNS_DURATION_SECONDS:-30}"
RELIABILITY_DHCP_DURATION_SECONDS="${RELIABILITY_DHCP_DURATION_SECONDS:-20}"
RELIABILITY_RUNS="${RELIABILITY_RUNS:-${RUNS_PER_LEVEL:-1}}"
PCAP_RETENTION_POLICY="${USER_PCAP_RETENTION_POLICY:-first-run-per-scenario}"
PCAP_ENABLE="${USER_PCAP_ENABLE:-0}"
PORT_PCAP_ENABLE="${USER_PORT_PCAP_ENABLE:-0}"
GUEST_PCAP_ENABLE="${USER_GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${USER_PCAP_SUMMARIES_ENABLE:-0}"
IPERF_ENABLE="${IPERF_ENABLE:-0}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-0}"
RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE:-0}"
REPORT_ENABLE="${REPORT_ENABLE:-0}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-2}"

usage() {
  cat <<'EOF'
Usage: ./shell/experiments/run-reliability-plan.sh [options]

Options:
  --thesis                  Run ARP/DNS and focused DHCP rogue-server reliability,
                            loss 0..100 step 10
  --both                    Alias for --thesis
  --dhcp-rogue-only        Run only DHCP rogue-server packet detection, loss 0..100 step 10
  --loss-levels "..."      Override packet-loss levels
  --runs N                  Runs per family/loss level (default: 1)
  --help                    Show this help text

Environment:
  FAMILIES="arp-mitm-dns dhcp-spoof"
  RELIABILITY_LOSS_LEVELS="0 10 20 30 40 50 60 70 80 90 100"
  RELIABILITY_DHCP_ROGUE_ONLY=0
  RELIABILITY_DHCP_ROGUE_FOCUSED=0
  RELIABILITY_SENSOR_ATTACK_TYPE=
  RELIABILITY_DELAY_MS=0
  RELIABILITY_JITTER_MS=0
  RELIABILITY_RATE=
  RELIABILITY_DUPLICATE_PERCENT=0
  RELIABILITY_REORDER_PERCENT=0
  RELIABILITY_CORRUPT_PERCENT=0
  RELIABILITY_RUNS=1
  RUN_SUMMARY_ENABLE=0
  REPORT_ENABLE=0

The plan routes the mirrored switch feed through a veth pair and applies Linux
tc netem before Detector, Zeek, and Suricata read packets. Attacks are launched
inside the same capture window so detector reliability can be measured under
packet loss, delay, jitter, rate limits, duplication, reordering, or corruption.
In --thesis and --dhcp-rogue-only modes, detector OVS DHCP polling is disabled for
the DHCP family so Detector, Zeek, and Suricata are compared only on
packet-visible rogue DHCP replies.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --thesis|--both)
      FAMILIES="arp-mitm-dns dhcp-spoof"
      if (( LOSS_LEVELS_EXPLICIT == 0 )); then
        RELIABILITY_LOSS_LEVELS="0 10 20 30 40 50 60 70 80 90 100"
      fi
      RELIABILITY_DHCP_ROGUE_FOCUSED="1"
      shift
      ;;
    --dhcp-rogue-only)
      RELIABILITY_DHCP_ROGUE_ONLY="1"
      RELIABILITY_DHCP_ROGUE_FOCUSED="1"
      FAMILIES="dhcp-spoof"
      if (( LOSS_LEVELS_EXPLICIT == 0 )); then
        RELIABILITY_LOSS_LEVELS="0 10 20 30 40 50 60 70 80 90 100"
      fi
      shift
      ;;
    --loss-levels)
      RELIABILITY_LOSS_LEVELS="${2:?missing value for --loss-levels}"
      LOSS_LEVELS_EXPLICIT=1
      shift 2
      ;;
    --runs)
      RELIABILITY_RUNS="${2:?missing value for --runs}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      warn "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if ! [[ "${RELIABILITY_RUNS}" =~ ^[0-9]+$ ]] || (( RELIABILITY_RUNS < 1 )); then
  warn "--runs / RELIABILITY_RUNS must be >= 1"
  exit 1
fi

require_experiment_tools
mkdir -p "$(results_root)"
start_lab_and_wait_for_access
prepare_attacker_research_workspace

latest_run_for() {
  local scenario="$1"
  find "$(results_root)" -maxdepth 1 -type d \( -name "*-${scenario}" -o -name "*-${scenario}-*" \) -printf '%T@ %p\n' \
    | sort -nr \
    | awk 'NR==1 {print $2}'
}

latest_run_for_scenario_from_db() {
  local scenario="$1"
  PYTHONPATH=./python python3 - "$(results_root)/experiment-results.sqlite" "${scenario}" <<'PY'
import sqlite3
import sys
from pathlib import Path

db_path = Path(sys.argv[1])
scenario = sys.argv[2]
if not db_path.exists():
    raise SystemExit(0)
with sqlite3.connect(db_path) as db:
    row = db.execute(
        """
        SELECT run_dir
        FROM runs
        WHERE scenario = ?
        ORDER BY started_at DESC, run_id DESC
        LIMIT 1
        """,
        (scenario,),
    ).fetchone()
if row:
    print(row[0])
PY
}

reliability_slug_suffix() {
  local loss="$1"
  local family="${2:-}"
  local suffix="param-loss-${loss}pct"
  if [[ "${family}" == "dhcp-spoof" && "${RELIABILITY_DHCP_ROGUE_FOCUSED}" == "1" ]]; then
    suffix="param-dhcp-rogue-loss-${loss}pct"
  fi
  if [[ "${RELIABILITY_DELAY_MS}" != "0" || "${RELIABILITY_JITTER_MS}" != "0" ]]; then
    suffix="${suffix}-delay-${RELIABILITY_DELAY_MS}ms-jitter-${RELIABILITY_JITTER_MS}ms"
  fi
  if [[ -n "${RELIABILITY_RATE}" ]]; then
    suffix="${suffix}-rate-${RELIABILITY_RATE}"
  fi
  printf '%s\n' "${suffix}"
}

reliability_family_attack_type_filter() {
  local family="$1"
  if [[ "${family}" == "dhcp-spoof" && "${RELIABILITY_DHCP_ROGUE_FOCUSED}" == "1" ]]; then
    printf '%s\n' "dhcp_rogue_server"
    return 0
  fi
  printf '%s\n' "${RELIABILITY_SENSOR_ATTACK_TYPE}"
}

run_reliability_family() {
  local family="$1"
  local loss="$2"
  local run_index="${3:-1}"
  local remote_root attack_cmd scenario duration note attack_start attack_stop forwarding dns_spoof domains

  remote_root="$(research_workspace_root)"
  case "${family}" in
    arp-mitm-dns)
      scenario="reliability-arp-mitm-dns"
      duration="${RELIABILITY_ARP_DNS_DURATION_SECONDS}"
      note="Reliability run: ARP MITM with focused DNS spoofing while netem applies ${loss}% packet loss"
      attack_start="5"
      attack_stop="$((duration - 5))"
      forwarding="1"
      dns_spoof="1"
      domains="iana.org"
      attack_cmd="sleep 5; cd '${remote_root}' && exec timeout -s INT $((duration - 10)) env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"
      ;;
    dhcp-spoof)
      scenario="reliability-dhcp-spoof"
      duration="${RELIABILITY_DHCP_DURATION_SECONDS}"
      note="Reliability run: rogue DHCP spoofing while netem applies ${loss}% packet loss"
      if [[ "${RELIABILITY_DHCP_ROGUE_FOCUSED}" == "1" ]]; then
        note="Reliability run: DHCP rogue-server packet detection only while netem applies ${loss}% packet loss"
      fi
      attack_start="5"
      attack_stop="$((duration - 5))"
      forwarding="0"
      dns_spoof="0"
      domains=""
      attack_cmd="sleep 5; cd '${remote_root}' && exec timeout -s INT $((duration - 10)) env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 1.0"
      ;;
    *)
      warn "Unknown reliability family: ${family}"
      return 1
      ;;
  esac

  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="${ATTACK_JOB_HOST_OVERRIDE:-attacker}" \
  ATTACK_JOB_LABEL="${scenario}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  PLAN_RUN_INDEX="${run_index}" \
  PLAN_DURATION_SECONDS="${duration}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${attack_start}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="${attack_stop}" \
  PLAN_FORWARDING_ENABLED="${forwarding}" \
  PLAN_DNS_SPOOF_ENABLED="${dns_spoof}" \
  PLAN_SPOOFED_DOMAINS="${domains}" \
  RUN_SLUG_SUFFIX="$(reliability_slug_suffix "${loss}" "${family}")" \
  RELIABILITY_NETEM_LOSS_PERCENT="${loss}" \
  RELIABILITY_NETEM_DELAY_MS="${RELIABILITY_DELAY_MS}" \
  RELIABILITY_NETEM_JITTER_MS="${RELIABILITY_JITTER_MS}" \
  RELIABILITY_NETEM_RATE="${RELIABILITY_RATE}" \
  RELIABILITY_NETEM_DUPLICATE_PERCENT="${RELIABILITY_DUPLICATE_PERCENT}" \
  RELIABILITY_NETEM_REORDER_PERCENT="${RELIABILITY_REORDER_PERCENT}" \
  RELIABILITY_NETEM_CORRUPT_PERCENT="${RELIABILITY_CORRUPT_PERCENT}" \
  RELIABILITY_SENSOR_ATTACK_TYPE="$(reliability_family_attack_type_filter "${family}")" \
  DETECTOR_OVS_DHCP_SNOOPING_ENABLE="${DETECTOR_OVS_DHCP_SNOOPING_ENABLE:-0}" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
  DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS}" \
  RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE}" \
  "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

latest_reliability_run_for() {
  local family="$1"
  local scenario run_dir
  case "${family}" in
    arp-mitm-dns)
      scenario="reliability-arp-mitm-dns"
      ;;
    dhcp-spoof)
      scenario="reliability-dhcp-spoof"
      ;;
    *)
      return 1
      ;;
  esac
  run_dir="$(latest_run_for "${scenario}")"
  if [[ -n "${run_dir}" ]]; then
    printf '%s\n' "${run_dir}"
    return 0
  fi
  latest_run_for_scenario_from_db "${scenario}"
}

evaluate_latest_reliability() {
  local family="$1"
  local run_dir

  run_dir="$(latest_reliability_run_for "${family}")"
  if [[ -z "${run_dir}" ]]; then
    warn "Could not find newest reliability run for ${family}"
    return 1
  fi

  PYTHONPATH=./python python3 - "${run_dir}" "$(results_root)/experiment-results.sqlite" <<'PY'
import json
import sys
import sqlite3
from pathlib import Path

run_dir = Path(sys.argv[1])
db_path = Path(sys.argv[2])
with sqlite3.connect(db_path) as db:
    row = db.execute(
        """
        SELECT scenario, detector_alert_events, zeek_alert_events, suricata_alert_events
        FROM runs
        WHERE run_dir = ?
        """,
        (str(run_dir.resolve()),),
    ).fetchone()
if row is None:
    payload = {
        "run_dir": str(run_dir),
        "scenario": run_dir.name,
        "detector_alert_events": 0,
        "zeek_alert_events": 0,
        "suricata_alert_events": 0,
    }
else:
    payload = {
        "run_dir": str(run_dir),
        "scenario": row[0],
        "detector_alert_events": row[1],
        "zeek_alert_events": row[2],
        "suricata_alert_events": row[3],
    }
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

evaluate_latest_reliability_attack_type() {
  local family="$1"
  local attack_type="$2"
  local run_dir

  run_dir="$(latest_reliability_run_for "${family}")"
  if [[ -z "${run_dir}" ]]; then
    warn "Could not find newest reliability run for ${family}"
    return 1
  fi

  PYTHONPATH=./python python3 - "${run_dir}" "$(results_root)/experiment-results.sqlite" "${attack_type}" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
db_path = Path(sys.argv[2])
attack_type = sys.argv[3]
payload = {
    "run_dir": str(run_dir),
    "scenario": run_dir.name,
    "attack_type": attack_type,
    "detector_alert_events": 0,
    "zeek_alert_events": 0,
    "suricata_alert_events": 0,
}
with sqlite3.connect(db_path) as db:
    row = db.execute("SELECT run_id, scenario FROM runs WHERE run_dir = ?", (str(run_dir.resolve()),)).fetchone()
    if row is not None:
        run_id, scenario = row
        payload["scenario"] = scenario
        for sensor in ("detector", "zeek", "suricata"):
            value = db.execute(
                """
                SELECT alert_count FROM sensor_counts
                WHERE run_id = ? AND sensor = ? AND attack_type = ?
                """,
                (run_id, sensor, attack_type),
            ).fetchone()
            payload[f"{sensor}_alert_events"] = int(value[0]) if value else 0
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

detected_count_from_result() {
  python3 -c '
import json, sys
payload = json.load(sys.stdin)
print(sum(1 for key in ("detector_alert_events", "zeek_alert_events", "suricata_alert_events") if int(payload.get(key) or 0) > 0))
'
}

run_reliability_level() {
  local family="$1"
  local loss="$2"
  local run_index="$3"
  local result_json detected attack_type_filter

  info "Reliability campaign: family=${family} loss=${loss}% run=${run_index}/${RELIABILITY_RUNS} delay=${RELIABILITY_DELAY_MS}ms jitter=${RELIABILITY_JITTER_MS}ms rate=${RELIABILITY_RATE:-unlimited}"
  run_reliability_family "${family}" "${loss}" "${run_index}"
  attack_type_filter="$(reliability_family_attack_type_filter "${family}")"
  if [[ -n "${attack_type_filter}" ]]; then
    result_json="$(evaluate_latest_reliability_attack_type "${family}" "${attack_type_filter}")"
  else
    result_json="$(evaluate_latest_reliability "${family}")"
  fi
  if [[ "${KEEP_DEBUG_ARTIFACTS:-0}" == "1" ]]; then
    local latest_dir
    latest_dir="$(latest_reliability_run_for "${family}")"
    if [[ -d "${latest_dir}" ]]; then
      printf '%s\n' "${result_json}" > "${latest_dir}/reliability-result.json"
    fi
  fi
  detected="$(printf '%s\n' "${result_json}" | detected_count_from_result)"
  if [[ -n "${attack_type_filter}" ]]; then
    info "Reliability result: family=${family} loss=${loss}% attack_type=${attack_type_filter} detectors_with_alerts=${detected}/3"
  else
    info "Reliability result: family=${family} loss=${loss}% detectors_with_alerts=${detected}/3"
  fi
}

for family in ${FAMILIES}; do
  for loss in ${RELIABILITY_LOSS_LEVELS}; do
    for ((run = 1; run <= RELIABILITY_RUNS; run++)); do
      run_reliability_level "${family}" "${loss}" "${run}"
    done
  done
done

if [[ "${REPORT_ENABLE}" == "1" ]]; then
  PYTHONPATH=./python python3 -m reporting.cli "$(results_root)" --profile all --output-dir "$(results_root)/experiment-report"
fi
