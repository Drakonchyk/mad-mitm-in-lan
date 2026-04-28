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
USER_OVERLOAD_PPS_LEVELS_SET="${OVERLOAD_PPS_LEVELS+x}"
USER_OVERLOAD_DURATION_SECONDS_SET="${OVERLOAD_DURATION_SECONDS+x}"
USER_OVERLOAD_TRAFFIC_SECONDS_SET="${OVERLOAD_TRAFFIC_SECONDS+x}"
USER_OVERLOAD_PPS_PER_WORKER_SET="${OVERLOAD_PPS_PER_WORKER+x}"
USER_OVERLOAD_MAX_WORKERS_PER_SOURCE_SET="${OVERLOAD_MAX_WORKERS_PER_SOURCE+x}"
USER_OVERLOAD_WORKERS_SET="${OVERLOAD_WORKERS+x}"
USER_OVERLOAD_FLOOD_SET="${OVERLOAD_FLOOD+x}"
USER_OVERLOAD_ENGINE_SET="${OVERLOAD_ENGINE+x}"
FAMILIES="${FAMILIES:-dhcp-spoof arp-mitm-dns}"
OVERLOAD_PRESET="${OVERLOAD_PRESET:-standard}"
OVERLOAD_PPS_LEVELS="${OVERLOAD_PPS_LEVELS:-0 50 100 200 500 1000}"
OVERLOAD_SOURCES="${OVERLOAD_SOURCES:-victim attacker}"
OVERLOAD_DURATION_SECONDS="${OVERLOAD_DURATION_SECONDS:-20}"
OVERLOAD_TRAFFIC_OFFSET_SECONDS="${OVERLOAD_TRAFFIC_OFFSET_SECONDS:-5}"
OVERLOAD_TRAFFIC_SECONDS="${OVERLOAD_TRAFFIC_SECONDS:-12}"
OVERLOAD_PACKET_BYTES="${OVERLOAD_PACKET_BYTES:-96}"
OVERLOAD_WORKERS="${OVERLOAD_WORKERS:-auto}"
OVERLOAD_PPS_PER_WORKER="${OVERLOAD_PPS_PER_WORKER:-250}"
OVERLOAD_MAX_WORKERS_PER_SOURCE="${OVERLOAD_MAX_WORKERS_PER_SOURCE:-8}"
OVERLOAD_FLOOD="${OVERLOAD_FLOOD:-0}"
OVERLOAD_ENGINE="${OVERLOAD_ENGINE:-raw-socket}"
OVERLOAD_RUNS="${OVERLOAD_RUNS:-${RUNS_PER_LEVEL:-1}}"
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
Usage: ./shell/experiments/run-overload-plan.sh [options]

Options:
  --preset NAME             standard, huge, or blast (default: standard)
  --runs N                  Runs per family/pps level (default: 1)
  --help                    Show this help text

Environment:
  OVERLOAD_PRESET=standard
  FAMILIES="dhcp-spoof arp-mitm-dns"
  OVERLOAD_PPS_LEVELS="0 50 100 200 500 1000"
  OVERLOAD_SOURCES="victim attacker"
  OVERLOAD_DURATION_SECONDS=20
  OVERLOAD_TRAFFIC_SECONDS=12
  OVERLOAD_PACKET_BYTES=96
  OVERLOAD_ENGINE=raw-socket
  OVERLOAD_WORKERS=auto
  OVERLOAD_PPS_PER_WORKER=250
  OVERLOAD_MAX_WORKERS_PER_SOURCE=8
  OVERLOAD_FLOOD=0
  OVERLOAD_RUNS=1

The plan sends ICMP echo traffic that matches the detector BPF filter. The total
pps is split evenly across OVERLOAD_SOURCES so the switch sees comparable load
from each selected port while OVS snooping remains the compact ground truth.
Use --preset huge for short stepped high-rate tests. Use --preset blast to send
as fast as the guests can generate packets.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)
      OVERLOAD_PRESET="${2:?missing value for --preset}"
      shift 2
      ;;
    --runs)
      OVERLOAD_RUNS="${2:?missing value for --runs}"
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

apply_overload_preset() {
  case "${OVERLOAD_PRESET}" in
    standard)
      ;;
    huge)
      if [[ -z "${USER_OVERLOAD_PPS_LEVELS_SET}" ]]; then
        OVERLOAD_PPS_LEVELS="0 1000 5000 10000 20000 50000 100000"
      fi
      if [[ -z "${USER_OVERLOAD_DURATION_SECONDS_SET}" ]]; then
        OVERLOAD_DURATION_SECONDS="18"
      fi
      if [[ -z "${USER_OVERLOAD_TRAFFIC_SECONDS_SET}" ]]; then
        OVERLOAD_TRAFFIC_SECONDS="8"
      fi
      if [[ -z "${USER_OVERLOAD_PPS_PER_WORKER_SET}" ]]; then
        OVERLOAD_PPS_PER_WORKER="2000"
      fi
      if [[ -z "${USER_OVERLOAD_MAX_WORKERS_PER_SOURCE_SET}" ]]; then
        OVERLOAD_MAX_WORKERS_PER_SOURCE="64"
      fi
      if [[ -z "${USER_OVERLOAD_ENGINE_SET}" ]]; then
        OVERLOAD_ENGINE="raw-socket"
      fi
      ;;
    blast)
      if [[ -z "${USER_OVERLOAD_PPS_LEVELS_SET}" ]]; then
        OVERLOAD_PPS_LEVELS="1000000"
      fi
      if [[ -z "${USER_OVERLOAD_DURATION_SECONDS_SET}" ]]; then
        OVERLOAD_DURATION_SECONDS="16"
      fi
      if [[ -z "${USER_OVERLOAD_TRAFFIC_SECONDS_SET}" ]]; then
        OVERLOAD_TRAFFIC_SECONDS="6"
      fi
      if [[ -z "${USER_OVERLOAD_WORKERS_SET}" ]]; then
        OVERLOAD_WORKERS="64"
      fi
      if [[ -z "${USER_OVERLOAD_FLOOD_SET}" ]]; then
        OVERLOAD_FLOOD="1"
      fi
      if [[ -z "${USER_OVERLOAD_ENGINE_SET}" ]]; then
        OVERLOAD_ENGINE="raw-socket"
      fi
      ;;
    *)
      warn "Unknown overload preset: ${OVERLOAD_PRESET}"
      usage
      exit 1
      ;;
  esac
}

apply_overload_preset

if ! [[ "${OVERLOAD_RUNS}" =~ ^[0-9]+$ ]] || (( OVERLOAD_RUNS < 1 )); then
  warn "--runs / OVERLOAD_RUNS must be >= 1"
  exit 1
fi

case "${OVERLOAD_ENGINE}" in
  raw-socket|scapy)
    ;;
  *)
    warn "OVERLOAD_ENGINE must be raw-socket or scapy"
    exit 1
    ;;
esac

require_experiment_tools
mkdir -p "$(results_root)"
start_lab_and_wait_for_access
prepare_attacker_research_workspace

word_count() {
  local count=0 item
  for item in $1; do
    count=$((count + 1))
  done
  printf '%s\n' "${count}"
}

ceil_div() {
  local numerator="$1"
  local denominator="$2"
  if (( denominator <= 0 )); then
    printf '0\n'
  else
    printf '%s\n' "$(((numerator + denominator - 1) / denominator))"
  fi
}

overload_workers_for_source() {
  local per_source_pps="$1"
  local workers

  if [[ "${OVERLOAD_WORKERS}" == "auto" ]]; then
    workers="$(ceil_div "${per_source_pps}" "${OVERLOAD_PPS_PER_WORKER}")"
    if (( workers < 1 )); then
      workers=1
    fi
    if [[ "${OVERLOAD_MAX_WORKERS_PER_SOURCE}" =~ ^[0-9]+$ ]] && (( OVERLOAD_MAX_WORKERS_PER_SOURCE > 0 && workers > OVERLOAD_MAX_WORKERS_PER_SOURCE )); then
      workers="${OVERLOAD_MAX_WORKERS_PER_SOURCE}"
    fi
  else
    workers="${OVERLOAD_WORKERS}"
  fi

  if ! [[ "${workers}" =~ ^[0-9]+$ ]] || (( workers < 1 )); then
    workers=1
  fi
  printf '%s\n' "${workers}"
}

overload_slug_suffix() {
  local pps="$1"
  printf 'param-overload-%spps\n' "${pps}"
}

overload_sender_cmd() {
  local per_source_pps="$1"
  local traffic_seconds="$2"
  local offset_seconds="$3"
  local packet_bytes="$4"
  local workers

  if (( per_source_pps <= 0 )); then
    printf 'sleep %q\n' "${traffic_seconds}"
    return 0
  fi

  workers="$(overload_workers_for_source "${per_source_pps}")"

  cat <<EOF
sleep ${offset_seconds}
python3 - '${GATEWAY_IP}' '${per_source_pps}' '${traffic_seconds}' '${packet_bytes}' '${workers}' '${OVERLOAD_FLOOD}' '${OVERLOAD_ENGINE}' <<'PY'
from datetime import datetime, timezone
from multiprocessing import Process, Queue
from queue import Empty
import json
import os
import socket
import struct
import sys
import time

dst = sys.argv[1]
pps = max(int(sys.argv[2]), 1)
duration = max(float(sys.argv[3]), 0.1)
packet_bytes = max(int(sys.argv[4]), 64)
workers = max(int(sys.argv[5]), 1)
flood = sys.argv[6] in {"1", "true", "yes", "on"}
engine = sys.argv[7]
payload_len = max(packet_bytes - 42, 1)
payload = bytes((index % 251 for index in range(payload_len)))
start_at = time.monotonic() + 0.5
queue = Queue()

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff

def icmp_packet(worker_id):
    ident = (os.getpid() + worker_id) & 0xffff
    header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
    packet = header + payload
    return struct.pack("!BBHHH", 8, 0, checksum(packet), ident, 1) + payload

def send_raw(worker_id, worker_pps):
    packet = icmp_packet(worker_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sent = 0
    if flood:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            for _ in range(256):
                sock.sendto(packet, (dst, 0))
                sent += 1
    else:
        count = max(int(worker_pps * duration), 1)
        interval = 1.0 / worker_pps if worker_pps > 0 else 0.0
        next_send = time.monotonic()
        for _ in range(count):
            sock.sendto(packet, (dst, 0))
            sent += 1
            next_send += interval
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    sock.close()
    return sent

def send_scapy(worker_pps):
    from scapy.all import ICMP, IP, Raw, send

    packet = IP(dst=dst) / ICMP(type=8) / Raw(load=payload)
    if flood:
        deadline = time.monotonic() + duration
        sent = 0
        batch = 64
        while time.monotonic() < deadline:
            send(packet, count=batch, inter=0, verbose=False)
            sent += batch
        return sent

    count = max(int(worker_pps * duration), 1)
    inter = 1.0 / worker_pps if worker_pps > 0 else 0
    send(packet, count=count, inter=inter, verbose=False)
    return count

def worker(worker_id, worker_pps, queue):
    while time.monotonic() < start_at:
        time.sleep(0.001)
    started = time.monotonic()
    error = None
    sent = 0
    try:
        if engine == "raw-socket":
            sent = send_raw(worker_id, worker_pps)
        else:
            sent = send_scapy(worker_pps)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        ended = time.monotonic()
        elapsed = max(ended - started, 0.000001)
        queue.put({
            "worker": worker_id,
            "requested_pps": worker_pps,
            "sent_packets": sent,
            "elapsed_seconds": elapsed,
            "actual_pps": sent / elapsed,
            "error": error,
        })

worker_pps = pps / workers
children = [Process(target=worker, args=(index, worker_pps, queue)) for index in range(workers)]
for child in children:
    child.start()
for child in children:
    child.join()

worker_results = []
for _ in children:
    try:
        worker_results.append(queue.get(timeout=1))
    except Empty:
        worker_results.append({"sent_packets": 0, "elapsed_seconds": 0.000001, "actual_pps": 0, "error": "worker exited without reporting"})
sent = sum(item["sent_packets"] for item in worker_results)
elapsed = max((item["elapsed_seconds"] for item in worker_results), default=duration)

print(json.dumps({
    "event": "overload_traffic_finished",
    "ts": datetime.now(timezone.utc).isoformat(),
    "target_ip": dst,
    "requested_pps": pps,
    "workers": workers,
    "flood": flood,
    "engine": engine,
    "duration_seconds": duration,
    "packet_bytes": packet_bytes,
    "sent_packets": sent,
    "actual_pps": sent / max(elapsed, 0.000001),
    "worker_results": worker_results,
}, sort_keys=True))
PY
EOF
}

latest_run_for() {
  local scenario="$1"
  find "$(results_root)" -maxdepth 1 -type d \( -name "*-${scenario}" -o -name "*-${scenario}-*" \) -printf '%T@ %p\n' \
    | sort -nr \
    | awk 'NR==1 {print $2}'
}

run_overload_family() {
  local family="$1"
  local total_pps="$2"
  local run_index="${3:-1}"
  local remote_root scenario note duration attack_start attack_stop forwarding dns_spoof domains attack_cmd
  local source_count per_source_pps victim_cmd attacker_cmd

  remote_root="$(research_workspace_root)"
  duration="${OVERLOAD_DURATION_SECONDS}"
  attack_start="5"
  attack_stop="$((duration - 5))"
  case "${family}" in
    dhcp-spoof)
      scenario="overload-dhcp-spoof"
      note="Detector overload run: rogue DHCP spoofing with ${total_pps} pps ICMP background traffic"
      forwarding="0"
      dns_spoof="0"
      domains=""
      attack_cmd="sleep 5; cd '${remote_root}' && exec timeout -s INT $((duration - 10)) env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf dhcp-spoof --interface vnic0 --interval 1.0"
      ;;
    arp-mitm-dns)
      scenario="overload-arp-mitm-dns"
      note="Detector overload run: ARP MITM with focused DNS spoofing and ${total_pps} pps ICMP background traffic"
      forwarding="1"
      dns_spoof="1"
      domains="iana.org"
      attack_cmd="sleep 5; cd '${remote_root}' && exec timeout -s INT $((duration - 10)) env PYTHONPATH='./python' python3 -m mitm.cli --config ./lab.conf mitm-dns --interface vnic0 --enable-forwarding --domains iana.org"
      ;;
    *)
      warn "Unknown overload family: ${family}"
      return 1
      ;;
  esac

  source_count="$(word_count "${OVERLOAD_SOURCES}")"
  per_source_pps="$(ceil_div "${total_pps}" "${source_count}")"
  victim_cmd=""
  attacker_cmd=""
  if [[ " ${OVERLOAD_SOURCES} " == *" victim "* ]]; then
    victim_cmd="$(overload_sender_cmd "${per_source_pps}" "${OVERLOAD_TRAFFIC_SECONDS}" "${OVERLOAD_TRAFFIC_OFFSET_SECONDS}" "${OVERLOAD_PACKET_BYTES}")"
  fi
  if [[ " ${OVERLOAD_SOURCES} " == *" attacker "* ]]; then
    attacker_cmd="$(overload_sender_cmd "${per_source_pps}" "${OVERLOAD_TRAFFIC_SECONDS}" "${OVERLOAD_TRAFFIC_OFFSET_SECONDS}" "${OVERLOAD_PACKET_BYTES}")"
  fi

  SKIP_LAB_START="1" \
  ATTACK_JOB_HOST="attacker" \
  ATTACK_JOB_LABEL="${scenario}" \
  ATTACK_JOB_CMD="${attack_cmd}" \
  ATTACK_JOB_USE_SUDO="1" \
  AUX_JOB_HOST="attacker" \
  AUX_JOB_LABEL="overload-attacker" \
  AUX_JOB_CMD="${attacker_cmd}" \
  AUX_JOB_USE_SUDO="1" \
  VICTIM_JOB_HOST="victim" \
  VICTIM_JOB_LABEL="overload-victim" \
  VICTIM_JOB_CMD="${victim_cmd}" \
  VICTIM_JOB_USE_SUDO="1" \
  PLAN_RUN_INDEX="${run_index}" \
  PLAN_WARMUP="0" \
  PLAN_DURATION_SECONDS="${duration}" \
  PLAN_ATTACK_START_OFFSET_SECONDS="${attack_start}" \
  PLAN_ATTACK_STOP_OFFSET_SECONDS="${attack_stop}" \
  PLAN_FORWARDING_ENABLED="${forwarding}" \
  PLAN_DNS_SPOOF_ENABLED="${dns_spoof}" \
  PLAN_SPOOFED_DOMAINS="${domains}" \
  RUN_SLUG_SUFFIX="$(overload_slug_suffix "${total_pps}")" \
  OVERLOAD_TOTAL_PPS="${total_pps}" \
  OVERLOAD_PPS_PER_SOURCE="${per_source_pps}" \
  OVERLOAD_TRAFFIC_SECONDS="${OVERLOAD_TRAFFIC_SECONDS}" \
  OVERLOAD_PACKET_BYTES="${OVERLOAD_PACKET_BYTES}" \
  OVERLOAD_SOURCES="${OVERLOAD_SOURCES}" \
  OVERLOAD_PRESET="${OVERLOAD_PRESET}" \
  OVERLOAD_ENGINE="${OVERLOAD_ENGINE}" \
  OVERLOAD_WORKERS="${OVERLOAD_WORKERS}" \
  OVERLOAD_PPS_PER_WORKER="${OVERLOAD_PPS_PER_WORKER}" \
  OVERLOAD_MAX_WORKERS_PER_SOURCE="${OVERLOAD_MAX_WORKERS_PER_SOURCE}" \
  OVERLOAD_FLOOD="${OVERLOAD_FLOOD}" \
  PCAP_ENABLE="${PCAP_ENABLE}" \
  PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE}" \
  GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE}" \
  PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE}" \
  PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY}" \
  IPERF_ENABLE="${IPERF_ENABLE}" \
  POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS}" \
  RUN_SUMMARY_ENABLE="${RUN_SUMMARY_ENABLE}" \
  DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS}" \
    "${EXPERIMENT_SCRIPT_DIR}/run-scenario-window.sh" "${scenario}" "${duration}" "${note}"
}

evaluate_latest_overload() {
  local scenario="$1"
  local run_dir
  run_dir="$(latest_run_for "${scenario}")"
  if [[ -z "${run_dir}" ]]; then
    warn "Could not find newest overload run for ${scenario}"
    return 1
  fi
  if [[ "${KEEP_DEBUG_ARTIFACTS:-0}" == "1" ]]; then
    PYTHONPATH=./python python3 -m metrics.summary_cli "${run_dir}" > "${run_dir}/overload-summary.txt" || true
  fi
}

for family in ${FAMILIES}; do
  for pps in ${OVERLOAD_PPS_LEVELS}; do
    for ((run = 1; run <= OVERLOAD_RUNS; run++)); do
      info "Overload campaign: family=${family} total_pps=${pps} run=${run}/${OVERLOAD_RUNS} sources='${OVERLOAD_SOURCES}' duration=${OVERLOAD_DURATION_SECONDS}s"
      run_overload_family "${family}" "${pps}" "${run}"
      case "${family}" in
        dhcp-spoof) evaluate_latest_overload "overload-dhcp-spoof" ;;
        arp-mitm-dns) evaluate_latest_overload "overload-arp-mitm-dns" ;;
      esac
    done
  done
done

if [[ "${REPORT_ENABLE}" == "1" ]]; then
  PYTHONPATH=./python python3 -m reporting.cli "$(results_root)" --profile all --output-dir "$(results_root)/experiment-report"
fi
