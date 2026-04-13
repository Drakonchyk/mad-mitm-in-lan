#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-2000}"

require_experiment_tools() {
  require_cmd ssh
  require_cmd scp
  require_cmd python3
}

remote_bash_lc() {
  local host="$1"
  local cmd="$2"
  local wrapped

  printf -v wrapped 'bash -lc %q' "$cmd"
  lab_ssh "$host" "$wrapped"
}

remote_sudo_bash_lc() {
  local host="$1"
  local cmd="$2"
  local wrapped

  printf -v wrapped 'sudo bash -lc %q' "$cmd"
  lab_ssh "$host" "$wrapped"
}

json_escape() {
  local text="$1"
  text="${text//\\/\\\\}"
  text="${text//\"/\\\"}"
  text="${text//$'\n'/\\n}"
  printf '%s' "$text"
}

scenario_slug() {
  local raw="$1"
  raw="${raw,,}"
  raw="${raw// /-}"
  raw="${raw//[^a-z0-9._-]/-}"
  printf '%s\n' "$raw"
}

prepare_run_dir() {
  local scenario="$1"
  local run_id slug

  run_id="$(date -u +%Y%m%dT%H%M%SZ)"
  slug="$(scenario_slug "$scenario")"

  RUN_ID="${run_id}"
  RUN_SCENARIO="${scenario}"
  RUN_SLUG="${slug}"
  RUN_DIR="$(results_root)/${RUN_ID}-${RUN_SLUG}"

  mkdir -p "${RUN_DIR}/host" "${RUN_DIR}/gateway" "${RUN_DIR}/victim" "${RUN_DIR}/attacker" "${RUN_DIR}/pcap"
}

start_lab_and_wait_for_access() {
  "${SCRIPT_DIR}/50-start-lab.sh" >/dev/null

  info "Waiting for SSH access to ${GATEWAY_NAME}"
  wait_for_lab_ssh gateway
  wait_for_lab_guest_ready gateway iperf3 tcpdump dig curl
  info "Waiting for SSH access to ${VICTIM_NAME}"
  wait_for_lab_ssh victim
  wait_for_lab_guest_ready victim iperf3 tcpdump dig curl python3
  info "Waiting for SSH access to ${ATTACKER_NAME}"
  wait_for_lab_ssh attacker
  wait_for_lab_guest_ready attacker iperf3 tcpdump dig curl python3
}

wait_for_lab_guest_ready() {
  local host="$1"
  shift
  local required_cmds=("$@")
  local attempts="${GUEST_READY_ATTEMPTS:-36}"
  local delay="${GUEST_READY_DELAY_SECONDS:-5}"
  local try cmd_check=""

  for cmd in "${required_cmds[@]}"; do
    printf -v cmd_check '%s command -v %q >/dev/null 2>&1 || exit 1;' "${cmd_check}" "${cmd}"
  done

  for ((try = 1; try <= attempts; try++)); do
    if remote_bash_lc "$host" "if command -v cloud-init >/dev/null 2>&1; then sudo cloud-init status --wait >/dev/null 2>&1; fi; ${cmd_check}" >/dev/null 2>&1; then
      info "Guest provisioning is ready on ${host} (${try}/${attempts})"
      return 0
    fi
    if (( try == 1 || try % 6 == 0 || try == attempts )); then
      info "Still waiting for guest provisioning on ${host} (${try}/${attempts}, retrying every ${delay}s)"
    fi
    sleep "$delay"
  done

  warn "Timed out waiting for guest provisioning on ${host}"
  return 1
}

write_run_meta() {
  local mode="$1"
  local started_at="$2"
  local ended_at="$3"
  local notes="${4:-}"

  cat > "${RUN_DIR}/run-meta.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "scenario": "${RUN_SCENARIO}",
  "mode": "${mode}",
  "started_at": "${started_at}",
  "ended_at": "${ended_at}",
  "gateway_upstream_ip": "$(gateway_upstream_ip)",
  "gateway_lab_ip": "${GATEWAY_IP}",
  "victim_ip": "$(cidr_addr "${VICTIM_CIDR}")",
  "attacker_ip": "$(cidr_addr "${ATTACKER_CIDR}")",
  "notes": "$(json_escape "${notes}")",
  "domains": "$(json_escape "${DETECTOR_DOMAINS}")"
}
EOF
}

capture_remote_command() {
  local host="$1"
  local outfile="$2"
  local cmd="$3"

  if ! remote_bash_lc "$host" "$cmd" > "${outfile}" 2>&1; then
    warn "Command on ${host} failed; output kept in ${outfile}"
    return 0
  fi
}

remote_file_size() {
  local host="$1"
  local path="$2"

  remote_sudo_bash_lc "$host" "if test -f '$path'; then wc -c < '$path'; else echo 0; fi" | tr -d '[:space:]'
}

capture_remote_delta() {
  local host="$1"
  local path="$2"
  local offset="$3"
  local outfile="$4"
  local start_byte=$((offset + 1))

  if ! remote_sudo_bash_lc "$host" "if test -f '$path'; then tail -c +${start_byte} '$path'; fi" > "${outfile}" 2>&1; then
    warn "Could not capture delta from ${host}:${path}"
  fi
}

start_remote_capture() {
  local host="$1"
  local iface="$2"
  local label="$3"

  local remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  local pcap="${remote_base}.pcap"
  local pid_file="${remote_base}.pid"
  local log_file="${remote_base}.log"

  remote_sudo_bash_lc "$host" \
    "for pid in \$(pgrep -x tcpdump 2>/dev/null || true); do cmd=\$(ps -p \"\$pid\" -o args= 2>/dev/null || true); case \"\$cmd\" in *\"-${label}.pcap\"*) kill -INT \"\$pid\" 2>/dev/null || true ;; esac; done; sleep 1; rm -f /tmp/*-${label}.pid /tmp/*-${label}.log /tmp/*-${label}.pcap"
  remote_sudo_bash_lc "$host" \
    "rm -f '${pcap}' '${pid_file}' '${log_file}'; nohup tcpdump -i '${iface}' -nn -s 0 -U -c '${CAPTURE_PACKET_COUNT}' -w '${pcap}' >'${log_file}' 2>&1 </dev/null & echo \$! > '${pid_file}'"

  printf '%s\n' "${pcap}"
}

stop_remote_capture() {
  local host="$1"
  local label="$2"

  local remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  local pid_file="${remote_base}.pid"

  remote_sudo_bash_lc "$host" \
    "if test -f '${pid_file}'; then pid=\$(cat '${pid_file}'); kill -INT \"\$pid\" 2>/dev/null || true; for _ in 1 2 3 4 5; do if ! kill -0 \"\$pid\" 2>/dev/null; then break; fi; sleep 1; done; if kill -0 \"\$pid\" 2>/dev/null; then kill -TERM \"\$pid\" 2>/dev/null || true; sleep 1; fi; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL \"\$pid\" 2>/dev/null || true; fi; fi" \
    >/dev/null 2>&1 || true
}

fetch_remote_file() {
  local host="$1"
  local remote_path="$2"
  local local_path="$3"

  if ! lab_scp_from "$host" "$remote_path" "$local_path" >/dev/null 2>&1; then
    warn "Could not copy ${host}:${remote_path}"
    return 1
  fi
}

save_common_state() {
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-route.txt" "ip route show"
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh.txt" "ip neigh show"
  capture_remote_command gateway "${RUN_DIR}/gateway/dnsmasq-service.txt" "systemctl status dnsmasq --no-pager || true"
  capture_remote_command victim "${RUN_DIR}/victim/ip-route.txt" "ip route show"
  capture_remote_command victim "${RUN_DIR}/victim/ip-neigh.txt" "ip neigh show"
  capture_remote_command victim "${RUN_DIR}/victim/detector-service.txt" "systemctl status mitm-lab-detector.service --no-pager || true"
  capture_remote_command attacker "${RUN_DIR}/attacker/ip-route.txt" "ip route show"
  capture_remote_command attacker "${RUN_DIR}/attacker/ip-neigh.txt" "ip neigh show"
}

save_capture_files() {
  fetch_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-gateway.pcap" "${RUN_DIR}/pcap/gateway.pcap" || true
  fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-victim.pcap" "${RUN_DIR}/pcap/victim.pcap" || true
  fetch_remote_file attacker "/tmp/${RUN_ID}-${RUN_SLUG}-attacker.pcap" "${RUN_DIR}/pcap/attacker.pcap" || true
  fetch_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log" "${RUN_DIR}/gateway/iperf-server.log" || true
}

write_summary() {
  local target="${1:-${RUN_DIR}}"
  python3 "${SCRIPT_DIR}/85-summarize-results.py" "${target}" | tee "${target}/summary.txt"
}
