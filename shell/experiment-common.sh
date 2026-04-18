#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-20000}"
PCAP_ENABLE="${PCAP_ENABLE:-1}"
ZEEK_ENABLE="${ZEEK_ENABLE:-0}"
SURICATA_ENABLE="${SURICATA_ENABLE:-0}"
DETECTOR_PACKET_SAMPLE_RATE="${DETECTOR_PACKET_SAMPLE_RATE:-1}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-10}"
KEEP_DEBUG_ARTIFACTS="${KEEP_DEBUG_ARTIFACTS:-0}"
ZEEK_ACTIVE=0
SURICATA_ACTIVE=0
SURICATA_ARP_RULE_ACTIVE=0
PCAP_ACTIVE=0

lab_python_module() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m "$@"
}

require_experiment_tools() {
  require_cmd ssh
  require_cmd scp
  require_cmd python3
  if pcap_requested; then
    require_cmd tshark
  fi
}

pcap_requested() {
  case "${PCAP_ENABLE}" in
    1|true|yes|on|auto)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown PCAP_ENABLE value: ${PCAP_ENABLE}; disabling pcap capture"
      return 1
      ;;
  esac
}

render_victim_detector() {
  local outfile="$1"

  lab_python_module lab.cli render-detector "${LAB_DIR}" "${outfile}"
}

render_victim_zeek_policy() {
  local outfile="$1"

  lab_python_module lab.cli render-zeek-policy "${LAB_DIR}" "${outfile}"
}

render_victim_suricata_rules() {
  local outfile="$1"
  local include_arp="${2:-1}"
  local attacker_ip victim_ip gateway_ip a b c d attacker_ip_hex
  local attacker_mac attacker_mac_hex gateway_ip_hex victim_ip_hex
  local m1 m2 m3 m4 m5 m6

  attacker_ip="$(cidr_addr "${ATTACKER_CIDR}")"
  victim_ip="$(cidr_addr "${VICTIM_CIDR}")"
  gateway_ip="${GATEWAY_IP}"
  attacker_mac="${ATTACKER_MAC,,}"
  IFS=. read -r a b c d <<< "${attacker_ip}"
  printf -v attacker_ip_hex '|%02X %02X %02X %02X|' "${a}" "${b}" "${c}" "${d}"
  IFS=. read -r a b c d <<< "${gateway_ip}"
  printf -v gateway_ip_hex '|%02X %02X %02X %02X|' "${a}" "${b}" "${c}" "${d}"
  IFS=. read -r a b c d <<< "${victim_ip}"
  printf -v victim_ip_hex '|%02X %02X %02X %02X|' "${a}" "${b}" "${c}" "${d}"
  IFS=: read -r m1 m2 m3 m4 m5 m6 <<< "${attacker_mac}"
  printf -v attacker_mac_hex '|%s %s %s %s %s %s|' \
    "${m1^^}" "${m2^^}" "${m3^^}" "${m4^^}" "${m5^^}" "${m6^^}"

  {
    if [[ "${include_arp}" == "1" ]]; then
      printf '%s\n' \
        "alert ether any any -> any any (msg:\"MITM-LAB live ARP reply from attacker claims gateway IP to victim\"; ether.hdr; content:\"${attacker_mac_hex}\"; offset:6; depth:6; content:\"|08 06|\"; offset:12; depth:2; content:\"|00 02|\"; offset:20; depth:2; content:\"${gateway_ip_hex}\"; offset:28; depth:4; content:\"${victim_ip_hex}\"; offset:38; depth:4; classtype:attempted-admin; sid:9901000; rev:1;)"
    fi
    cat <<EOF
alert icmp ${attacker_ip} any -> ${victim_ip} any (msg:"MITM-LAB live ICMP redirect from attacker to victim"; itype:5; classtype:attempted-admin; sid:9901001; rev:1;)
alert udp ${gateway_ip} 53 -> ${victim_ip} any (msg:"MITM-LAB live DNS answer contains attacker IP"; content:"${attacker_ip_hex}"; classtype:bad-unknown; sid:9901002; rev:1;)
EOF
  } > "${outfile}"
}

prepare_victim_detector() {
  local rendered_detector detector_override
  rendered_detector="$(mktemp)"
  detector_override="$(mktemp)"
  render_victim_detector "${rendered_detector}"
  printf '[Service]\nEnvironment=MITM_LAB_PACKET_SAMPLE_RATE=%s\nEnvironment=MITM_LAB_HEARTBEAT_SECONDS=%s\n' \
    "${DETECTOR_PACKET_SAMPLE_RATE}" \
    "${DETECTOR_HEARTBEAT_SECONDS}" > "${detector_override}"

  info "Refreshing victim gateway neighbor state before detector baseline"
  remote_sudo_bash_lc victim \
    "ip neigh del '${GATEWAY_IP}' dev vnic0 2>/dev/null || true"
  remote_bash_lc victim \
    "ping -c 1 -W 1 '${GATEWAY_IP}' >/dev/null 2>&1 || true"

  info "Deploying current detector source to victim"
  lab_scp_to victim "${rendered_detector}" "/tmp/mitm_lab_detector.py"
  lab_scp_to victim "${detector_override}" "/tmp/mitm-lab-detector.override.conf"
  remote_sudo_bash_lc victim \
    "if ! python3 -c 'import scapy.all' >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-scapy; fi
     install -d -m 0755 '/etc/systemd/system/mitm-lab-detector.service.d'
     install -m 0755 '/tmp/mitm_lab_detector.py' '/usr/local/bin/mitm_lab_detector.py'
     install -m 0644 '/tmp/mitm-lab-detector.override.conf' '/etc/systemd/system/mitm-lab-detector.service.d/override.conf'
     rm -f '/tmp/mitm_lab_detector.py' '/tmp/mitm-lab-detector.override.conf'
     rm -f '/var/lib/mitm-lab-detector/state.json'
     systemctl daemon-reload
     systemctl restart mitm-lab-detector.service
     systemctl is-active --quiet mitm-lab-detector.service"

  rm -f "${rendered_detector}"
  rm -f "${detector_override}"
  prime_victim_detector_domains
  wait_for_victim_detector_baseline
}

zeek_requested() {
  case "${ZEEK_ENABLE}" in
    1|true|yes|on|auto)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown ZEEK_ENABLE value: ${ZEEK_ENABLE}; skipping Zeek"
      return 1
      ;;
  esac
}

suricata_requested() {
  case "${SURICATA_ENABLE}" in
    1|true|yes|on|auto)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown SURICATA_ENABLE value: ${SURICATA_ENABLE}; skipping Suricata"
      return 1
      ;;
  esac
}

prepare_victim_zeek() {
  local rendered_policy

  ZEEK_ACTIVE=0
  if ! zeek_requested; then
    return 0
  fi

  rendered_policy="$(mktemp)"
  render_victim_zeek_policy "${rendered_policy}"

  info "Deploying live Zeek comparison sensor to victim"
  lab_scp_to victim "${rendered_policy}" "/tmp/mitm-lab-live.zeek"
  lab_scp_to victim "${LAB_DIR}/shell/mitm-lab-zeek-live.sh" "/tmp/mitm-lab-zeek-live.sh"
  lab_scp_to victim "${LAB_DIR}/services/mitm-lab-zeek.service" "/tmp/mitm-lab-zeek.service"

  if remote_sudo_bash_lc victim \
    "if ! command -v zeek >/dev/null 2>&1 && [[ ! -x /opt/zeek/bin/zeek ]]; then
       if ! command -v gpg >/dev/null 2>&1; then
         apt-get update
         DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg ca-certificates
       fi
       . /etc/os-release
       repo_base=\"https://download.opensuse.org/repositories/security:/zeek/xUbuntu_\${VERSION_ID}\"
       curl -fsSL \"\${repo_base}/Release.key\" | gpg --dearmor > /tmp/security_zeek.gpg
       install -m 0644 /tmp/security_zeek.gpg /etc/apt/trusted.gpg.d/security_zeek.gpg
       echo \"deb \${repo_base}/ /\" > /etc/apt/sources.list.d/security:zeek.list
       apt-get update
       DEBIAN_FRONTEND=noninteractive apt-get install -y zeek
     fi
     if ! command -v zeek >/dev/null 2>&1 && [[ -x /opt/zeek/bin/zeek ]]; then
       ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
     fi
     install -d -m 0755 '/etc/mitm-lab' '/var/log/mitm-lab-zeek/current'
     install -m 0644 '/tmp/mitm-lab-live.zeek' '/etc/mitm-lab/mitm-lab-live.zeek'
     install -m 0755 '/tmp/mitm-lab-zeek-live.sh' '/usr/local/bin/mitm-lab-zeek-live.sh'
     install -m 0644 '/tmp/mitm-lab-zeek.service' '/etc/systemd/system/mitm-lab-zeek.service'
     rm -f '/tmp/mitm-lab-live.zeek' '/tmp/mitm-lab-zeek-live.sh' '/tmp/mitm-lab-zeek.service'
     rm -f /var/log/mitm-lab-zeek/current/*.log
     systemctl daemon-reload
     systemctl enable --now mitm-lab-zeek.service
     systemctl restart mitm-lab-zeek.service
     systemctl is-active --quiet mitm-lab-zeek.service"; then
    ZEEK_ACTIVE=1
  else
    warn "Victim Zeek service could not be prepared; continuing without Zeek comparison for this run"
  fi

  rm -f "${rendered_policy}"
}

prepare_victim_suricata() {
  local rendered_rules

  SURICATA_ACTIVE=0
  SURICATA_ARP_RULE_ACTIVE=0
  if ! suricata_requested; then
    return 0
  fi

  rendered_rules="$(mktemp)"
  render_victim_suricata_rules "${rendered_rules}" 1

  info "Deploying live Suricata comparison sensor to victim"
  lab_scp_to victim "${rendered_rules}" "/tmp/mitm-lab-suricata.rules"
  lab_scp_to victim "${LAB_DIR}/shell/mitm-lab-suricata-live.sh" "/tmp/mitm-lab-suricata-live.sh"
  lab_scp_to victim "${LAB_DIR}/services/mitm-lab-suricata.service" "/tmp/mitm-lab-suricata.service"

  if remote_sudo_bash_lc victim \
    "set -euo pipefail
     need_upgrade=0
     if ! command -v suricata >/dev/null 2>&1; then
       need_upgrade=1
     elif ! suricata --build-info 2>/dev/null | sed -n '1p' | grep -Eq 'version 8\\.'; then
       need_upgrade=1
     fi
     if [[ \"\${need_upgrade}\" == '1' ]]; then
       apt-get update
       DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common ca-certificates
       add-apt-repository -y ppa:oisf/suricata-stable
       apt-get update
       DEBIAN_FRONTEND=noninteractive apt-get remove -y suricata-update || true
       DEBIAN_FRONTEND=noninteractive apt-get install -y suricata
     fi
     install -d -m 0755 '/etc/mitm-lab' '/var/log/mitm-lab-suricata/current'
     install -m 0644 '/tmp/mitm-lab-suricata.rules' '/etc/mitm-lab/mitm-lab-suricata.rules'
     install -m 0755 '/tmp/mitm-lab-suricata-live.sh' '/usr/local/bin/mitm-lab-suricata-live.sh'
     install -m 0644 '/tmp/mitm-lab-suricata.service' '/etc/systemd/system/mitm-lab-suricata.service'
     rm -f '/tmp/mitm-lab-suricata.rules' '/tmp/mitm-lab-suricata-live.sh' '/tmp/mitm-lab-suricata.service'"; then
    if remote_sudo_bash_lc victim "suricata -T -c '/etc/suricata/suricata.yaml' -S '/etc/mitm-lab/mitm-lab-suricata.rules' >/tmp/mitm-lab-suricata-test.log 2>&1"; then
      SURICATA_ARP_RULE_ACTIVE=1
    else
      warn "Victim Suricata rejected the ARP comparison rule; falling back to ICMP+DNS only"
      render_victim_suricata_rules "${rendered_rules}" 0
      lab_scp_to victim "${rendered_rules}" "/tmp/mitm-lab-suricata.rules"
      remote_sudo_bash_lc victim \
        "install -m 0644 '/tmp/mitm-lab-suricata.rules' '/etc/mitm-lab/mitm-lab-suricata.rules'
         rm -f '/tmp/mitm-lab-suricata.rules'"
      SURICATA_ARP_RULE_ACTIVE=0
    fi

    if remote_sudo_bash_lc victim \
      "rm -f /var/log/mitm-lab-suricata/current/*.json /var/log/mitm-lab-suricata/current/*.log
       systemctl daemon-reload
       systemctl enable --now mitm-lab-suricata.service
       systemctl restart mitm-lab-suricata.service
       systemctl is-active --quiet mitm-lab-suricata.service"; then
      SURICATA_ACTIVE=1
    else
      warn "Victim Suricata service could not be started after preparation; continuing without Suricata comparison for this run"
    fi
  else
    warn "Victim Suricata service could not be prepared; continuing without Suricata comparison for this run"
  fi

  rm -f "${rendered_rules}"
}

prime_victim_detector_domains() {
  info "Priming victim detector with clean DNS answers for monitored domains"
  remote_bash_lc victim \
    "for domain in ${DETECTOR_DOMAINS}; do dig +time=1 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}' >/dev/null 2>&1 || true; done"
  sleep 2
}

wait_for_victim_detector_baseline() {
  local attempts delay try state

  attempts="${DETECTOR_BASELINE_ATTEMPTS:-10}"
  delay="${DETECTOR_BASELINE_DELAY_SECONDS:-1}"

  for ((try = 1; try <= attempts; try++)); do
    state="$(remote_bash_lc victim "python3 - <<'PY'
import json
from pathlib import Path

path = Path('/var/lib/mitm-lab-detector/state.json')
if not path.exists():
    print('{}')
else:
    print(path.read_text())
PY")"

    if [[ "${state}" == *"\"expected_gateway_mac\": \"${GATEWAY_LAB_MAC,,}\""* ]]; then
      info "Victim detector baseline is set to ${GATEWAY_LAB_MAC} (${try}/${attempts})"
      return 0
    fi

    if (( try < attempts )); then
      sleep "${delay}"
    fi
  done

  warn "Victim detector baseline did not settle on ${GATEWAY_LAB_MAC}; continuing anyway"
  return 0
}

research_workspace_root() {
  printf '/opt/mitm-lab\n'
}

prepare_attacker_research_workspace() {
  local remote_root
  remote_root="$(research_workspace_root)"

  info "Preparing attacker research workspace under ${remote_root}"
  cleanup_attacker_dns_block_rules
  remote_sudo_bash_lc attacker \
    "mkdir -p '${remote_root}/python' && chown -R '${LAB_USER}:${LAB_USER}' '${remote_root}'"

  lab_scp_to attacker "${LAB_DIR}/lab.conf" "${remote_root}/lab.conf"
  lab_scp_to attacker "${LAB_DIR}/python/lab" "${remote_root}/python/lab"
  lab_scp_to attacker "${LAB_DIR}/python/mitm" "${remote_root}/python/mitm"

  remote_bash_lc attacker \
    "find '${remote_root}/python' -type f -name '*.py' -exec chmod 0644 {} + && chmod 0644 '${remote_root}/lab.conf'"
  remote_bash_lc attacker "PYTHONPATH='${remote_root}/python' python3 -c 'import mitm.cli, scapy.all'"
}

cleanup_attacker_dns_block_rules() {
  remote_sudo_bash_lc attacker \
    "while iptables -D FORWARD -s '$(cidr_addr "${VICTIM_CIDR}")' -d '${GATEWAY_IP}' -p udp --dport 53 -j DROP >/dev/null 2>&1; do :; done
     while iptables -D FORWARD -s '${GATEWAY_IP}' -d '$(cidr_addr "${VICTIM_CIDR}")' -p udp --sport 53 -j DROP >/dev/null 2>&1; do :; done" \
    >/dev/null 2>&1 || true
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

json_bool() {
  case "${1:-}" in
    1|true|yes|on)
      printf 'true\n'
      ;;
    *)
      printf 'false\n'
      ;;
  esac
}

json_number_or_null() {
  if [[ -n "${1:-}" ]]; then
    printf '%s\n' "$1"
  else
    printf 'null\n'
  fi
}

json_string_array_from_words() {
  lab_python_module lab.cli json-string-array "$1"
}

timestamp_at_offset_or_null() {
  local base_ts="$1"
  local offset="$2"

  if [[ -z "${offset}" ]]; then
    printf 'null\n'
    return 0
  fi

  lab_python_module lab.cli timestamp-at-offset "$base_ts" "$offset"
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
  PCAP_ACTIVE=0

  mkdir -p "${RUN_DIR}/host" "${RUN_DIR}/gateway" "${RUN_DIR}/victim" "${RUN_DIR}/attacker" "${RUN_DIR}/pcap"
}

start_lab_and_wait_for_access() {
  "${LAB_DIR}/shell/lab/start-lab.sh" >/dev/null

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
  local run_index_json warmup_json duration_json attack_start_json attack_stop_json mitigation_start_json forwarding_json dns_spoof_json spoofed_domains_json

  run_index_json="$(json_number_or_null "${PLAN_RUN_INDEX:-}")"
  warmup_json="$(json_bool "${PLAN_WARMUP:-0}")"
  duration_json="$(json_number_or_null "${PLAN_DURATION_SECONDS:-}")"
  attack_start_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_ATTACK_START_OFFSET_SECONDS:-}")"
  attack_stop_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_ATTACK_STOP_OFFSET_SECONDS:-}")"
  mitigation_start_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_MITIGATION_START_OFFSET_SECONDS:-}")"
  forwarding_json="$(json_bool "${PLAN_FORWARDING_ENABLED:-0}")"
  dns_spoof_json="$(json_bool "${PLAN_DNS_SPOOF_ENABLED:-0}")"
  spoofed_domains_json="$(json_string_array_from_words "${PLAN_SPOOFED_DOMAINS:-}")"

  cat > "${RUN_DIR}/run-meta.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "scenario": "${RUN_SCENARIO}",
  "mode": "${mode}",
  "started_at": "${started_at}",
  "ended_at": "${ended_at}",
  "capture_packet_count": ${CAPTURE_PACKET_COUNT},
  "gateway_upstream_ip": "$(gateway_upstream_ip)",
  "gateway_lab_ip": "${GATEWAY_IP}",
  "gateway_lab_mac": "${GATEWAY_LAB_MAC}",
  "victim_ip": "$(cidr_addr "${VICTIM_CIDR}")",
  "victim_mac": "${VICTIM_MAC}",
  "attacker_ip": "$(cidr_addr "${ATTACKER_CIDR}")",
  "attacker_mac": "${ATTACKER_MAC}",
  "run_index": ${run_index_json},
  "warmup": ${warmup_json},
  "duration_seconds": ${duration_json},
  "attack_started_at": ${attack_start_json},
  "attack_stopped_at": ${attack_stop_json},
  "mitigation_started_at": ${mitigation_start_json},
  "forwarding_enabled": ${forwarding_json},
  "dns_spoof_enabled": ${dns_spoof_json},
  "spoofed_domains": ${spoofed_domains_json},
  "pcap_enabled": $(json_bool "${PCAP_ACTIVE:-0}"),
  "zeek_enabled": $(json_bool "${ZEEK_ACTIVE:-0}"),
  "suricata_enabled": $(json_bool "${SURICATA_ACTIVE:-0}"),
  "suricata_arp_rule_enabled": $(json_bool "${SURICATA_ARP_RULE_ACTIVE:-0}"),
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

capture_local_command() {
  local outfile="$1"
  local cmd="$2"

  if ! bash -lc "$cmd" > "${outfile}" 2>&1; then
    warn "Local command failed; output kept in ${outfile}"
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

  if ! pcap_requested; then
    return 0
  fi

  PCAP_ACTIVE=1

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

  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

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

remote_file_exists() {
  local host="$1"
  local remote_path="$2"

  remote_bash_lc "$host" "test -f '$remote_path'" >/dev/null 2>&1
}

wait_for_remote_file() {
  local host="$1"
  local remote_path="$2"
  local attempts="${3:-5}"
  local delay="${4:-1}"
  local try

  for ((try = 1; try <= attempts; try++)); do
    if remote_file_exists "$host" "$remote_path"; then
      return 0
    fi
    if (( try < attempts )); then
      sleep "$delay"
    fi
  done

  return 1
}

start_remote_background_job() {
  local host="$1"
  local label="$2"
  local cmd="$3"
  local remote_base pid_file stdout_file stderr_file quoted_cmd

  remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  pid_file="${remote_base}.pid"
  stdout_file="${remote_base}.stdout"
  stderr_file="${remote_base}.stderr"
  printf -v quoted_cmd '%q' "$cmd"

  remote_bash_lc "$host" \
    "rm -f '${pid_file}' '${stdout_file}' '${stderr_file}'; nohup bash -lc ${quoted_cmd} >'${stdout_file}' 2>'${stderr_file}' </dev/null & echo \$! > '${pid_file}'"
}

stop_remote_background_job() {
  local host="$1"
  local label="$2"
  local remote_base pid_file

  remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  pid_file="${remote_base}.pid"

  remote_bash_lc "$host" \
    "if test -f '${pid_file}'; then pid=\$(cat '${pid_file}'); kill -INT \"\$pid\" 2>/dev/null || true; for _ in 1 2 3 4 5; do if ! kill -0 \"\$pid\" 2>/dev/null; then break; fi; sleep 1; done; if kill -0 \"\$pid\" 2>/dev/null; then kill -TERM \"\$pid\" 2>/dev/null || true; sleep 1; fi; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL \"\$pid\" 2>/dev/null || true; fi; fi" \
    >/dev/null 2>&1 || true

  if [[ "${host}" == "attacker" ]]; then
    cleanup_attacker_dns_block_rules
  fi
}

save_common_state() {
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-route.txt" "ip route show"
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh.txt" "ip neigh show"
  capture_remote_command gateway "${RUN_DIR}/gateway/dnsmasq-service.txt" "systemctl status dnsmasq --no-pager || true"
  capture_remote_command victim "${RUN_DIR}/victim/ip-route.txt" "ip route show"
  capture_remote_command victim "${RUN_DIR}/victim/ip-neigh.txt" "ip neigh show"
  capture_remote_command victim "${RUN_DIR}/victim/detector-service.txt" "systemctl status mitm-lab-detector.service --no-pager || true"
  capture_remote_command victim "${RUN_DIR}/victim/zeek-service.txt" "systemctl status mitm-lab-zeek.service --no-pager || true"
  capture_remote_command victim "${RUN_DIR}/victim/suricata-service.txt" "systemctl status mitm-lab-suricata.service --no-pager || true"
  capture_remote_command attacker "${RUN_DIR}/attacker/ip-route.txt" "ip route show"
  capture_remote_command attacker "${RUN_DIR}/attacker/ip-neigh.txt" "ip neigh show"
}

save_tool_versions() {
  capture_local_command "${RUN_DIR}/host/versions.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo 'capture_packet_count=${CAPTURE_PACKET_COUNT}'
    echo
    echo '== os-release =='
    cat /etc/os-release 2>/dev/null || true
    echo
    echo '== uname =='
    uname -a || true
    echo
    echo '== command versions =='
    python3 --version || true
    virsh --version || true
    qemu-system-x86_64 --version 2>/dev/null | sed -n '1p' || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst \
      tshark tcpdump python3 curl jq dnsutils 2>/dev/null || true
  "

  capture_remote_command gateway "${RUN_DIR}/gateway/versions.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo
    echo '== os-release =='
    cat /etc/os-release 2>/dev/null || true
    echo
    echo '== uname =='
    uname -a || true
    echo
    echo '== command versions =='
    python3 --version 2>/dev/null || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    dig -v 2>/dev/null | sed -n '1p' || true
    dnsmasq --version 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    iperf3 --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      tcpdump tshark dnsutils dnsmasq curl iperf3 jq 2>/dev/null || true
  "

  capture_remote_command victim "${RUN_DIR}/victim/versions.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo
    echo '== os-release =='
    cat /etc/os-release 2>/dev/null || true
    echo
    echo '== uname =='
    uname -a || true
    echo
    echo '== command versions =='
    python3 --version 2>/dev/null || true
    python3 -c 'import scapy; print(\"scapy=\" + scapy.__version__)' 2>/dev/null || true
    zeek --version 2>/dev/null | sed -n '1p' || true
    suricata --build-info 2>/dev/null | sed -n '1,4p' || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    dig -v 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    iperf3 --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      python3 python3-pip python3-scapy tcpdump tshark dnsutils curl iperf3 jq zeek suricata 2>/dev/null || true
  "

  capture_remote_command attacker "${RUN_DIR}/attacker/versions.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo
    echo '== os-release =='
    cat /etc/os-release 2>/dev/null || true
    echo
    echo '== uname =='
    uname -a || true
    echo
    echo '== command versions =='
    python3 --version 2>/dev/null || true
    python3 -c 'import scapy; print(\"scapy=\" + scapy.__version__)' 2>/dev/null || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    dig -v 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    iperf3 --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      python3 python3-pip python3-scapy tcpdump tshark dnsutils curl iperf3 jq 2>/dev/null || true
  "
}

save_capture_files() {
  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  fetch_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-gateway.pcap" "${RUN_DIR}/pcap/gateway.pcap" || true
  fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-victim.pcap" "${RUN_DIR}/pcap/victim.pcap" || true
  fetch_remote_file attacker "/tmp/${RUN_ID}-${RUN_SLUG}-attacker.pcap" "${RUN_DIR}/pcap/attacker.pcap" || true
  if remote_file_exists gateway "/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log"; then
    fetch_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log" "${RUN_DIR}/gateway/iperf-server.log" || true
  fi
}

write_tshark_summary() {
  local pcap_path="$1"
  local outfile="${pcap_path%.pcap}.tshark-summary.txt"

  [[ -s "${pcap_path}" ]] || return 0

  {
    echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "pcap=${pcap_path}"
    echo
    echo "== packet count =="
    tshark -r "${pcap_path}" -q -z io,phs
    echo
    echo "== conversations (ip) =="
    tshark -r "${pcap_path}" -q -z conv,ip
    echo
    echo "== endpoints (ip) =="
    tshark -r "${pcap_path}" -q -z endpoints,ip
    echo
    echo "== arp frames sample =="
    tshark -r "${pcap_path}" -Y arp \
      -T fields \
      -e frame.number \
      -e frame.time_relative \
      -e eth.src \
      -e eth.dst \
      -e arp.src.proto_ipv4 \
      -e arp.src.hw_mac \
      -e arp.dst.proto_ipv4 \
      -E header=y -E separator=, | sed -n '1,80p'
    echo
    echo "== dns frames sample =="
    tshark -r "${pcap_path}" -Y dns \
      -T fields \
      -e frame.number \
      -e frame.time_relative \
      -e ip.src \
      -e ip.dst \
      -e dns.qry.name \
      -e dns.a \
      -E header=y -E separator=, | sed -n '1,80p'
    echo
    echo "== icmp redirect sample =="
    tshark -r "${pcap_path}" -Y "icmp.type == 5" \
      -T fields \
      -e frame.number \
      -e frame.time_relative \
      -e ip.src \
      -e ip.dst \
      -e icmp.type \
      -e icmp.code \
      -e icmp.redir_gw \
      -E header=y -E separator=, | sed -n '1,80p'
  } > "${outfile}" 2>&1 || {
    warn "tshark summary failed for ${pcap_path}"
    return 0
  }
}

summarize_saved_pcaps() {
  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  while IFS= read -r -d '' pcap_path; do
    write_tshark_summary "${pcap_path}"
  done < <(find "${RUN_DIR}/pcap" -maxdepth 1 -type f -name '*.pcap' -print0 | sort -z)
}

write_zeek_status() {
  local message="$1"
  mkdir -p "${RUN_DIR}/zeek"
  printf '%s\n' "${message}" > "${RUN_DIR}/zeek/status.txt"
}

write_suricata_status() {
  local message="$1"
  mkdir -p "${RUN_DIR}/suricata"
  printf '%s\n' "${message}" > "${RUN_DIR}/suricata/status.txt"
}

capture_victim_zeek_artifacts() {
  local outdir notice_path summary_path

  if ! zeek_requested; then
    write_zeek_status "zeek_status=skipped"
    return 0
  fi

  if [[ "${ZEEK_ACTIVE:-0}" != "1" ]]; then
    write_zeek_status "zeek_status=prepare_failed"
    return 0
  fi

  outdir="${RUN_DIR}/zeek/victim"
  notice_path="${outdir}/notice.log"
  summary_path="${outdir}/summary.txt"
  mkdir -p "${outdir}"

  if remote_file_exists victim "/var/log/mitm-lab-zeek/current/notice.log"; then
    fetch_remote_file victim "/var/log/mitm-lab-zeek/current/notice.log" "${notice_path}" || true
  fi

  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    if remote_file_exists victim "/var/log/mitm-lab-zeek/current/reporter.log"; then
      fetch_remote_file victim "/var/log/mitm-lab-zeek/current/reporter.log" "${outdir}/reporter.log" || true
    fi
    if remote_file_exists victim "/var/log/mitm-lab-zeek/current/loaded_scripts.log"; then
      fetch_remote_file victim "/var/log/mitm-lab-zeek/current/loaded_scripts.log" "${outdir}/loaded_scripts.log" || true
    fi
  fi

  if [[ -f "${notice_path}" ]]; then
    PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m logs.zeek_notice "${notice_path}" > "${summary_path}" 2>&1 || true
    write_zeek_status "zeek_status=ok"
  else
    write_zeek_status "zeek_status=ok_no_notice"
  fi
}

capture_victim_suricata_artifacts() {
  local outdir eve_path summary_path

  if ! suricata_requested; then
    write_suricata_status "suricata_status=skipped"
    return 0
  fi

  if [[ "${SURICATA_ACTIVE:-0}" != "1" ]]; then
    write_suricata_status "suricata_status=prepare_failed"
    return 0
  fi

  outdir="${RUN_DIR}/suricata/victim"
  eve_path="${outdir}/eve.json"
  summary_path="${outdir}/summary.txt"
  mkdir -p "${outdir}"

  if remote_file_exists victim "/var/log/mitm-lab-suricata/current/eve.json"; then
    fetch_remote_file victim "/var/log/mitm-lab-suricata/current/eve.json" "${eve_path}" || true
  fi

  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    if remote_file_exists victim "/var/log/mitm-lab-suricata/current/fast.log"; then
      fetch_remote_file victim "/var/log/mitm-lab-suricata/current/fast.log" "${outdir}/fast.log" || true
    fi
    if remote_file_exists victim "/var/log/mitm-lab-suricata/current/suricata.log"; then
      fetch_remote_file victim "/var/log/mitm-lab-suricata/current/suricata.log" "${outdir}/suricata.log" || true
    fi
    if remote_file_exists victim "/var/log/mitm-lab-suricata/current/stats.log"; then
      fetch_remote_file victim "/var/log/mitm-lab-suricata/current/stats.log" "${outdir}/stats.log" || true
    fi
  fi

  if [[ -f "${eve_path}" ]]; then
    PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m logs.suricata_eve "${eve_path}" > "${summary_path}" 2>&1 || true
    write_suricata_status "suricata_status=ok"
  else
    write_suricata_status "suricata_status=ok_no_eve"
  fi
}

prune_run_artifacts() {
  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    return 0
  fi

  rm -f \
    "${RUN_DIR}/host/versions.txt" \
    "${RUN_DIR}/gateway/ip-route.txt" \
    "${RUN_DIR}/gateway/ip-neigh.txt" \
    "${RUN_DIR}/gateway/ip-neigh-after.txt" \
    "${RUN_DIR}/gateway/dnsmasq-service.txt" \
    "${RUN_DIR}/gateway/dnsmasq.delta.log" \
    "${RUN_DIR}/gateway/iperf-server.log" \
    "${RUN_DIR}/gateway/versions.txt" \
    "${RUN_DIR}/victim/ip-route.txt" \
    "${RUN_DIR}/victim/ip-neigh.txt" \
    "${RUN_DIR}/victim/ip-neigh-after.txt" \
    "${RUN_DIR}/victim/detector-service.txt" \
    "${RUN_DIR}/victim/zeek-service.txt" \
    "${RUN_DIR}/victim/suricata-service.txt" \
    "${RUN_DIR}/victim/detector.state.json" \
    "${RUN_DIR}/victim/post-window-probe.txt" \
    "${RUN_DIR}/victim/versions.txt" \
    "${RUN_DIR}/attacker/ip-route.txt" \
    "${RUN_DIR}/attacker/ip-neigh.txt" \
    "${RUN_DIR}/attacker/ip-neigh-after.txt" \
    "${RUN_DIR}/attacker/versions.txt" \
    "${RUN_DIR}/attacker/"*.command.txt \
    "${RUN_DIR}/attacker/"*.stdout \
    "${RUN_DIR}/attacker/"*.stderr \
    "${RUN_DIR}/pcap/attacker.pcap" \
    "${RUN_DIR}/pcap/gateway.pcap" \
    "${RUN_DIR}/pcap/"*.tshark-summary.txt
}

explain_saved_run() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m logs.explain_run "${RUN_DIR}" > "${RUN_DIR}/victim/detector-explained.txt" 2>&1 || true
}

evaluate_saved_run() {
  lab_python_module metrics.evaluator "${RUN_DIR}" \
    --json-out "${RUN_DIR}/evaluation.json" \
    --text-out "${RUN_DIR}/evaluation-summary.txt" >/dev/null 2>&1 || true
}

write_summary() {
  local target="${1:-${RUN_DIR}}"
  lab_python_module metrics.summary_cli "${target}" | tee "${target}/summary.txt"
}
