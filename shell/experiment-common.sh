#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-0}"
PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY:-all}"
PCAP_ENABLE="${PCAP_ENABLE:-1}"
GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE:-0}"
ZEEK_ENABLE="${ZEEK_ENABLE:-1}"
SURICATA_ENABLE="${SURICATA_ENABLE:-1}"
DETECTOR_PACKET_SAMPLE_RATE="${DETECTOR_PACKET_SAMPLE_RATE:-1}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-10}"
KEEP_DEBUG_ARTIFACTS="${KEEP_DEBUG_ARTIFACTS:-0}"
ZEEK_ACTIVE=0
SURICATA_ACTIVE=0
SURICATA_ARP_RULE_ACTIVE=0
SURICATA_ARP_RULE_MODE="disabled"
SURICATA_ARP_RULE_NOTE=""
PCAP_ACTIVE=0

lab_python_module() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m "$@"
}

host_python_with_scapy() {
  local candidate

  for candidate in \
    "${MITM_LAB_HOST_PYTHON:-}" \
    /usr/bin/python3 \
    python3 \
    python; do
    [[ -n "${candidate}" ]] || continue
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import scapy.all' >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
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

guest_pcaps_requested() {
  case "${GUEST_PCAP_ENABLE}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown GUEST_PCAP_ENABLE value: ${GUEST_PCAP_ENABLE}; disabling guest pcaps"
      return 1
      ;;
  esac
}

pcap_summaries_requested() {
  case "${PCAP_SUMMARIES_ENABLE}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown PCAP_SUMMARIES_ENABLE value: ${PCAP_SUMMARIES_ENABLE}; disabling tshark summaries"
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
  local attacker_ip victim_ip

  attacker_ip="$(lab_host_ip attacker)"
  victim_ip="$(lab_host_ip victim)"

  lab_python_module lab.cli render-zeek-policy "${LAB_DIR}" "${outfile}" --attacker-ip "${attacker_ip}" --victim-ip "${victim_ip}"
}

render_victim_suricata_rules() {
  local outfile="$1"
  local include_arp="${2:-1}"
  local arp_rule_mode="${3:-arp}"
  local attacker_ip victim_ip gateway_ip a b c d attacker_ip_hex
  local attacker_mac attacker_mac_hex gateway_ip_hex victim_ip_hex
  local m1 m2 m3 m4 m5 m6

  attacker_ip="$(lab_host_ip attacker)"
  victim_ip="$(lab_host_ip victim)"
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
      case "${arp_rule_mode}" in
        arp)
          printf '%s\n' \
            "alert arp any any -> any any (msg:\"MITM-LAB live ARP reply from attacker claims gateway IP to victim\"; content:\"|00 02|\"; offset:6; depth:2; content:\"${attacker_mac_hex}\"; offset:8; depth:6; content:\"${gateway_ip_hex}\"; offset:14; depth:4; content:\"${victim_ip_hex}\"; offset:24; depth:4; classtype:attempted-admin; sid:9901000; rev:3;)"
          ;;
        ether)
          printf '%s\n' \
            "alert ether any any -> any any (msg:\"MITM-LAB live ARP reply from attacker claims gateway IP to victim\"; content:\"${attacker_mac_hex}\"; offset:6; depth:6; content:\"|08 06|\"; offset:12; depth:2; content:\"|00 02|\"; offset:20; depth:2; content:\"${gateway_ip_hex}\"; offset:28; depth:4; content:\"${victim_ip_hex}\"; offset:38; depth:4; classtype:attempted-admin; sid:9901000; rev:3;)"
          ;;
        *)
          warn "Unknown Suricata ARP rule mode: ${arp_rule_mode}"
          ;;
      esac
    fi
    cat <<EOF
alert icmp ${attacker_ip} any -> ${victim_ip} any (msg:"MITM-LAB live ICMP redirect from attacker to victim"; itype:5; classtype:attempted-admin; sid:9901001; rev:1;)
alert udp ${gateway_ip} 53 -> ${victim_ip} any (msg:"MITM-LAB live DNS answer contains attacker IP"; content:"${attacker_ip_hex}"; classtype:bad-unknown; sid:9901002; rev:1;)
alert udp ${attacker_ip} 67 -> any 68 (msg:"MITM-LAB live rogue DHCP reply from attacker"; content:"|63 82 53 63|"; offset:236; depth:4; classtype:bad-unknown; sid:9901003; rev:1;)
EOF
  } > "${outfile}"
}

prepare_victim_detector() {
  local rendered_detector
  local detector_path log_path state_path pid_path stdout_path stderr_path host_python
  rendered_detector="$(mktemp)"
  render_victim_detector "${rendered_detector}"
  detector_path="/tmp/mitm-lab-detector-host.py"
  log_path="/tmp/mitm-lab-detector-host.jsonl"
  state_path="/tmp/mitm-lab-detector-host-state.json"
  pid_path="/tmp/mitm-lab-detector-host.pid"
  stdout_path="/tmp/mitm-lab-detector-host.stdout"
  stderr_path="/tmp/mitm-lab-detector-host.stderr"

  if ! host_python="$(host_python_with_scapy)"; then
    rm -f "${rendered_detector}"
    warn "A host Python with Scapy is required for the host-side detector (tried MITM_LAB_HOST_PYTHON, /usr/bin/python3, python3, python)"
    return 1
  fi

  info "Starting detector on the mirrored switch sensor port ${LAB_SWITCH_SENSOR_PORT} with ${host_python}"
  run_root install -m 0755 "${rendered_detector}" "${detector_path}"
  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -TERM \"\${pid}\" 2>/dev/null || true
        sleep 1
      fi
    fi
    rm -f '${log_path}' '${state_path}' '${pid_path}' '${stdout_path}' '${stderr_path}'
    nohup env \
      MITM_LAB_INTERFACE='${LAB_SWITCH_SENSOR_PORT}' \
      MITM_LAB_LOG_PATH='${log_path}' \
      MITM_LAB_STATE_PATH='${state_path}' \
      MITM_LAB_EXPECTED_GATEWAY_MAC='${GATEWAY_LAB_MAC,,}' \
      MITM_LAB_EXPECTED_DHCP_SERVER='${GATEWAY_IP}' \
      MITM_LAB_EXPECTED_DHCP_SERVER_MAC='${GATEWAY_LAB_MAC,,}' \
      MITM_LAB_VICTIM_MAC='${VICTIM_MAC,,}' \
      MITM_LAB_ATTACKER_MAC='${ATTACKER_MAC,,}' \
      MITM_LAB_PACKET_SAMPLE_RATE='${DETECTOR_PACKET_SAMPLE_RATE}' \
      MITM_LAB_HEARTBEAT_SECONDS='${DETECTOR_HEARTBEAT_SECONDS}' \
      '${host_python}' '${detector_path}' >'${stdout_path}' 2>'${stderr_path}' </dev/null &
    echo \$! > '${pid_path}'
  "

  rm -f "${rendered_detector}"
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

local_zeek_bin() {
  if command -v zeek >/dev/null 2>&1; then
    command -v zeek
    return 0
  fi
  if [[ -x /opt/zeek/bin/zeek ]]; then
    printf '/opt/zeek/bin/zeek\n'
    return 0
  fi
  return 1
}

ensure_local_zeek() {
  local zeek_bin

  if zeek_bin="$(local_zeek_bin)"; then
    printf '%s\n' "${zeek_bin}"
    return 0
  fi

  info "Preparing host Zeek installation" >&2
  if ! run_root bash -lc "
    set -euo pipefail
    if ! command -v gpg >/dev/null 2>&1; then
      apt-get update || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg ca-certificates curl
    fi
    . /etc/os-release
    repo_base=\"https://download.opensuse.org/repositories/security:/zeek/xUbuntu_\${VERSION_ID}\"
    curl -fsSL \"\${repo_base}/Release.key\" | gpg --dearmor > /tmp/security_zeek.gpg
    install -m 0644 /tmp/security_zeek.gpg /etc/apt/trusted.gpg.d/security_zeek.gpg
    echo \"deb \${repo_base}/ /\" > /etc/apt/sources.list.d/security:zeek.list
    apt-get update || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y zeek
  " >&2; then
    return 1
  fi

  local_zeek_bin
}

ensure_local_suricata() {
  local suricata_bin

  if suricata_bin="$(command -v suricata 2>/dev/null)"; then
    printf '%s\n' "${suricata_bin}"
    return 0
  fi

  info "Preparing host Suricata installation" >&2
  if ! run_root bash -lc "
    set -euo pipefail
    apt-get update || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common ca-certificates
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update || true
    DEBIAN_FRONTEND=noninteractive apt-get remove -y suricata-update || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata
  " >&2; then
    return 1
  fi

  command -v suricata
}

prepare_victim_zeek() {
  local rendered_policy runtime_root log_dir policy_path pid_path stdout_path stderr_path zeek_bin

  ZEEK_ACTIVE=0
  if ! zeek_requested; then
    return 0
  fi

  rendered_policy="$(mktemp)"
  render_victim_zeek_policy "${rendered_policy}"
  runtime_root="/tmp/mitm-lab-zeek-host"
  log_dir="${runtime_root}/current"
  policy_path="${runtime_root}/mitm-lab-live.zeek"
  pid_path="${runtime_root}/zeek.pid"
  stdout_path="${runtime_root}/zeek.stdout"
  stderr_path="${runtime_root}/zeek.stderr"

  if ! zeek_bin="$(ensure_local_zeek)"; then
    rm -f "${rendered_policy}"
    warn "Host Zeek could not be prepared; continuing without Zeek comparison for this run"
    return 0
  fi

  info "Starting live Zeek comparison sensor on host switch port ${LAB_SWITCH_SENSOR_PORT}"
  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -TERM \"\${pid}\" 2>/dev/null || true
        sleep 1
      fi
    fi
    rm -rf '${runtime_root}'
    install -d -m 0755 '${log_dir}'
  "
  run_root install -m 0644 "${rendered_policy}" "${policy_path}"
  run_root bash -lc "
    nohup '${zeek_bin}' -C -i '${LAB_SWITCH_SENSOR_PORT}' 'Log::default_logdir=${log_dir}' '${policy_path}' >'${stdout_path}' 2>'${stderr_path}' </dev/null &
    echo \$! > '${pid_path}'
  "

  if run_root bash -lc "pid=\$(cat '${pid_path}' 2>/dev/null || true); [[ -n \"\${pid}\" ]] && kill -0 \"\${pid}\" 2>/dev/null"; then
    ZEEK_ACTIVE=1
  else
    warn "Host Zeek process did not stay up; continuing without Zeek comparison for this run"
  fi

  rm -f "${rendered_policy}"
}

prepare_victim_suricata() {
  local rendered_rules runtime_root log_dir rules_path pid_path stdout_path stderr_path suricata_bin
  local arp_rule_mode arp_test_log ether_test_log suricata_start_opts

  SURICATA_ACTIVE=0
  SURICATA_ARP_RULE_ACTIVE=0
  SURICATA_ARP_RULE_MODE="disabled"
  SURICATA_ARP_RULE_NOTE=""
  if ! suricata_requested; then
    return 0
  fi

  rendered_rules="$(mktemp)"
  arp_rule_mode="arp"
  suricata_start_opts=""
  render_victim_suricata_rules "${rendered_rules}" 1 "${arp_rule_mode}"
  runtime_root="/tmp/mitm-lab-suricata-host"
  log_dir="${runtime_root}/current"
  rules_path="${runtime_root}/mitm-lab-suricata.rules"
  pid_path="${runtime_root}/suricata.pid"
  stdout_path="${runtime_root}/suricata.stdout"
  stderr_path="${runtime_root}/suricata.stderr"
  arp_test_log="/tmp/mitm-lab-suricata-test-arp.log"
  ether_test_log="/tmp/mitm-lab-suricata-test-ether.log"

  if ! suricata_bin="$(ensure_local_suricata)"; then
    rm -f "${rendered_rules}"
    warn "Host Suricata could not be prepared; continuing without Suricata comparison for this run"
    return 0
  fi

  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -TERM \"\${pid}\" 2>/dev/null || true
        sleep 1
      fi
    fi
    rm -rf '${runtime_root}'
    rm -f '${arp_test_log}' '${ether_test_log}' /tmp/mitm-lab-suricata-test.log
    install -d -m 0755 '${log_dir}'
  "
  run_root install -m 0644 "${rendered_rules}" "${rules_path}"

  if run_root bash -lc "'${suricata_bin}' -T -c '/etc/suricata/suricata.yaml' -S '${rules_path}' >'${arp_test_log}' 2>&1"; then
    SURICATA_ARP_RULE_ACTIVE=1
    SURICATA_ARP_RULE_MODE="arp"
    suricata_start_opts=""
    run_root bash -lc "cp '${arp_test_log}' /tmp/mitm-lab-suricata-test.log"
  elif run_root bash -lc "'${suricata_bin}' -T -c '/etc/suricata/suricata.yaml' --set app-layer.protocols.arp.enabled=yes -S '${rules_path}' >'${arp_test_log}' 2>&1"; then
    SURICATA_ARP_RULE_ACTIVE=1
    SURICATA_ARP_RULE_MODE="arp"
    SURICATA_ARP_RULE_NOTE="Host Suricata ARP comparison enabled via --set app-layer.protocols.arp.enabled=yes"
    suricata_start_opts="--set app-layer.protocols.arp.enabled=yes"
    run_root bash -lc "cp '${arp_test_log}' /tmp/mitm-lab-suricata-test.log"
  else
    arp_rule_mode="ether"
    render_victim_suricata_rules "${rendered_rules}" 1 "${arp_rule_mode}"
    run_root install -m 0644 "${rendered_rules}" "${rules_path}"
    if run_root bash -lc "'${suricata_bin}' -T -c '/etc/suricata/suricata.yaml' --set app-layer.protocols.ether.enabled=yes -S '${rules_path}' >'${ether_test_log}' 2>&1"; then
      SURICATA_ARP_RULE_ACTIVE=1
      SURICATA_ARP_RULE_MODE="ether"
      SURICATA_ARP_RULE_NOTE="Host Suricata ARP comparison enabled via --set app-layer.protocols.ether.enabled=yes"
      suricata_start_opts="--set app-layer.protocols.ether.enabled=yes"
      run_root bash -lc "cp '${ether_test_log}' /tmp/mitm-lab-suricata-test.log"
    elif run_root bash -lc "'${suricata_bin}' -T -c '/etc/suricata/suricata.yaml' --set app-layer.protocols.ether.detection-enabled=yes -S '${rules_path}' >'${ether_test_log}' 2>&1"; then
      SURICATA_ARP_RULE_ACTIVE=1
      SURICATA_ARP_RULE_MODE="ether"
      SURICATA_ARP_RULE_NOTE="Host Suricata ARP comparison enabled via legacy ether.detection-enabled override"
      suricata_start_opts="--set app-layer.protocols.ether.detection-enabled=yes"
      run_root bash -lc "cp '${ether_test_log}' /tmp/mitm-lab-suricata-test.log"
    else
      warn "Host Suricata ARP comparison self-test failed; running DHCP+DNS+ICMP comparison only"
      render_victim_suricata_rules "${rendered_rules}" 0
      run_root install -m 0644 "${rendered_rules}" "${rules_path}"
      SURICATA_ARP_RULE_ACTIVE=0
      SURICATA_ARP_RULE_MODE="disabled"
      SURICATA_ARP_RULE_NOTE="Host Suricata ARP comparison self-test failed; DHCP+DNS+ICMP only"
      run_root bash -lc "cp '${ether_test_log}' /tmp/mitm-lab-suricata-test.log"
    fi
  fi

  info "Starting live Suricata comparison sensor on host switch port ${LAB_SWITCH_SENSOR_PORT}"
  run_root bash -lc "
    nohup '${suricata_bin}' -i '${LAB_SWITCH_SENSOR_PORT}' -l '${log_dir}' -c '/etc/suricata/suricata.yaml' ${suricata_start_opts} -S '${rules_path}' >'${stdout_path}' 2>'${stderr_path}' </dev/null &
    echo \$! > '${pid_path}'
  "

  if run_root bash -lc "pid=\$(cat '${pid_path}' 2>/dev/null || true); [[ -n \"\${pid}\" ]] && kill -0 \"\${pid}\" 2>/dev/null"; then
    SURICATA_ACTIVE=1
  else
    warn "Host Suricata process did not stay up; continuing without Suricata comparison for this run"
  fi

  rm -f "${rendered_rules}"
}

prime_victim_detector_domains() {
  info "Priming the switch-side detector with clean victim DNS answers"
  remote_bash_lc victim \
    "for domain in ${DETECTOR_DOMAINS}; do dig +time=1 +tries=1 +short A \"\$domain\" @'${DNS_SERVER}' >/dev/null 2>&1 || true; done"
  sleep 2
}

wait_for_victim_detector_baseline() {
  local attempts delay try state

  attempts="${DETECTOR_BASELINE_ATTEMPTS:-10}"
  delay="${DETECTOR_BASELINE_DELAY_SECONDS:-1}"

  for ((try = 1; try <= attempts; try++)); do
    state="$(
      run_root python3 - <<'PY'
from pathlib import Path

path = Path('/tmp/mitm-lab-detector-host-state.json')
if not path.exists():
    print('{}')
else:
    print(path.read_text())
PY
    )"

    if [[ "${state}" == *"\"expected_gateway_mac\": \"${GATEWAY_LAB_MAC,,}\""* ]]; then
      info "Switch-side detector baseline is set to ${GATEWAY_LAB_MAC} (${try}/${attempts})"
      return 0
    fi

    if (( try < attempts )); then
      sleep "${delay}"
    fi
  done

  warn "Switch-side detector baseline did not settle on ${GATEWAY_LAB_MAC}; continuing anyway"
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
    "rm -rf '${remote_root}' && mkdir -p '${remote_root}/python' && chown -R '${LAB_USER}:${LAB_USER}' '${remote_root}'"

  lab_scp_to attacker "${LAB_DIR}/lab.conf" "${remote_root}/lab.conf"
  lab_scp_to attacker "${LAB_DIR}/python/lab" "${remote_root}/python/lab"
  lab_scp_to attacker "${LAB_DIR}/python/mitm" "${remote_root}/python/mitm"

  remote_bash_lc attacker \
    "find '${remote_root}/python' -type f -name '*.py' -exec chmod 0644 {} + && chmod 0644 '${remote_root}/lab.conf'"
  remote_bash_lc attacker "PYTHONPATH='${remote_root}/python' python3 -c 'import mitm.cli, scapy.all'"
}

cleanup_attacker_dns_block_rules() {
  local victim_ip
  victim_ip="$(lab_host_ip victim 2>/dev/null || true)"
  [[ -n "${victim_ip}" ]] || return 0

  remote_sudo_bash_lc attacker \
    "while iptables -D FORWARD -s '${victim_ip}' -d '${GATEWAY_IP}' -p udp --dport 53 -j DROP >/dev/null 2>&1; do :; done
     while iptables -D FORWARD -s '${GATEWAY_IP}' -d '${victim_ip}' -p udp --sport 53 -j DROP >/dev/null 2>&1; do :; done" \
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

should_keep_run_pcaps() {
  case "${PCAP_RETENTION_POLICY}" in
    all)
      return 0
      ;;
    none)
      return 1
      ;;
    first-measured-per-scenario)
      if [[ "${PLAN_WARMUP:-0}" == "1" ]]; then
        return 1
      fi
      if [[ -n "${PLAN_RUN_INDEX:-}" && "${PLAN_RUN_INDEX}" =~ ^[0-9]+$ && "${PLAN_RUN_INDEX}" -eq 1 ]]; then
        return 0
      fi
      return 1
      ;;
    first-run-per-scenario)
      if [[ -n "${PLAN_RUN_INDEX:-}" && "${PLAN_RUN_INDEX}" =~ ^[0-9]+$ && "${PLAN_RUN_INDEX}" -eq 1 ]]; then
        return 0
      fi
      return 1
      ;;
    *)
      warn "Unknown PCAP_RETENTION_POLICY value: ${PCAP_RETENTION_POLICY}; keeping pcaps"
      return 0
      ;;
  esac
}

prune_run_pcaps_for_policy() {
  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  if should_keep_run_pcaps; then
    return 0
  fi

  rm -f \
    "${RUN_DIR}/pcap/attacker.pcap" \
    "${RUN_DIR}/pcap/gateway.pcap" \
    "${RUN_DIR}/pcap/sensor.pcap" \
    "${RUN_DIR}/pcap/victim.pcap" \
    "${RUN_DIR}/pcap/"*.tshark-summary.txt
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

  mkdir -p "${RUN_DIR}/host" "${RUN_DIR}/gateway" "${RUN_DIR}/victim" "${RUN_DIR}/detector" "${RUN_DIR}/attacker" "${RUN_DIR}/pcap"
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
  "pcap_retention_policy": "$(json_escape "${PCAP_RETENTION_POLICY}")",
  "detector_placement": "switch-sensor-port",
  "detector_interface": "${LAB_SWITCH_SENSOR_PORT}",
  "lab_switch_bridge": "${LAB_SWITCH_BRIDGE}",
  "lab_switch_mirror": "${LAB_SWITCH_MIRROR}",
  "gateway_upstream_ip": "$(gateway_upstream_ip)",
  "gateway_lab_ip": "${GATEWAY_IP}",
  "gateway_lab_mac": "${GATEWAY_LAB_MAC}",
  "victim_ip": "$(lab_host_ip victim)",
  "victim_mac": "${VICTIM_MAC}",
  "attacker_ip": "$(lab_host_ip attacker)",
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
  "suricata_arp_rule_mode": "$(json_escape "${SURICATA_ARP_RULE_MODE:-disabled}")",
  "suricata_arp_rule_note": "$(json_escape "${SURICATA_ARP_RULE_NOTE:-}")",
  "notes": "$(json_escape "${notes}")",
  "domains": "$(json_escape "${DETECTOR_DOMAINS}")"
}
EOF
}

capture_remote_command() {
  local host="$1"
  local outfile="$2"
  local cmd="$3"

  mkdir -p "$(dirname "${outfile}")"
  if ! remote_bash_lc "$host" "$cmd" > "${outfile}" 2>&1; then
    warn "Command on ${host} failed; output kept in ${outfile}"
    return 0
  fi
}

capture_remote_command_retry() {
  local host="$1"
  local outfile="$2"
  local cmd="$3"
  local attempts="${4:-3}"
  local delay="${5:-2}"
  local try

  mkdir -p "$(dirname "${outfile}")"
  for ((try = 1; try <= attempts; try++)); do
    if remote_bash_lc "$host" "$cmd" > "${outfile}" 2>&1; then
      return 0
    fi
    if (( try < attempts )); then
      sleep "${delay}"
    fi
  done

  warn "Command on ${host} failed after ${attempts} attempt(s); output kept in ${outfile}"
  return 0
}

capture_local_command() {
  local outfile="$1"
  local cmd="$2"

  mkdir -p "$(dirname "${outfile}")"
  if ! bash -lc "$cmd" > "${outfile}" 2>&1; then
    warn "Local command failed; output kept in ${outfile}"
    return 0
  fi
}

local_file_size() {
  local path="$1"

  if test -f "$path"; then
    wc -c < "$path" | tr -d '[:space:]'
  else
    printf '0\n'
  fi
}

capture_local_delta() {
  local path="$1"
  local offset="$2"
  local outfile="$3"
  local start_byte=$((offset + 1))

  if test -f "$path"; then
    tail -c "+${start_byte}" "$path" > "${outfile}"
  else
    : > "${outfile}"
  fi
}

start_local_capture() {
  local iface="$1"
  local label="$2"
  local count_args=""

  if ! pcap_requested; then
    return 0
  fi

  PCAP_ACTIVE=1

  local local_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  local pcap="${local_base}.pcap"
  local pid_file="${local_base}.pid"
  local log_file="${local_base}.log"

  if [[ "${CAPTURE_PACKET_COUNT}" =~ ^[0-9]+$ ]] && (( CAPTURE_PACKET_COUNT > 0 )); then
    count_args="-c '${CAPTURE_PACKET_COUNT}'"
  fi

  run_root bash -lc "
    for pid in \$(pgrep -x tcpdump 2>/dev/null || true); do
      cmd=\$(ps -p \"\$pid\" -o args= 2>/dev/null || true)
      case \"\$cmd\" in
        *\"-${label}.pcap\"*) kill -INT \"\$pid\" 2>/dev/null || true ;;
      esac
    done
    sleep 1
    rm -f /tmp/*-${label}.pid /tmp/*-${label}.log /tmp/*-${label}.pcap
    rm -f '${pcap}' '${pid_file}' '${log_file}'
    nohup tcpdump -i '${iface}' -nn -s 0 -U ${count_args} -w '${pcap}' >'${log_file}' 2>&1 </dev/null &
    echo \$! > '${pid_file}'
  "

  printf '%s\n' "${pcap}"
}

stop_local_capture() {
  local label="$1"

  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  local local_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  local pid_file="${local_base}.pid"

  run_root bash -lc "
    if test -f '${pid_file}'; then
      pid=\$(cat '${pid_file}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -INT \"\${pid}\" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
          if ! kill -0 \"\${pid}\" 2>/dev/null; then
            break
          fi
          sleep 1
        done
        if kill -0 \"\${pid}\" 2>/dev/null; then
          kill -TERM \"\${pid}\" 2>/dev/null || true
          sleep 1
        fi
        if kill -0 \"\${pid}\" 2>/dev/null; then
          kill -KILL \"\${pid}\" 2>/dev/null || true
        fi
      fi
    fi
  " >/dev/null 2>&1 || true
}

stop_local_detector() {
  local pid_path="/tmp/mitm-lab-detector-host.pid"

  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -INT \"\${pid}\" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
          if ! kill -0 \"\${pid}\" 2>/dev/null; then
            break
          fi
          sleep 1
        done
        if kill -0 \"\${pid}\" 2>/dev/null; then
          kill -TERM \"\${pid}\" 2>/dev/null || true
          sleep 1
        fi
      fi
    fi
  " >/dev/null 2>&1 || true
}

stop_local_zeek() {
  local pid_path="/tmp/mitm-lab-zeek-host/zeek.pid"

  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -TERM \"\${pid}\" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
          if ! kill -0 \"\${pid}\" 2>/dev/null; then
            break
          fi
          sleep 1
        done
        if kill -0 \"\${pid}\" 2>/dev/null; then
          kill -KILL \"\${pid}\" 2>/dev/null || true
        fi
      fi
    fi
  " >/dev/null 2>&1 || true
}

stop_local_suricata() {
  local pid_path="/tmp/mitm-lab-suricata-host/suricata.pid"

  run_root bash -lc "
    if test -f '${pid_path}'; then
      pid=\$(cat '${pid_path}' 2>/dev/null || true)
      if [[ -n \"\${pid}\" ]]; then
        kill -TERM \"\${pid}\" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
          if ! kill -0 \"\${pid}\" 2>/dev/null; then
            break
          fi
          sleep 1
        done
        if kill -0 \"\${pid}\" 2>/dev/null; then
          kill -KILL \"\${pid}\" 2>/dev/null || true
        fi
      fi
    fi
  " >/dev/null 2>&1 || true
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
  local count_args=""

  if ! pcap_requested; then
    return 0
  fi

  PCAP_ACTIVE=1

  local remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  local pcap="${remote_base}.pcap"
  local pid_file="${remote_base}.pid"
  local log_file="${remote_base}.log"

  if [[ "${CAPTURE_PACKET_COUNT}" =~ ^[0-9]+$ ]] && (( CAPTURE_PACKET_COUNT > 0 )); then
    count_args="-c '${CAPTURE_PACKET_COUNT}'"
  fi

  remote_sudo_bash_lc "$host" \
    "for pid in \$(pgrep -x tcpdump 2>/dev/null || true); do cmd=\$(ps -p \"\$pid\" -o args= 2>/dev/null || true); case \"\$cmd\" in *\"-${label}.pcap\"*) kill -INT \"\$pid\" 2>/dev/null || true ;; esac; done; sleep 1; rm -f /tmp/*-${label}.pid /tmp/*-${label}.log /tmp/*-${label}.pcap"
  remote_sudo_bash_lc "$host" \
    "rm -f '${pcap}' '${pid_file}' '${log_file}'; nohup tcpdump -i '${iface}' -nn -s 0 -U ${count_args} -w '${pcap}' >'${log_file}' 2>&1 </dev/null & echo \$! > '${pid_file}'"

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
  local use_sudo="${4:-0}"
  local remote_base pid_file stdout_file stderr_file quoted_cmd

  remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  pid_file="${remote_base}.pid"
  stdout_file="${remote_base}.stdout"
  stderr_file="${remote_base}.stderr"
  printf -v quoted_cmd '%q' "$cmd"

  if [[ "${host}" == "attacker" ]]; then
    remote_sudo_bash_lc "$host" \
      "pkill -f 'python3 -m mitm\\.cli' 2>/dev/null || true; pkill -f 'timeout -s INT .*python3 -m mitm\\.cli' 2>/dev/null || true" \
      >/dev/null 2>&1 || true
    cleanup_attacker_dns_block_rules
  fi

  if [[ "${use_sudo}" == "1" ]]; then
    remote_sudo_bash_lc "$host" \
      "rm -f '${pid_file}' '${stdout_file}' '${stderr_file}'; nohup setsid bash -lc ${quoted_cmd} >'${stdout_file}' 2>'${stderr_file}' </dev/null & echo \$! > '${pid_file}'"
  else
    remote_bash_lc "$host" \
      "rm -f '${pid_file}' '${stdout_file}' '${stderr_file}'; nohup setsid bash -lc ${quoted_cmd} >'${stdout_file}' 2>'${stderr_file}' </dev/null & echo \$! > '${pid_file}'"
  fi
}

stop_remote_background_job() {
  local host="$1"
  local label="$2"
  local use_sudo="${3:-0}"
  local remote_base pid_file

  remote_base="/tmp/${RUN_ID}-${RUN_SLUG}-${label}"
  pid_file="${remote_base}.pid"

  if [[ "${use_sudo}" == "1" ]]; then
    remote_sudo_bash_lc "$host" \
      "if test -f '${pid_file}'; then pid=\$(cat '${pid_file}'); kill -INT -- \"-\$pid\" 2>/dev/null || kill -INT \"\$pid\" 2>/dev/null || true; for _ in 1 2 3 4 5; do if ! kill -0 \"\$pid\" 2>/dev/null; then break; fi; sleep 1; done; if kill -0 \"\$pid\" 2>/dev/null; then kill -TERM -- \"-\$pid\" 2>/dev/null || kill -TERM \"\$pid\" 2>/dev/null || true; sleep 1; fi; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL -- \"-\$pid\" 2>/dev/null || kill -KILL \"\$pid\" 2>/dev/null || true; fi; fi" \
      >/dev/null 2>&1 || true
  else
    remote_bash_lc "$host" \
      "if test -f '${pid_file}'; then pid=\$(cat '${pid_file}'); kill -INT -- \"-\$pid\" 2>/dev/null || kill -INT \"\$pid\" 2>/dev/null || true; for _ in 1 2 3 4 5; do if ! kill -0 \"\$pid\" 2>/dev/null; then break; fi; sleep 1; done; if kill -0 \"\$pid\" 2>/dev/null; then kill -TERM -- \"-\$pid\" 2>/dev/null || kill -TERM \"\$pid\" 2>/dev/null || true; sleep 1; fi; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL -- \"-\$pid\" 2>/dev/null || kill -KILL \"\$pid\" 2>/dev/null || true; fi; fi" \
      >/dev/null 2>&1 || true
  fi

  if [[ "${host}" == "attacker" ]]; then
    remote_sudo_bash_lc "$host" \
      "pkill -f 'python3 -m mitm\\.cli' 2>/dev/null || true; pkill -f 'timeout -s INT .*python3 -m mitm\\.cli' 2>/dev/null || true" \
      >/dev/null 2>&1 || true
    cleanup_attacker_dns_block_rules
  fi
}

save_common_state() {
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-route.txt" "ip route show"
  capture_remote_command gateway "${RUN_DIR}/gateway/ip-neigh.txt" "ip neigh show"
  capture_remote_command gateway "${RUN_DIR}/gateway/dnsmasq-service.txt" "systemctl status dnsmasq --no-pager || true"
  capture_local_command "${RUN_DIR}/detector/status.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo 'detector_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'detector_log=/tmp/mitm-lab-detector-host.jsonl'
    echo 'detector_state=/tmp/mitm-lab-detector-host-state.json'
    echo 'switch_truth_pcap=/tmp/${RUN_ID}-${RUN_SLUG}-sensor.pcap'
    echo
    if test -f /tmp/mitm-lab-detector-host.pid; then
      pid=\$(cat /tmp/mitm-lab-detector-host.pid 2>/dev/null || true)
      echo 'pid='\"\${pid}\"
      ps -p \"\${pid}\" -o pid=,etime=,args= 2>/dev/null || true
    else
      echo 'pid=missing'
    fi
    echo
    ovs-vsctl show 2>/dev/null || true
  "
  capture_local_command "${RUN_DIR}/zeek/status-runtime.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo 'sensor_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'runtime_root=/tmp/mitm-lab-zeek-host'
    echo 'log_dir=/tmp/mitm-lab-zeek-host/current'
    echo
    if test -f /tmp/mitm-lab-zeek-host/zeek.pid; then
      pid=\$(cat /tmp/mitm-lab-zeek-host/zeek.pid 2>/dev/null || true)
      echo 'pid='\"\${pid}\"
      ps -p \"\${pid}\" -o pid=,etime=,args= 2>/dev/null || true
    else
      echo 'pid=missing'
    fi
  "
  capture_local_command "${RUN_DIR}/suricata/status-runtime.txt" "
    echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    echo 'sensor_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'runtime_root=/tmp/mitm-lab-suricata-host'
    echo 'log_dir=/tmp/mitm-lab-suricata-host/current'
    echo 'arp_rule_enabled=${SURICATA_ARP_RULE_ACTIVE:-0}'
    echo
    if test -f /tmp/mitm-lab-suricata-host/suricata.pid; then
      pid=\$(cat /tmp/mitm-lab-suricata-host/suricata.pid 2>/dev/null || true)
      echo 'pid='\"\${pid}\"
      ps -p \"\${pid}\" -o pid=,etime=,args= 2>/dev/null || true
    else
      echo 'pid=missing'
    fi
  "
  capture_remote_command victim "${RUN_DIR}/victim/ip-route.txt" "ip route show"
  capture_remote_command victim "${RUN_DIR}/victim/ip-neigh.txt" "ip neigh show"
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
    ovs-vsctl --version 2>/dev/null | sed -n '1p' || true
    qemu-system-x86_64 --version 2>/dev/null | sed -n '1p' || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    zeek --version 2>/dev/null | sed -n '1p' || true
    suricata --build-info 2>/dev/null | sed -n '1,4p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    python3 -c 'import scapy; print(\"scapy=\" + scapy.__version__)' 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst \
      tshark tcpdump python3 python3-scapy curl jq dnsutils openvswitch-switch zeek suricata 2>/dev/null || true
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

  capture_local_delta "/tmp/${RUN_ID}-${RUN_SLUG}-sensor.pcap" 0 "${RUN_DIR}/pcap/sensor.pcap"
  if guest_pcaps_requested; then
    fetch_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-gateway.pcap" "${RUN_DIR}/pcap/gateway.pcap" || true
    fetch_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-victim.pcap" "${RUN_DIR}/pcap/victim.pcap" || true
    fetch_remote_file attacker "/tmp/${RUN_ID}-${RUN_SLUG}-attacker.pcap" "${RUN_DIR}/pcap/attacker.pcap" || true
  fi
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

  if ! pcap_summaries_requested; then
    return 0
  fi

  while IFS= read -r -d '' pcap_path; do
    write_tshark_summary "${pcap_path}"
  done < <(find "${RUN_DIR}/pcap" -maxdepth 1 -type f -name '*.pcap' -print0 | sort -z)
}

materialize_wire_truth_summary() {
  if [[ "${PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  if [[ ! -s "${RUN_DIR}/pcap/sensor.pcap" && ! -s "${RUN_DIR}/pcap/victim.pcap" ]]; then
    return 0
  fi

  lab_python_module metrics.wire_truth_cli "${RUN_DIR}" \
    --out "${RUN_DIR}/pcap/wire-truth.json" >/dev/null 2>&1 || true
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
  local outdir notice_path summary_path runtime_root

  if ! zeek_requested; then
    write_zeek_status "zeek_status=skipped"
    return 0
  fi

  if [[ "${ZEEK_ACTIVE:-0}" != "1" ]]; then
    write_zeek_status "zeek_status=prepare_failed"
    return 0
  fi

  outdir="${RUN_DIR}/zeek/host"
  notice_path="${outdir}/notice.log"
  summary_path="${outdir}/summary.txt"
  runtime_root="/tmp/mitm-lab-zeek-host"
  mkdir -p "${outdir}"

  if [[ -f "${RUN_DIR}/zeek/status-runtime.txt" ]]; then
    cp "${RUN_DIR}/zeek/status-runtime.txt" "${outdir}/runtime-status.txt" 2>/dev/null || true
  fi

  [[ -f "${runtime_root}/current/notice.log" ]] && cp "${runtime_root}/current/notice.log" "${notice_path}" 2>/dev/null || true

  if [[ -f "${runtime_root}/zeek.stdout" ]]; then
    cp "${runtime_root}/zeek.stdout" "${outdir}/zeek.stdout" 2>/dev/null || true
  fi
  if [[ -f "${runtime_root}/zeek.stderr" ]]; then
    cp "${runtime_root}/zeek.stderr" "${outdir}/zeek.stderr" 2>/dev/null || true
  fi

  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    if [[ -f "${runtime_root}/current/reporter.log" ]]; then
      cp "${runtime_root}/current/reporter.log" "${outdir}/reporter.log" 2>/dev/null || true
    fi
    if [[ -f "${runtime_root}/current/loaded_scripts.log" ]]; then
      cp "${runtime_root}/current/loaded_scripts.log" "${outdir}/loaded_scripts.log" 2>/dev/null || true
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
  local outdir eve_path summary_path runtime_root

  if ! suricata_requested; then
    write_suricata_status "suricata_status=skipped"
    return 0
  fi

  if [[ "${SURICATA_ACTIVE:-0}" != "1" ]]; then
    write_suricata_status "suricata_status=prepare_failed"
    return 0
  fi

  outdir="${RUN_DIR}/suricata/host"
  eve_path="${outdir}/eve.json"
  summary_path="${outdir}/summary.txt"
  runtime_root="/tmp/mitm-lab-suricata-host"
  mkdir -p "${outdir}"

  if [[ -f "${RUN_DIR}/suricata/status-runtime.txt" ]]; then
    cp "${RUN_DIR}/suricata/status-runtime.txt" "${outdir}/runtime-status.txt" 2>/dev/null || true
  fi

  [[ -f "${runtime_root}/current/eve.json" ]] && cp "${runtime_root}/current/eve.json" "${eve_path}" 2>/dev/null || true

  if [[ -f "${runtime_root}/suricata.stdout" ]]; then
    cp "${runtime_root}/suricata.stdout" "${outdir}/suricata.stdout" 2>/dev/null || true
  fi
  if [[ -f "${runtime_root}/suricata.stderr" ]]; then
    cp "${runtime_root}/suricata.stderr" "${outdir}/suricata.stderr" 2>/dev/null || true
  fi

  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    if [[ -f "${runtime_root}/current/fast.log" ]]; then
      cp "${runtime_root}/current/fast.log" "${outdir}/fast.log" 2>/dev/null || true
    fi
    if [[ -f "${runtime_root}/current/suricata.log" ]]; then
      cp "${runtime_root}/current/suricata.log" "${outdir}/suricata.log" 2>/dev/null || true
    fi
    if [[ -f "${runtime_root}/current/stats.log" ]]; then
      cp "${runtime_root}/current/stats.log" "${outdir}/stats.log" 2>/dev/null || true
    fi
    if [[ -f "/tmp/mitm-lab-suricata-test.log" ]]; then
      cp "/tmp/mitm-lab-suricata-test.log" "${outdir}/suricata-test.log" 2>/dev/null || true
    fi
    if [[ -f "/tmp/mitm-lab-suricata-test-arp.log" ]]; then
      cp "/tmp/mitm-lab-suricata-test-arp.log" "${outdir}/suricata-test-arp.log" 2>/dev/null || true
    fi
    if [[ -f "/tmp/mitm-lab-suricata-test-ether.log" ]]; then
      cp "/tmp/mitm-lab-suricata-test-ether.log" "${outdir}/suricata-test-ether.log" 2>/dev/null || true
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
  prune_run_pcaps_for_policy

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
    "${RUN_DIR}/detector/status.txt" \
    "${RUN_DIR}/victim/ip-route.txt" \
    "${RUN_DIR}/victim/ip-neigh.txt" \
    "${RUN_DIR}/victim/ip-neigh-after.txt" \
    "${RUN_DIR}/detector/detector.state.json" \
    "${RUN_DIR}/victim/post-window-probe.txt" \
    "${RUN_DIR}/victim/versions.txt" \
    "${RUN_DIR}/attacker/ip-route.txt" \
    "${RUN_DIR}/attacker/ip-neigh.txt" \
    "${RUN_DIR}/attacker/ip-neigh-after.txt" \
    "${RUN_DIR}/attacker/versions.txt" \
    "${RUN_DIR}/attacker/"*.command.txt \
    "${RUN_DIR}/attacker/"*.stdout \
    "${RUN_DIR}/attacker/"*.stderr \
    "${RUN_DIR}/zeek/status-runtime.txt" \
    "${RUN_DIR}/zeek/host/runtime-status.txt" \
    "${RUN_DIR}/zeek/host/zeek.stdout" \
    "${RUN_DIR}/zeek/host/zeek.stderr" \
    "${RUN_DIR}/suricata/status-runtime.txt" \
    "${RUN_DIR}/suricata/host/runtime-status.txt" \
    "${RUN_DIR}/suricata/host/suricata.stdout" \
    "${RUN_DIR}/suricata/host/suricata.stderr" \
    "${RUN_DIR}/suricata/host/suricata-test.log"
}

explain_saved_run() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m logs.explain_run "${RUN_DIR}" > "${RUN_DIR}/detector/detector-explained.txt" 2>&1 || true
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
