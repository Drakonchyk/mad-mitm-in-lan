#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-0}"
PCAP_RETENTION_POLICY="${PCAP_RETENTION_POLICY:-all}"
PCAP_ENABLE="${PCAP_ENABLE:-0}"
PORT_PCAP_ENABLE="${PORT_PCAP_ENABLE:-0}"
PORT_PCAP_ROLES="${PORT_PCAP_ROLES:-gateway victim attacker}"
GUEST_PCAP_ENABLE="${GUEST_PCAP_ENABLE:-0}"
PCAP_SUMMARIES_ENABLE="${PCAP_SUMMARIES_ENABLE:-0}"
ZEEK_ENABLE="${ZEEK_ENABLE:-1}"
SURICATA_ENABLE="${SURICATA_ENABLE:-1}"
DETECTOR_PACKET_SAMPLE_RATE="${DETECTOR_PACKET_SAMPLE_RATE:-1}"
RELIABILITY_NETEM_LOSS_PERCENT="${RELIABILITY_NETEM_LOSS_PERCENT:-0}"
RELIABILITY_NETEM_DELAY_MS="${RELIABILITY_NETEM_DELAY_MS:-0}"
RELIABILITY_NETEM_JITTER_MS="${RELIABILITY_NETEM_JITTER_MS:-0}"
RELIABILITY_NETEM_RATE="${RELIABILITY_NETEM_RATE:-}"
RELIABILITY_NETEM_DUPLICATE_PERCENT="${RELIABILITY_NETEM_DUPLICATE_PERCENT:-0}"
RELIABILITY_NETEM_REORDER_PERCENT="${RELIABILITY_NETEM_REORDER_PERCENT:-0}"
RELIABILITY_NETEM_CORRUPT_PERCENT="${RELIABILITY_NETEM_CORRUPT_PERCENT:-0}"
RELIABILITY_TX_IFACE="${RELIABILITY_TX_IFACE:-mitm-rel-tx}"
RELIABILITY_RX_IFACE="${RELIABILITY_RX_IFACE:-mitm-rel-rx}"
DETECTOR_HEARTBEAT_SECONDS="${DETECTOR_HEARTBEAT_SECONDS:-10}"
KEEP_DEBUG_ARTIFACTS="${KEEP_DEBUG_ARTIFACTS:-0}"
MIN_FREE_MB_FOR_PCAPS="${MIN_FREE_MB_FOR_PCAPS:-2048}"
STALE_CAPTURE_CLEANUP_ENABLE="${STALE_CAPTURE_CLEANUP_ENABLE:-1}"
ZEEK_ACTIVE=0
SURICATA_ACTIVE=0
SURICATA_ARP_RULE_ACTIVE=0
SURICATA_ARP_RULE_MODE="disabled"
SURICATA_ARP_RULE_NOTE=""
PCAP_ACTIVE=0
PORT_PCAP_ACTIVE=0
PORT_PCAP_CAPTURE_ROLES=()
PORT_PCAP_CAPTURE_LABELS=()
PORT_PCAP_CAPTURE_IFACES=()
RELIABILITY_NETEM_ACTIVE=0
EFFECTIVE_SENSOR_PORT="${LAB_SWITCH_SENSOR_PORT}"

lab_python_module() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m "$@"
}

run_root_host_bash_lc() {
  local script="$1"
  local unit

  if [[ $(id -u) -eq 0 ]]; then
    bash -lc "${script}"
    return
  fi

  if [[ "${MITM_LAB_ROOT_VIA_SYSTEMD_RUN:-1}" == "1" ]] && command -v systemd-run >/dev/null 2>&1; then
    unit="mitm-lab-root-${$}-${RANDOM}"
    if sudo systemd-run --wait --pipe --collect --quiet --unit="${unit}" /bin/bash -lc "${script}"; then
      return
    fi
  fi

  sudo bash -lc "${script}"
}

host_python_with_scapy() {
  local candidates=()
  local candidate resolved seen
  local -A tried=()

  if [[ -n "${MITM_LAB_HOST_PYTHON:-}" ]]; then
    candidates+=("${MITM_LAB_HOST_PYTHON}")
  fi
  candidates+=(/usr/bin/python3 python3 python)

  for candidate in "${candidates[@]}"; do
    [[ -n "${candidate}" ]] || continue
    if ! resolved="$(command -v "${candidate}" 2>/dev/null)"; then
      continue
    fi
    seen="${resolved}"
    if [[ -n "${tried[${seen}]:-}" ]]; then
      continue
    fi
    tried["${seen}"]=1
    if "${resolved}" -c 'import scapy.all' >/dev/null 2>&1; then
      printf '%s\n' "${resolved}"
      return 0
    fi
  done

  return 1
}

percent_value() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    warn "Invalid ${name}=${value}; using 0"
    printf '0\n'
    return 0
  fi
  if (( value < 0 )); then
    value=0
  elif (( value > 100 )); then
    value=100
  fi
  printf '%s\n' "${value}"
}

nonnegative_int_value() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    warn "Invalid ${name}=${value}; using 0"
    printf '0\n'
    return 0
  fi
  printf '%s\n' "${value}"
}

reliability_netem_requested() {
  local loss duplicate reorder corrupt delay jitter
  loss="$(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}")"
  duplicate="$(percent_value RELIABILITY_NETEM_DUPLICATE_PERCENT "${RELIABILITY_NETEM_DUPLICATE_PERCENT}")"
  reorder="$(percent_value RELIABILITY_NETEM_REORDER_PERCENT "${RELIABILITY_NETEM_REORDER_PERCENT}")"
  corrupt="$(percent_value RELIABILITY_NETEM_CORRUPT_PERCENT "${RELIABILITY_NETEM_CORRUPT_PERCENT}")"
  delay="$(nonnegative_int_value RELIABILITY_NETEM_DELAY_MS "${RELIABILITY_NETEM_DELAY_MS}")"
  jitter="$(nonnegative_int_value RELIABILITY_NETEM_JITTER_MS "${RELIABILITY_NETEM_JITTER_MS}")"
  (( loss > 0 || duplicate > 0 || reorder > 0 || corrupt > 0 || delay > 0 || jitter > 0 || ${#RELIABILITY_NETEM_RATE} > 0 ))
}

require_experiment_tools() {
  require_cmd ssh
  require_cmd scp
  require_cmd python3
  cleanup_stale_lab_capture_processes
  guard_low_disk_pcap_defaults
  if reliability_netem_requested; then
    require_cmd tc
    require_cmd ovs-vsctl
    require_cmd ip
  fi
  if pcap_requested; then
    require_cmd tshark
  fi
}

cleanup_stale_lab_capture_processes() {
  local stopped

  if [[ "${STALE_CAPTURE_CLEANUP_ENABLE}" != "1" ]]; then
    return 0
  fi

  stopped="$(
    run_root_host_bash_lc '
      count=0
      stop_matches() {
        local signal="$1"
        for pid in $(pgrep -x tcpdump 2>/dev/null || true); do
          cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
          case "$cmd" in
            *" -w /tmp/20"*.pcap*)
              kill -"${signal}" "$pid" 2>/dev/null || true
              if [[ "${signal}" == "INT" ]]; then
                count=$((count + 1))
              fi
              ;;
          esac
        done
      }

      stop_matches INT
      sleep 1
      stop_matches TERM
      sleep 1
      stop_matches KILL
      rm -f /tmp/20*.pcap /tmp/20*.pid /tmp/20*.log 2>/dev/null || true
      printf "%s\n" "${count}"
    ' 2>/dev/null || true
  )"

  if [[ "${stopped}" =~ ^[0-9]+$ ]] && (( stopped > 0 )); then
    info "Stopped ${stopped} stale host tcpdump capture process(es)"
  fi
}

cleanup_stale_remote_lab_capture_processes() {
  local host stopped total=0

  if [[ "${STALE_CAPTURE_CLEANUP_ENABLE}" != "1" ]]; then
    return 0
  fi

  for host in gateway victim attacker; do
    stopped="$(
      remote_sudo_bash_lc "${host}" '
        count=0
        stop_matches() {
          local signal="$1"
          for pid in $(pgrep -x tcpdump 2>/dev/null || true); do
            cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
            case "$cmd" in
              *" -w /tmp/20"*.pcap*)
                kill -"${signal}" "$pid" 2>/dev/null || true
                if [[ "${signal}" == "INT" ]]; then
                  count=$((count + 1))
                fi
                ;;
            esac
          done
        }

        stop_matches INT
        sleep 1
        stop_matches TERM
        sleep 1
        stop_matches KILL
        rm -f /tmp/20*.pcap /tmp/20*.pid /tmp/20*.log 2>/dev/null || true
        printf "%s\n" "${count}"
      ' 2>/dev/null || true
    )"
    if [[ "${stopped}" =~ ^[0-9]+$ ]]; then
      total=$((total + stopped))
    fi
  done

  if (( total > 0 )); then
    info "Stopped ${total} stale guest tcpdump capture process(es)"
  fi
}

guard_low_disk_pcap_defaults() {
  local available_kb available_mb

  pcap_requested || return 0
  available_kb="$(df -Pk "$(results_root)" 2>/dev/null | awk 'NR==2 {print $4}')"
  if ! [[ "${available_kb}" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  available_mb=$((available_kb / 1024))
  if (( available_mb < MIN_FREE_MB_FOR_PCAPS )) && [[ "${ALLOW_LOW_DISK_PCAPS:-0}" != "1" ]]; then
    warn "Only ${available_mb} MiB free under results; disabling pcaps for this run. Set ALLOW_LOW_DISK_PCAPS=1 to force captures."
    PCAP_ENABLE=0
    PORT_PCAP_ENABLE=0
    GUEST_PCAP_ENABLE=0
    PCAP_SUMMARIES_ENABLE=0
    PCAP_RETENTION_POLICY=none
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

port_pcaps_requested() {
  pcap_requested || return 1
  case "${PORT_PCAP_ENABLE}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      warn "Unknown PORT_PCAP_ENABLE value: ${PORT_PCAP_ENABLE}; disabling per-port pcaps"
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
alert udp !${gateway_ip} 67 -> any 68 (msg:"MITM-LAB live rogue DHCP reply from non-gateway server"; content:"|63 82 53 63|"; offset:236; depth:4; classtype:bad-unknown; sid:9901003; rev:2;)
EOF
  } > "${outfile}"
}

prepare_victim_detector() {
  local rendered_detector
  local detector_path log_path state_path pid_path stdout_path stderr_path host_python
  local detector_ovs_dhcp_bridge detector_ovs_dhcp_mode
  rendered_detector="$(mktemp)"
  render_victim_detector "${rendered_detector}"
  detector_path="/tmp/mitm-lab-detector-host.py"
  log_path="/tmp/mitm-lab-detector-host.jsonl"
  state_path="/tmp/mitm-lab-detector-host-state.json"
  pid_path="/tmp/mitm-lab-detector-host.pid"
  stdout_path="/tmp/mitm-lab-detector-host.stdout"
  stderr_path="/tmp/mitm-lab-detector-host.stderr"
  detector_ovs_dhcp_bridge="${LAB_SWITCH_BRIDGE}"
  detector_ovs_dhcp_mode="$(dhcp_snooping_mode)"
  if [[ "${DETECTOR_OVS_DHCP_SNOOPING_ENABLE:-1}" != "1" ]]; then
    detector_ovs_dhcp_bridge=""
    detector_ovs_dhcp_mode="off"
  fi

  if ! host_python="$(host_python_with_scapy)"; then
    rm -f "${rendered_detector}"
    warn "A host Python with Scapy is required for the host-side detector (tried MITM_LAB_HOST_PYTHON, /usr/bin/python3, python3, python)"
    return 1
  fi

  info "Starting detector on sensor interface ${EFFECTIVE_SENSOR_PORT} with ${host_python}"
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
      MITM_LAB_INTERFACE='${EFFECTIVE_SENSOR_PORT}' \
      MITM_LAB_LOG_PATH='${log_path}' \
      MITM_LAB_STATE_PATH='${state_path}' \
      MITM_LAB_EXPECTED_GATEWAY_MAC='${GATEWAY_LAB_MAC,,}' \
      MITM_LAB_EXPECTED_DHCP_SERVER='${GATEWAY_IP}' \
      MITM_LAB_EXPECTED_DHCP_SERVER_MAC='${GATEWAY_LAB_MAC,,}' \
      MITM_LAB_VICTIM_MAC='${VICTIM_MAC,,}' \
      MITM_LAB_ATTACKER_MAC='${ATTACKER_MAC,,}' \
      MITM_LAB_PACKET_SAMPLE_RATE='${DETECTOR_PACKET_SAMPLE_RATE}' \
      MITM_LAB_HEARTBEAT_SECONDS='${DETECTOR_HEARTBEAT_SECONDS}' \
      MITM_LAB_OVS_DHCP_SNOOPING_BRIDGE='${detector_ovs_dhcp_bridge}' \
      MITM_LAB_OVS_DHCP_SNOOPING_MODE='${detector_ovs_dhcp_mode}' \
      MITM_LAB_OVS_DHCP_SNOOPING_POLL_SECONDS='${OVS_DHCP_SNOOPING_POLL_SECONDS:-2}' \
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

  info "Starting live Zeek comparison sensor on ${EFFECTIVE_SENSOR_PORT}"
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
    nohup '${zeek_bin}' -C -i '${EFFECTIVE_SENSOR_PORT}' 'Log::default_logdir=${log_dir}' '${policy_path}' >'${stdout_path}' 2>'${stderr_path}' </dev/null &
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

  info "Starting live Suricata comparison sensor on ${EFFECTIVE_SENSOR_PORT}"
  run_root bash -lc "
    nohup '${suricata_bin}' -i '${EFFECTIVE_SENSOR_PORT}' -l '${log_dir}' -c '/etc/suricata/suricata.yaml' ${suricata_start_opts} -S '${rules_path}' >'${stdout_path}' 2>'${stderr_path}' </dev/null &
    echo \$! > '${pid_path}'
  "

  if run_root bash -lc "pid=\$(cat '${pid_path}' 2>/dev/null || true); [[ -n \"\${pid}\" ]] && kill -0 \"\${pid}\" 2>/dev/null"; then
    SURICATA_ACTIVE=1
  else
    warn "Host Suricata process did not stay up; continuing without Suricata comparison for this run"
  fi

  rm -f "${rendered_rules}"
}

reliability_netem_args() {
  local loss duplicate reorder corrupt delay jitter args
  loss="$(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}")"
  duplicate="$(percent_value RELIABILITY_NETEM_DUPLICATE_PERCENT "${RELIABILITY_NETEM_DUPLICATE_PERCENT}")"
  reorder="$(percent_value RELIABILITY_NETEM_REORDER_PERCENT "${RELIABILITY_NETEM_REORDER_PERCENT}")"
  corrupt="$(percent_value RELIABILITY_NETEM_CORRUPT_PERCENT "${RELIABILITY_NETEM_CORRUPT_PERCENT}")"
  delay="$(nonnegative_int_value RELIABILITY_NETEM_DELAY_MS "${RELIABILITY_NETEM_DELAY_MS}")"
  jitter="$(nonnegative_int_value RELIABILITY_NETEM_JITTER_MS "${RELIABILITY_NETEM_JITTER_MS}")"
  args=()
  if (( delay > 0 || jitter > 0 )); then
    args+=("delay" "${delay}ms")
    if (( jitter > 0 )); then
      args+=("${jitter}ms")
    fi
  fi
  if (( loss > 0 )); then
    args+=("loss" "${loss}%")
  fi
  if (( duplicate > 0 )); then
    args+=("duplicate" "${duplicate}%")
  fi
  if (( reorder > 0 )); then
    args+=("reorder" "${reorder}%")
  fi
  if (( corrupt > 0 )); then
    args+=("corrupt" "${corrupt}%")
  fi
  if [[ -n "${RELIABILITY_NETEM_RATE}" ]]; then
    args+=("rate" "${RELIABILITY_NETEM_RATE}")
  fi
  printf '%q ' "${args[@]}"
}

prepare_reliability_netem() {
  local netem_args

  EFFECTIVE_SENSOR_PORT="${LAB_SWITCH_SENSOR_PORT}"
  RELIABILITY_NETEM_ACTIVE=0

  if ! reliability_netem_requested; then
    return 0
  fi

  netem_args="$(reliability_netem_args)"
  info "Starting reliability netem path: ${LAB_SWITCH_SENSOR_PORT} mirror -> ${RELIABILITY_TX_IFACE} -> ${RELIABILITY_RX_IFACE} (${netem_args:-no impairment})"
  run_root bash -lc "
    set -euo pipefail
    ovs-vsctl --if-exists del-port '${LAB_SWITCH_BRIDGE}' '${RELIABILITY_TX_IFACE}' || true
    ip link del '${RELIABILITY_TX_IFACE}' 2>/dev/null || true
    ip link add '${RELIABILITY_TX_IFACE}' type veth peer name '${RELIABILITY_RX_IFACE}'
    ip link set '${RELIABILITY_TX_IFACE}' up
    ip link set '${RELIABILITY_RX_IFACE}' up
    ip link set '${RELIABILITY_TX_IFACE}' promisc on
    ip link set '${RELIABILITY_RX_IFACE}' promisc on
    ovs-vsctl add-port '${LAB_SWITCH_BRIDGE}' '${RELIABILITY_TX_IFACE}'
    tc qdisc replace dev '${RELIABILITY_TX_IFACE}' root netem ${netem_args}
    ovs-vsctl -- --id=@out get Port '${RELIABILITY_TX_IFACE}' -- set Mirror '${LAB_SWITCH_MIRROR}' output-port=@out
  "

  EFFECTIVE_SENSOR_PORT="${RELIABILITY_RX_IFACE}"
  RELIABILITY_NETEM_ACTIVE=1
}

stop_reliability_netem() {
  if [[ "${RELIABILITY_NETEM_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  run_root bash -lc "
    set +e
    ovs-vsctl -- --id=@sensor get Port '${LAB_SWITCH_SENSOR_PORT}' -- set Mirror '${LAB_SWITCH_MIRROR}' output-port=@sensor
    tc qdisc del dev '${RELIABILITY_TX_IFACE}' root 2>/dev/null
    ovs-vsctl --if-exists del-port '${LAB_SWITCH_BRIDGE}' '${RELIABILITY_TX_IFACE}'
    ip link del '${RELIABILITY_TX_IFACE}' 2>/dev/null
  " >/dev/null 2>&1 || true
}

capture_reliability_netem_stats() {
  capture_local_command "${RUN_DIR}/detector/reliability-netem.txt" "
    {
      echo '== qdisc ${RELIABILITY_TX_IFACE} =='
      tc -s qdisc show dev '${RELIABILITY_TX_IFACE}' 2>/dev/null || true
      echo '== link ${RELIABILITY_TX_IFACE} =='
      ip -s link show dev '${RELIABILITY_TX_IFACE}' 2>/dev/null || true
      echo '== link ${RELIABILITY_RX_IFACE} =='
      ip -s link show dev '${RELIABILITY_RX_IFACE}' 2>/dev/null || true
    }
  "
}

capture_ovs_dhcp_snooping_stats() {
  local mode
  mode="$(dhcp_snooping_mode)"

  capture_local_command "${RUN_DIR}/detector/ovs-dhcp-snooping.txt" "
    {
      echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
      echo 'mode=${mode}'
      echo 'legacy_enforce=${LAB_DHCP_SNOOPING_ENFORCE:-0}'
      echo 'bridge=${LAB_SWITCH_BRIDGE}'
      echo 'trusted_gateway_ip=${GATEWAY_IP}'
      echo 'trusted_gateway_mac=${GATEWAY_LAB_MAC,,}'
      echo
      echo '== bridge external_ids =='
      sudo -n ovs-vsctl get Bridge '${LAB_SWITCH_BRIDGE}' external_ids 2>/dev/null || ovs-vsctl get Bridge '${LAB_SWITCH_BRIDGE}' external_ids 2>/dev/null || true
      echo
      echo '== lab port roles =='
      sudo -n ovs-vsctl --columns=name,external_ids list Port 2>/dev/null || ovs-vsctl --columns=name,external_ids list Port 2>/dev/null || true
      echo
      echo '== interface ofports =='
      sudo -n ovs-vsctl --columns=name,ofport list Interface 2>/dev/null || ovs-vsctl --columns=name,ofport list Interface 2>/dev/null || true
      echo
      echo '== DHCP snooping flows =='
      sudo -n ovs-ofctl dump-flows '${LAB_SWITCH_BRIDGE}' 'cookie=0x4d49544d/-1' 2>/dev/null || ovs-ofctl dump-flows '${LAB_SWITCH_BRIDGE}' 'cookie=0x4d49544d/-1' 2>/dev/null || true
    }
  "
}

capture_ovs_switch_truth_snooping_stats() {
  capture_local_command "${RUN_DIR}/detector/ovs-switch-truth-snooping.txt" "
    {
      echo 'generated_at='\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
      echo 'enabled=${LAB_SWITCH_TRUTH_SNOOPING:-1}'
      echo 'bridge=${LAB_SWITCH_BRIDGE}'
      echo 'trusted_gateway_ip=${GATEWAY_IP}'
      echo 'trusted_gateway_mac=${GATEWAY_LAB_MAC,,}'
      echo 'trusted_dns_ip=${DNS_SERVER}'
      echo
      echo '== lab port roles =='
      sudo -n ovs-vsctl --columns=name,external_ids list Port 2>/dev/null || ovs-vsctl --columns=name,external_ids list Port 2>/dev/null || true
      echo
      echo '== interface ofports =='
      sudo -n ovs-vsctl --columns=name,ofport list Interface 2>/dev/null || ovs-vsctl --columns=name,ofport list Interface 2>/dev/null || true
      echo
      echo '== switch truth snooping flows =='
      sudo -n ovs-ofctl dump-flows '${LAB_SWITCH_BRIDGE}' 'cookie=0x4d49544e/-1' 2>/dev/null || ovs-ofctl dump-flows '${LAB_SWITCH_BRIDGE}' 'cookie=0x4d49544e/-1' 2>/dev/null || true
    }
  "
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
    all|keep)
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
      if find "$(results_root)" -maxdepth 3 \
        -path "${RUN_DIR}" -prune -o \
        -type f \( \
          -path "*-${RUN_BASE_SLUG:-${RUN_SLUG}}/pcap/sensor.pcap" -o \
          -path "*-${RUN_BASE_SLUG:-${RUN_SLUG}}-param-*/pcap/sensor.pcap" \
        \) -print -quit \
        | grep -q .; then
        return 1
      fi
      return 0
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
	    "${RUN_DIR}/pcap/"*.tshark-summary.txt \
	    "${RUN_DIR}/pcap/ports/"*.pcap \
	    "${RUN_DIR}/pcap/ports/"*.tshark-summary.txt
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
  local run_id base_slug slug suffix

  run_id="$(date -u +%Y%m%dT%H%M%SZ)"
  base_slug="$(scenario_slug "$scenario")"
  suffix="$(scenario_slug "${RUN_SLUG_SUFFIX:-}")"
  slug="${base_slug}"
  if [[ -n "${suffix}" ]]; then
    slug="${slug}-${suffix}"
  fi

  RUN_ID="${run_id}"
  RUN_SCENARIO="${scenario}"
  RUN_BASE_SLUG="${base_slug}"
  RUN_SLUG="${slug}"
  RUN_DIR="$(results_root)/${RUN_ID}-${RUN_SLUG}"
  PCAP_ACTIVE=0

  mkdir -p "${RUN_DIR}/host" "${RUN_DIR}/gateway" "${RUN_DIR}/victim" "${RUN_DIR}/detector" "${RUN_DIR}/attacker" "${RUN_DIR}/pcap" "${RUN_DIR}/pcap/ports"
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
  cleanup_stale_remote_lab_capture_processes
}

refresh_switch_counters_for_run() {
  "${LAB_DIR}/shell/lab/start-lab.sh" >/dev/null
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
  local run_index_json warmup_json duration_json attack_start_json attack_stop_json mitigation_start_json forwarding_json dns_spoof_json spoofed_domains_json port_pcap_roles_json overload_sources_json
  local dhcp_snooping_mode_value dhcp_snooping_enforced_json

  run_index_json="$(json_number_or_null "${PLAN_RUN_INDEX:-}")"
  warmup_json="$(json_bool "${PLAN_WARMUP:-0}")"
  duration_json="$(json_number_or_null "${PLAN_DURATION_SECONDS:-}")"
  attack_start_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_ATTACK_START_OFFSET_SECONDS:-}")"
  attack_stop_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_ATTACK_STOP_OFFSET_SECONDS:-}")"
  mitigation_start_json="$(timestamp_at_offset_or_null "${started_at}" "${PLAN_MITIGATION_START_OFFSET_SECONDS:-}")"
  forwarding_json="$(json_bool "${PLAN_FORWARDING_ENABLED:-0}")"
  dns_spoof_json="$(json_bool "${PLAN_DNS_SPOOF_ENABLED:-0}")"
  spoofed_domains_json="$(json_string_array_from_words "${PLAN_SPOOFED_DOMAINS:-}")"
  port_pcap_roles_json="$(json_string_array_from_words "${PORT_PCAP_ROLES}")"
  overload_sources_json="$(json_string_array_from_words "${OVERLOAD_SOURCES:-}")"
  dhcp_snooping_mode_value="$(dhcp_snooping_mode)"
  if [[ "${dhcp_snooping_mode_value}" == "enforce" ]]; then
    dhcp_snooping_enforced_json="true"
  else
    dhcp_snooping_enforced_json="false"
  fi

  cat > "${RUN_DIR}/run-meta.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "scenario": "${RUN_SCENARIO}",
  "mode": "${mode}",
  "started_at": "${started_at}",
  "ended_at": "${ended_at}",
  "capture_packet_count": ${CAPTURE_PACKET_COUNT},
  "pcap_retention_policy": "$(json_escape "${PCAP_RETENTION_POLICY}")",
  "pcap_requested": $(json_bool "${PCAP_ENABLE}"),
  "port_pcap_requested": $(json_bool "${PORT_PCAP_ENABLE}"),
  "port_pcap_roles": ${port_pcap_roles_json},
  "port_pcap_active": $(json_bool "${PORT_PCAP_ACTIVE:-0}"),
  "port_pcap_map": "pcap/port-map.json",
  "guest_pcap_requested": $(json_bool "${GUEST_PCAP_ENABLE}"),
  "pcap_summaries_requested": $(json_bool "${PCAP_SUMMARIES_ENABLE}"),
  "detector_placement": "switch-sensor-port",
  "detector_interface": "${EFFECTIVE_SENSOR_PORT}",
  "truth_interface": "${LAB_SWITCH_SENSOR_PORT}",
  "reliability_netem_active": $(json_bool "${RELIABILITY_NETEM_ACTIVE:-0}"),
  "reliability_netem_model": "OVS mirror output routed through veth and Linux tc netem before Detector, Zeek, and Suricata",
  "reliability_netem_loss_percent": $(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}"),
  "reliability_netem_delay_ms": $(nonnegative_int_value RELIABILITY_NETEM_DELAY_MS "${RELIABILITY_NETEM_DELAY_MS}"),
  "reliability_netem_jitter_ms": $(nonnegative_int_value RELIABILITY_NETEM_JITTER_MS "${RELIABILITY_NETEM_JITTER_MS}"),
  "reliability_netem_rate": "$(json_escape "${RELIABILITY_NETEM_RATE}")",
  "reliability_netem_duplicate_percent": $(percent_value RELIABILITY_NETEM_DUPLICATE_PERCENT "${RELIABILITY_NETEM_DUPLICATE_PERCENT}"),
  "reliability_netem_reorder_percent": $(percent_value RELIABILITY_NETEM_REORDER_PERCENT "${RELIABILITY_NETEM_REORDER_PERCENT}"),
  "reliability_netem_corrupt_percent": $(percent_value RELIABILITY_NETEM_CORRUPT_PERCENT "${RELIABILITY_NETEM_CORRUPT_PERCENT}"),
  "reliability_sensor_attack_type": "$(json_escape "${RELIABILITY_SENSOR_ATTACK_TYPE:-}")",
  "switch_truth_snooping_enabled": $(json_bool "${LAB_SWITCH_TRUTH_SNOOPING:-1}"),
  "switch_truth_snooping_artifact": "detector/ovs-switch-truth-snooping.txt",
  "trusted_ground_truth_db": "ground-truth/trusted-observations.sqlite",
  "traffic_probe_enabled": $(json_bool "${TRAFFIC_PROBE_ENABLE:-0}"),
  "traffic_probe_mode": "$(json_escape "${TRAFFIC_PROBE_MODE:-none}")",
  "traffic_probe_pps": $(json_number_or_null "${TRAFFIC_PROBE_PPS:-}"),
  "traffic_probe_dns_interval_seconds": $(json_number_or_null "${TRAFFIC_PROBE_DNS_INTERVAL_SECONDS:-}"),
  "traffic_probe_packet_bytes": $(json_number_or_null "${TRAFFIC_PROBE_PACKET_BYTES:-}"),
  "traffic_probe_artifact": "victim/traffic-window.txt",
  "overload_total_pps": $(json_number_or_null "${OVERLOAD_TOTAL_PPS:-}"),
  "overload_pps_per_source": $(json_number_or_null "${OVERLOAD_PPS_PER_SOURCE:-}"),
  "overload_traffic_seconds": $(json_number_or_null "${OVERLOAD_TRAFFIC_SECONDS:-}"),
  "overload_packet_bytes": $(json_number_or_null "${OVERLOAD_PACKET_BYTES:-}"),
  "overload_sources": ${overload_sources_json},
  "overload_preset": "$(json_escape "${OVERLOAD_PRESET:-}")",
  "overload_engine": "$(json_escape "${OVERLOAD_ENGINE:-}")",
  "overload_workers": "$(json_escape "${OVERLOAD_WORKERS:-}")",
  "overload_pps_per_worker": $(json_number_or_null "${OVERLOAD_PPS_PER_WORKER:-}"),
  "overload_max_workers_per_source": $(json_number_or_null "${OVERLOAD_MAX_WORKERS_PER_SOURCE:-}"),
  "overload_flood": $(json_bool "${OVERLOAD_FLOOD:-0}"),
  "ovs_dhcp_snooping_mode": "${dhcp_snooping_mode_value}",
  "ovs_dhcp_snooping_enforced": ${dhcp_snooping_enforced_json},
  "ovs_dhcp_snooping_artifact": "detector/ovs-dhcp-snooping.txt",
  "detector_ovs_dhcp_snooping_enabled": $(json_bool "${DETECTOR_OVS_DHCP_SNOOPING_ENABLE:-1}"),
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

dhcp_lease_snapshot_cmd() {
  cat <<EOF
sudo python3 - '${VICTIM_MAC,,}' '${ATTACKER_MAC,,}' '${LAB_DHCP_RANGE_START}' '${LAB_DHCP_RANGE_END}' <<'PY'
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import sys

victim_mac = sys.argv[1].lower()
attacker_mac = sys.argv[2].lower()
range_start = ip_address(sys.argv[3])
range_end = ip_address(sys.argv[4])
pool_total = int(range_end) - int(range_start) + 1

leases = []
for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
    if not candidate.exists():
        continue
    for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
        parts = raw_line.split()
        if len(parts) < 3:
            continue
        try:
            lease_ip = ip_address(parts[2])
        except ValueError:
            continue
        if not (range_start <= lease_ip <= range_end):
            continue
        leases.append({
            'expiry': parts[0],
            'mac': parts[1].lower(),
            'ip': str(lease_ip),
            'hostname': parts[3] if len(parts) >= 4 else '',
        })

payload = {
    'ts': datetime.now(timezone.utc).isoformat(),
    'pool_total': pool_total,
    'taken': len(leases),
    'free': pool_total - len(leases),
    'victim_ip': next((lease['ip'] for lease in leases if lease['mac'] == victim_mac), ''),
    'attacker_ip': next((lease['ip'] for lease in leases if lease['mac'] == attacker_mac), ''),
    'leases': leases,
}
print(json.dumps(payload, sort_keys=True))
PY
EOF
}

dhcp_lease_monitor_cmd() {
  local duration="${1:-60}"
  local interval="${2:-1}"
  cat <<EOF
python3 - '${VICTIM_MAC,,}' '${ATTACKER_MAC,,}' '${LAB_DHCP_RANGE_START}' '${LAB_DHCP_RANGE_END}' '${duration}' '${interval}' <<'PY'
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import sys
import time

victim_mac = sys.argv[1].lower()
attacker_mac = sys.argv[2].lower()
range_start = ip_address(sys.argv[3])
range_end = ip_address(sys.argv[4])
duration = float(sys.argv[5])
interval = max(float(sys.argv[6]), 0.2)
pool_total = int(range_end) - int(range_start) + 1

def snapshot():
    leases = []
    for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
        if not candidate.exists():
            continue
        for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
            parts = raw_line.split()
            if len(parts) < 3:
                continue
            try:
                lease_ip = ip_address(parts[2])
            except ValueError:
                continue
            if not (range_start <= lease_ip <= range_end):
                continue
            leases.append({
                'expiry': parts[0],
                'mac': parts[1].lower(),
                'ip': str(lease_ip),
                'hostname': parts[3] if len(parts) >= 4 else '',
            })
    return {
        'ts': datetime.now(timezone.utc).isoformat(),
        'pool_total': pool_total,
        'taken': len(leases),
        'free': pool_total - len(leases),
        'victim_ip': next((lease['ip'] for lease in leases if lease['mac'] == victim_mac), ''),
        'attacker_ip': next((lease['ip'] for lease in leases if lease['mac'] == attacker_mac), ''),
        'leases': leases,
    }

deadline = time.time() + duration
while True:
    print(json.dumps(snapshot(), sort_keys=True), flush=True)
    if time.time() >= deadline:
        break
    time.sleep(interval)
PY
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

lab_switch_port_by_role() {
  local role="$1"
  local vm mac

  case "${role}" in
    gateway)
      vm="${GATEWAY_NAME}"
      mac="${GATEWAY_LAB_MAC}"
      ;;
    victim)
      vm="${VICTIM_NAME}"
      mac="${VICTIM_MAC}"
      ;;
    attacker)
      vm="${ATTACKER_NAME}"
      mac="${ATTACKER_MAC}"
      ;;
    sensor)
      printf '%s\n' "${LAB_SWITCH_SENSOR_PORT}"
      return 0
      ;;
    *)
      warn "Unknown PORT_PCAP_ROLES entry: ${role}"
      return 1
      ;;
  esac

  run_hypervisor virsh -c "${LIBVIRT_URI}" domiflist "${vm}" 2>/dev/null \
    | awk -v wanted="${mac,,}" '
        BEGIN { IGNORECASE = 1 }
        $0 ~ /^[[:space:]]*$/ { next }
        tolower($5) == wanted { print $1; exit }
      '
}

write_port_pcap_map() {
  local outfile="${RUN_DIR}/pcap/port-map.json"
  local idx role label iface comma=""

  {
    printf '{\n'
    printf '  "generated_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "bridge": "%s",\n' "$(json_escape "${LAB_SWITCH_BRIDGE}")"
    printf '  "captures": [\n'
    for idx in "${!PORT_PCAP_CAPTURE_ROLES[@]}"; do
      role="${PORT_PCAP_CAPTURE_ROLES[$idx]}"
      label="${PORT_PCAP_CAPTURE_LABELS[$idx]}"
      iface="${PORT_PCAP_CAPTURE_IFACES[$idx]}"
      printf '%b    {"role": "%s", "interface": "%s", "label": "%s", "pcap": "pcap/ports/%s.pcap"}' \
        "${comma}" "$(json_escape "${role}")" "$(json_escape "${iface}")" "$(json_escape "${label}")" "$(json_escape "${role}")"
      comma=",\n"
    done
    printf '\n  ]\n'
    printf '}\n'
  } > "${outfile}"
}

start_switch_port_captures() {
  local role iface label

  PORT_PCAP_ACTIVE=0
  PORT_PCAP_CAPTURE_ROLES=()
  PORT_PCAP_CAPTURE_LABELS=()
  PORT_PCAP_CAPTURE_IFACES=()

  if ! port_pcaps_requested; then
    return 0
  fi

  for role in ${PORT_PCAP_ROLES}; do
    iface="$(lab_switch_port_by_role "${role}" || true)"
    if [[ -z "${iface}" ]]; then
      warn "Could not resolve switch port for ${role}; skipping per-port capture"
      continue
    fi
    label="port-${role}"
    info "Starting per-port capture for ${role} on ${iface}"
    start_local_capture "${iface}" "${label}" >/dev/null
    PORT_PCAP_CAPTURE_ROLES+=("${role}")
    PORT_PCAP_CAPTURE_LABELS+=("${label}")
    PORT_PCAP_CAPTURE_IFACES+=("${iface}")
    PORT_PCAP_ACTIVE=1
  done

  write_port_pcap_map
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

stop_switch_port_captures() {
  local label

  if [[ "${PORT_PCAP_ACTIVE:-0}" != "1" ]]; then
    return 0
  fi

  for label in "${PORT_PCAP_CAPTURE_LABELS[@]}"; do
    stop_local_capture "${label}"
  done
}

cleanup_run_tmp_capture_files() {
  local host

  if [[ -z "${RUN_ID:-}" || -z "${RUN_SLUG:-}" ]]; then
    return 0
  fi

  run_root_host_bash_lc "
    prefix='/tmp/${RUN_ID}-${RUN_SLUG}-'
    stop_matches() {
      local signal=\"\$1\"
      for pid in \$(pgrep -x tcpdump 2>/dev/null || true); do
        cmd=\$(ps -p \"\$pid\" -o args= 2>/dev/null || true)
        case \"\$cmd\" in
          *\" -w \${prefix}\"*.pcap*) kill -\"\${signal}\" \"\$pid\" 2>/dev/null || true ;;
        esac
      done
    }

    stop_matches INT
    sleep 1
    stop_matches TERM
    sleep 1
    stop_matches KILL
  " >/dev/null 2>&1 || true

  run_root rm -f \
    "/tmp/${RUN_ID}-${RUN_SLUG}-"*.pcap \
    "/tmp/${RUN_ID}-${RUN_SLUG}-"*.pid \
    "/tmp/${RUN_ID}-${RUN_SLUG}-"*.log \
    >/dev/null 2>&1 || true

  for host in gateway victim attacker; do
    remote_sudo_bash_lc "${host}" "
      prefix='/tmp/${RUN_ID}-${RUN_SLUG}-'
      stop_matches() {
        local signal=\"\$1\"
        for pid in \$(pgrep -x tcpdump 2>/dev/null || true); do
          cmd=\$(ps -p \"\$pid\" -o args= 2>/dev/null || true)
          case \"\$cmd\" in
            *\" -w \${prefix}\"*.pcap*) kill -\"\${signal}\" \"\$pid\" 2>/dev/null || true ;;
          esac
        done
      }

      stop_matches INT
      sleep 1
      stop_matches TERM
      sleep 1
      stop_matches KILL
      rm -f \"\${prefix}\"*.pcap \"\${prefix}\"*.pid \"\${prefix}\"*.log 2>/dev/null || true
    " >/dev/null 2>&1 || true
  done
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

fetch_optional_remote_file() {
  local host="$1"
  local remote_path="$2"
  local local_path="$3"

  remote_file_exists "$host" "$remote_path" || return 0
  lab_scp_from "$host" "$remote_path" "$local_path" >/dev/null 2>&1 || return 0
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

  if [[ "${host}" == "attacker" && "${label}" == "${ATTACK_JOB_LABEL:-scenario-job}" ]]; then
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
    echo 'detector_interface=${EFFECTIVE_SENSOR_PORT}'
    echo 'truth_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'reliability_netem_active=${RELIABILITY_NETEM_ACTIVE:-0}'
    echo 'reliability_netem_loss_percent=$(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}")'
    echo 'reliability_netem_delay_ms=${RELIABILITY_NETEM_DELAY_MS}'
    echo 'reliability_netem_jitter_ms=${RELIABILITY_NETEM_JITTER_MS}'
    echo 'reliability_netem_rate=${RELIABILITY_NETEM_RATE}'
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
    echo 'sensor_interface=${EFFECTIVE_SENSOR_PORT}'
    echo 'truth_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'reliability_netem_active=${RELIABILITY_NETEM_ACTIVE:-0}'
    echo 'reliability_netem_loss_percent=$(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}")'
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
    echo 'sensor_interface=${EFFECTIVE_SENSOR_PORT}'
    echo 'truth_interface=${LAB_SWITCH_SENSOR_PORT}'
    echo 'reliability_netem_active=${RELIABILITY_NETEM_ACTIVE:-0}'
    echo 'reliability_netem_loss_percent=$(percent_value RELIABILITY_NETEM_LOSS_PERCENT "${RELIABILITY_NETEM_LOSS_PERCENT}")'
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

  local sensor_pcap="/tmp/${RUN_ID}-${RUN_SLUG}-sensor.pcap"
  local idx role label port_pcap
  if should_keep_run_pcaps; then
    capture_local_delta "${sensor_pcap}" 0 "${RUN_DIR}/pcap/sensor.pcap"
  elif [[ -s "${sensor_pcap}" ]]; then
    ln -s "${sensor_pcap}" "${RUN_DIR}/pcap/sensor.pcap"
  fi

  if should_keep_run_pcaps && [[ "${PORT_PCAP_ACTIVE:-0}" == "1" ]]; then
    for idx in "${!PORT_PCAP_CAPTURE_ROLES[@]}"; do
      role="${PORT_PCAP_CAPTURE_ROLES[$idx]}"
      label="${PORT_PCAP_CAPTURE_LABELS[$idx]}"
      port_pcap="/tmp/${RUN_ID}-${RUN_SLUG}-${label}.pcap"
      capture_local_delta "${port_pcap}" 0 "${RUN_DIR}/pcap/ports/${role}.pcap"
    done
  fi

  if should_keep_run_pcaps && guest_pcaps_requested; then
    fetch_optional_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-gateway.pcap" "${RUN_DIR}/pcap/gateway.pcap"
    fetch_optional_remote_file victim "/tmp/${RUN_ID}-${RUN_SLUG}-victim.pcap" "${RUN_DIR}/pcap/victim.pcap"
    fetch_optional_remote_file attacker "/tmp/${RUN_ID}-${RUN_SLUG}-attacker.pcap" "${RUN_DIR}/pcap/attacker.pcap"
  fi
  fetch_optional_remote_file gateway "/tmp/${RUN_ID}-${RUN_SLUG}-iperf-server.log" "${RUN_DIR}/gateway/iperf-server.log"
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
  done < <(find "${RUN_DIR}/pcap" -type f -name '*.pcap' -print0 | sort -z)
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
  [[ -f "${runtime_root}/current/stats.log" ]] && cp "${runtime_root}/current/stats.log" "${outdir}/stats.log" 2>/dev/null || true

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
  [[ -f "${runtime_root}/current/stats.log" ]] && cp "${runtime_root}/current/stats.log" "${outdir}/stats.log" 2>/dev/null || true

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

  find "${RUN_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  rmdir "${RUN_DIR}" 2>/dev/null || true
}

explain_saved_run() {
  PYTHONPATH="${LAB_DIR}/python${PYTHONPATH:+:${PYTHONPATH}}" python3 -m logs.explain_run "${RUN_DIR}" > "${RUN_DIR}/detector/detector-explained.txt" 2>&1 || true
}

evaluate_saved_run() {
  lab_python_module metrics.evaluator "${RUN_DIR}" \
    --json-out "${RUN_DIR}/evaluation.json" \
    --text-out "${RUN_DIR}/evaluation-summary.txt" >/dev/null 2>&1 || true
}

upsert_results_db() {
  local compact_arg=()
  if [[ "${KEEP_DEBUG_ARTIFACTS}" != "1" ]]; then
    compact_arg=(--compact)
  fi
  lab_python_module metrics.results_db upsert-run "${RUN_DIR}" "${compact_arg[@]}" >/dev/null
}

write_summary() {
  local target="${1:-${RUN_DIR}}"
  if [[ "${KEEP_DEBUG_ARTIFACTS}" == "1" ]]; then
    lab_python_module metrics.summary_cli "${target}" | tee "${target}/summary.txt"
  else
    lab_python_module metrics.summary_cli "${target}"
  fi
}
