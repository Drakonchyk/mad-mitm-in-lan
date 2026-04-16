#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-20000}"
SURICATA_ENABLE="${SURICATA_ENABLE:-auto}"

require_experiment_tools() {
  require_cmd ssh
  require_cmd scp
  require_cmd python3
  require_cmd tshark
}

render_victim_detector() {
  local outfile="$1"

  python3 - "$LAB_DIR" "$outfile" <<'PY'
from pathlib import Path
import sys

repo_root = Path(sys.argv[1])
output_path = Path(sys.argv[2])
sys.path.insert(0, str(repo_root / "python"))

from lab_config import load_lab_config  # noqa: E402

config = load_lab_config(repo_root / "lab.conf")
domain_list = ", ".join(repr(domain) for domain in config["DETECTOR_DOMAINS"].split() if domain)
source = (repo_root / "python" / "mitm_lab_detector.py").read_text(encoding="utf-8")
rendered = (
    source.replace("__GATEWAY_IP__", config["GATEWAY_IP"])
    .replace("__DNS_SERVER__", config["DNS_SERVER"])
    .replace("__PYTHON_DOMAIN_LIST__", domain_list)
)
output_path.write_text(rendered, encoding="utf-8")
PY
}

prepare_victim_detector() {
  local rendered_detector
  rendered_detector="$(mktemp)"
  render_victim_detector "${rendered_detector}"

  info "Refreshing victim gateway neighbor state before detector baseline"
  remote_sudo_bash_lc victim \
    "ip neigh del '${GATEWAY_IP}' dev vnic0 2>/dev/null || true"
  remote_bash_lc victim \
    "ping -c 1 -W 1 '${GATEWAY_IP}' >/dev/null 2>&1 || true"

  info "Deploying current detector source to victim"
  lab_scp_to victim "${rendered_detector}" "/tmp/mitm_lab_detector.py"
  remote_sudo_bash_lc victim \
    "install -m 0755 '/tmp/mitm_lab_detector.py' '/usr/local/bin/mitm_lab_detector.py' && rm -f '/tmp/mitm_lab_detector.py' && rm -f '/var/lib/mitm-lab-detector/state.json' && systemctl restart mitm-lab-detector.service && systemctl is-active --quiet mitm-lab-detector.service"

  rm -f "${rendered_detector}"
  wait_for_victim_detector_baseline
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
  lab_scp_to attacker "${LAB_DIR}/python/lab_config.py" "${remote_root}/python/lab_config.py"
  lab_scp_to attacker "${LAB_DIR}/python/lab_network.py" "${remote_root}/python/lab_network.py"
  lab_scp_to attacker "${LAB_DIR}/python/mitm_research.py" "${remote_root}/python/mitm_research.py"
  lab_scp_to attacker "${LAB_DIR}/python/setup_all.py" "${remote_root}/python/setup_all.py"

  remote_bash_lc attacker \
    "chmod 0644 '${remote_root}/lab.conf' '${remote_root}/python/'*.py && chmod 0755 '${remote_root}/python/setup_all.py'"
  remote_bash_lc attacker "python3 -c 'import scapy.all'"
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
  "capture_packet_count": ${CAPTURE_PACKET_COUNT},
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

remote_file_exists() {
  local host="$1"
  local remote_path="$2"

  remote_bash_lc "$host" "test -f '$remote_path'" >/dev/null 2>&1
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
    suricata --build-info 2>/dev/null | sed -n '1,4p' || true
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst \
      suricata tshark tcpdump python3 curl jq dnsutils 2>/dev/null || true
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
    tshark --version 2>/dev/null | sed -n '1,2p' || true
    tcpdump --version 2>/dev/null | sed -n '1p' || true
    dig -v 2>/dev/null | sed -n '1p' || true
    curl --version 2>/dev/null | sed -n '1p' || true
    iperf3 --version 2>/dev/null | sed -n '1p' || true
    jq --version 2>/dev/null || true
    echo
    echo '== package versions =='
    dpkg-query -W -f='\${Package}=\${Version}\n' \
      python3 python3-pip tcpdump tshark dnsutils curl iperf3 jq 2>/dev/null || true
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
  } > "${outfile}" 2>&1 || {
    warn "tshark summary failed for ${pcap_path}"
    return 0
  }
}

summarize_saved_pcaps() {
  while IFS= read -r -d '' pcap_path; do
    write_tshark_summary "${pcap_path}"
  done < <(find "${RUN_DIR}/pcap" -maxdepth 1 -type f -name '*.pcap' -print0 | sort -z)
}

suricata_should_run() {
  case "${SURICATA_ENABLE}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    auto)
      command -v suricata >/dev/null 2>&1 && [[ -f /etc/suricata/suricata.yaml ]]
      return
      ;;
    *)
      warn "Unknown SURICATA_ENABLE value: ${SURICATA_ENABLE}; skipping Suricata"
      return 1
      ;;
  esac
}

write_suricata_status() {
  local message="$1"
  mkdir -p "${RUN_DIR}/suricata"
  printf '%s\n' "${message}" > "${RUN_DIR}/suricata/status.txt"
}

analyze_saved_pcaps_with_suricata() {
  local pcap_path outdir eve_path summary_path rules_path

  if ! suricata_should_run; then
    write_suricata_status "suricata_status=skipped"
    return 0
  fi

  pcap_path="${RUN_DIR}/pcap/victim.pcap"
  if [[ ! -s "${pcap_path}" ]]; then
    write_suricata_status "suricata_status=skipped_no_victim_pcap"
    return 0
  fi

  outdir="${RUN_DIR}/suricata/victim"
  eve_path="${outdir}/eve.json"
  summary_path="${outdir}/summary.txt"
  rules_path="${RUN_DIR}/suricata/mitm-lab.rules"
  mkdir -p "${outdir}"
  write_suricata_status "suricata_status=running"
  render_suricata_lab_rules "${rules_path}"

  if ! suricata -r "${pcap_path}" -l "${outdir}" -c /etc/suricata/suricata.yaml -S "${rules_path}" >/dev/null 2>&1; then
    write_suricata_status "suricata_status=failed"
    warn "Suricata analysis failed for ${pcap_path}"
    return 0
  fi

  if [[ -f "${eve_path}" ]]; then
    python3 "${LAB_DIR}/python/summarize_suricata_eve.py" "${eve_path}" "${RUN_DIR}" > "${summary_path}" 2>&1 || true
    write_suricata_status "suricata_status=ok"
  else
    write_suricata_status "suricata_status=ok_no_eve"
  fi
}

render_suricata_lab_rules() {
  local outfile="$1"
  local victim_ip attacker_ip gateway_ip attacker_ip_hex

  victim_ip="$(cidr_addr "${VICTIM_CIDR}")"
  attacker_ip="$(cidr_addr "${ATTACKER_CIDR}")"
  gateway_ip="${GATEWAY_IP}"
  IFS=. read -r a b c d <<< "${attacker_ip}"
  printf -v attacker_ip_hex '|%02X %02X %02X %02X|' "${a}" "${b}" "${c}" "${d}"

  cat > "${outfile}" <<EOF
alert icmp ${attacker_ip} any -> ${victim_ip} any (msg:"MITM-LAB ICMP redirect from attacker to victim"; itype:5; classtype:attempted-admin; sid:9900001; rev:1;)
alert udp ${gateway_ip} 53 -> ${victim_ip} any (msg:"MITM-LAB DNS answer contains attacker IP"; content:"${attacker_ip_hex}"; classtype:bad-unknown; sid:9900002; rev:1;)
EOF
}

explain_saved_run() {
  python3 "${LAB_DIR}/python/explain_run.py" "${RUN_DIR}" > "${RUN_DIR}/victim/detector-explained.txt" 2>&1 || true
}

evaluate_saved_run() {
  python3 "${LAB_DIR}/python/evaluate_run.py" "${RUN_DIR}" \
    --json-out "${RUN_DIR}/evaluation.json" \
    --text-out "${RUN_DIR}/evaluation-summary.txt" >/dev/null 2>&1 || true
}

write_summary() {
  local target="${1:-${RUN_DIR}}"
  python3 "${LAB_DIR}/python/summarize_results.py" "${target}" | tee "${target}/summary.txt"
}
