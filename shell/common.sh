#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${LAB_DIR}/lab.conf"

info() {
  printf '[*] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    warn "Missing required command: $1"
    exit 1
  }
}

run_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

have_libvirt_group() {
  id -nG "$USER" | tr ' ' '\n' | grep -qx libvirt
}

libvirt_direct_ok() {
  virsh -c "${LIBVIRT_URI}" uri >/dev/null 2>&1
}

run_hypervisor() {
  if libvirt_direct_ok; then
    "$@"
    return
  fi

  if have_libvirt_group; then
    local quoted
    printf -v quoted '%q ' "$@"
    sg libvirt -c "$quoted"
    return
  fi

  run_root "$@"
}

vm_disk_path() {
  local name="$1"
  printf '%s/%s.qcow2\n' "$STORAGE_ROOT" "$name"
}

canonical_path() {
  readlink -m -- "$1"
}

pool_name_for_path() {
  local wanted actual pool xml_path
  wanted="$(canonical_path "$1")"

  while IFS= read -r pool; do
    pool="$(printf '%s' "$pool" | xargs)"
    [[ -n "$pool" ]] || continue
    xml_path="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" pool-dumpxml "$pool" 2>/dev/null \
        | awk -F'[<>]' '/<path>/ { print $3; exit }'
    )"
    [[ -n "$xml_path" ]] || continue
    actual="$(canonical_path "$xml_path")"
    if [[ "$actual" == "$wanted" ]]; then
      printf '%s\n' "$pool"
      return 0
    fi
  done < <(run_hypervisor virsh -c "${LIBVIRT_URI}" pool-list --all --name 2>/dev/null || true)

  return 1
}

generated_dir() {
  local name="$1"
  printf '%s/generated/%s\n' "$LAB_DIR" "$name"
}

results_root() {
  printf '%s/results\n' "$LAB_DIR"
}

automation_key_dir() {
  printf '%s/generated/ssh\n' "$LAB_DIR"
}

automation_private_key() {
  printf '%s/lab_automation_ed25519\n' "$(automation_key_dir)"
}

automation_public_key() {
  printf '%s.pub\n' "$(automation_private_key)"
}

ensure_automation_ssh_key() {
  local key
  key="$(automation_private_key)"

  if [[ -f "$key" && -f "$(automation_public_key)" ]]; then
    return 0
  fi

  require_cmd ssh-keygen
  mkdir -p "$(automation_key_dir)"
  ssh-keygen -q -t ed25519 -N '' -f "$key" -C "mitm-lab-automation" >/dev/null
}

cidr_addr() {
  local cidr="$1"
  printf '%s\n' "${cidr%/*}"
}

query_gateway_upstream_ip() {
  local ip=""

  ip="$(
    run_hypervisor virsh -c "${LIBVIRT_URI}" net-dhcp-leases default 2>/dev/null \
      | awk -v mac="${GATEWAY_UP_MAC,,}" '
          BEGIN { IGNORECASE = 1 }
          index(tolower($0), mac) {
            for (i = 1; i <= NF; i++) {
              if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
                sub(/\/.*/, "", $i)
                print $i
                exit
              }
            }
          }
        '
  )"

  if [[ -z "$ip" ]]; then
    ip="$(
      run_hypervisor virsh -c "${LIBVIRT_URI}" domifaddr "${GATEWAY_NAME}" --source lease 2>/dev/null \
        | awk -v mac="${GATEWAY_UP_MAC,,}" '
            BEGIN { IGNORECASE = 1 }
            index(tolower($0), mac) {
              for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
                  sub(/\/.*/, "", $i)
                  print $i
                  exit
                }
              }
            }
          '
    )"
  fi

  printf '%s\n' "$ip"
}

gateway_upstream_ip() {
  local ip attempts delay try

  attempts="${GATEWAY_IP_LOOKUP_ATTEMPTS:-12}"
  delay="${GATEWAY_IP_LOOKUP_DELAY_SECONDS:-5}"

  for ((try = 1; try <= attempts; try++)); do
    ip="$(query_gateway_upstream_ip)"
    if [[ -n "$ip" ]]; then
      printf '%s\n' "$ip"
      return 0
    fi

    if (( try < attempts )); then
      if (( try == 1 || try == attempts - 1 || try % 3 == 0 )); then
        info "Waiting for ${GATEWAY_NAME} upstream DHCP lease (${try}/${attempts})"
      fi
      sleep "$delay"
    fi
  done

  if [[ -z "$ip" ]]; then
    warn "Could not determine ${GATEWAY_NAME} upstream IP from libvirt DHCP lease data"
    return 1
  fi

  printf '%s\n' "$ip"
}

lab_mac_for_host() {
  local host="$1"

  case "$host" in
    gateway)
      printf '%s\n' "${GATEWAY_LAB_MAC}"
      ;;
    victim)
      printf '%s\n' "${VICTIM_MAC}"
      ;;
    attacker)
      printf '%s\n' "${ATTACKER_MAC}"
      ;;
    *)
      warn "Unknown lab host for MAC lookup: ${host}"
      return 1
      ;;
  esac
}

query_gateway_dnsmasq_lease_ip_by_mac() {
  local mac="$1"

  ensure_automation_ssh_key

  local key addr
  key="$(automation_private_key)"
  addr="$(gateway_upstream_ip)"

  ssh \
    -i "$key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    "${LAB_USER}@${addr}" \
    "sudo python3 - '${mac,,}' <<'PY'
from pathlib import Path
import sys

mac = sys.argv[1].lower()
for candidate in (Path('/var/lib/misc/dnsmasq.leases'), Path('/var/lib/dhcp/dnsmasq.leases')):
    if not candidate.exists():
        continue
    for raw_line in candidate.read_text(encoding='utf-8', errors='replace').splitlines():
        parts = raw_line.split()
        if len(parts) >= 3 and parts[1].lower() == mac:
            print(parts[2])
            raise SystemExit(0)
PY" 2>/dev/null || true
}

lab_guest_ip() {
  local host="$1"
  local mac ip attempts delay try

  mac="$(lab_mac_for_host "$host")"
  attempts="${LAB_GUEST_IP_LOOKUP_ATTEMPTS:-20}"
  delay="${LAB_GUEST_IP_LOOKUP_DELAY_SECONDS:-3}"

  for ((try = 1; try <= attempts; try++)); do
    ip="$(query_gateway_dnsmasq_lease_ip_by_mac "${mac}")"
    if [[ -n "${ip}" ]]; then
      printf '%s\n' "${ip}"
      return 0
    fi
    if (( try < attempts )) && (( try == 1 || try == attempts - 1 || try % 4 == 0 )); then
      info "Waiting for ${host} DHCP lease on the lab switch (${try}/${attempts})"
    fi
    if (( try < attempts )); then
      sleep "${delay}"
    fi
  done

  warn "Could not determine current DHCP lease for ${host}"
  return 1
}

lab_host_ip() {
  local host="$1"

  case "$host" in
    gateway)
      gateway_upstream_ip
      ;;
    victim)
      lab_guest_ip victim
      ;;
    attacker)
      lab_guest_ip attacker
      ;;
    *)
      warn "Unknown lab host: ${host}"
      return 1
      ;;
  esac
}

lab_ssh() {
  local host="$1"
  shift

  ensure_automation_ssh_key

  local key addr gateway_ip proxy_cmd
  local connect_timeout="${LAB_SSH_CONNECT_TIMEOUT:-10}"
  key="$(automation_private_key)"
  addr="$(lab_host_ip "$host")"
  local ssh_args=(
    -i "$key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o ConnectTimeout="${connect_timeout}"
  )

  if [[ "$host" == "gateway" ]]; then
    ssh "${ssh_args[@]}" "${LAB_USER}@${addr}" "$@"
    return
  fi

  gateway_ip="$(gateway_upstream_ip)"
  printf -v proxy_cmd 'ssh -i %q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=%q -W %%h:%%p %q' \
    "$key" "${connect_timeout}" "${LAB_USER}@${gateway_ip}"
  ssh "${ssh_args[@]}" -o "ProxyCommand=${proxy_cmd}" "${LAB_USER}@${addr}" "$@"
}

lab_scp_from() {
  local host="$1"
  local remote_path="$2"
  local local_path="$3"

  ensure_automation_ssh_key

  local key addr gateway_ip proxy_cmd
  local connect_timeout="${LAB_SSH_CONNECT_TIMEOUT:-10}"
  key="$(automation_private_key)"
  addr="$(lab_host_ip "$host")"
  local scp_args=(
    -i "$key"
    -r
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o ConnectTimeout="${connect_timeout}"
  )

  if [[ "$host" == "gateway" ]]; then
    scp "${scp_args[@]}" "${LAB_USER}@${addr}:${remote_path}" "${local_path}"
    return
  fi

  gateway_ip="$(gateway_upstream_ip)"
  printf -v proxy_cmd 'ssh -i %q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=%q -W %%h:%%p %q' \
    "$key" "${connect_timeout}" "${LAB_USER}@${gateway_ip}"
  scp "${scp_args[@]}" -o "ProxyCommand=${proxy_cmd}" "${LAB_USER}@${addr}:${remote_path}" "${local_path}"
}

lab_scp_to() {
  local host="$1"
  local local_path="$2"
  local remote_path="$3"

  ensure_automation_ssh_key

  local key addr gateway_ip proxy_cmd
  local connect_timeout="${LAB_SSH_CONNECT_TIMEOUT:-10}"
  key="$(automation_private_key)"
  addr="$(lab_host_ip "$host")"
  local scp_args=(
    -i "$key"
    -r
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o ConnectTimeout="${connect_timeout}"
  )

  if [[ "$host" == "gateway" ]]; then
    scp "${scp_args[@]}" "${local_path}" "${LAB_USER}@${addr}:${remote_path}"
    return
  fi

  gateway_ip="$(gateway_upstream_ip)"
  printf -v proxy_cmd 'ssh -i %q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=%q -W %%h:%%p %q' \
    "$key" "${connect_timeout}" "${LAB_USER}@${gateway_ip}"
  scp "${scp_args[@]}" -o "ProxyCommand=${proxy_cmd}" "${local_path}" "${LAB_USER}@${addr}:${remote_path}"
}

wait_for_lab_ssh() {
  local host="$1"
  local attempts="${2:-60}"
  local delay="${3:-5}"
  local try

  for ((try = 1; try <= attempts; try++)); do
    if lab_ssh "$host" true >/dev/null 2>&1; then
      info "SSH is ready on ${host} (${try}/${attempts})"
      return 0
    fi
    if (( try == 1 || try % 6 == 0 || try == attempts )); then
      info "Still waiting for SSH on ${host} (${try}/${attempts}, retrying every ${delay}s)"
    fi
    sleep "$delay"
  done

  warn "Timed out waiting for SSH access to ${host}"
  return 1
}
