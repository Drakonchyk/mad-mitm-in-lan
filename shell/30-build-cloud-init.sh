#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ensure_automation_ssh_key

mkdir -p "$(generated_dir gateway)" "$(generated_dir victim)" "$(generated_dir attacker)"
SHELL_SOURCE_DIR="${LAB_DIR}/shell"
PYTHON_SOURCE_DIR="${LAB_DIR}/python"
SERVICE_SOURCE_DIR="${LAB_DIR}/services"
CONFIG_SOURCE_DIR="${LAB_DIR}/config"

IFS=' ' read -r -a DETECTOR_DOMAIN_ARRAY <<< "${DETECTOR_DOMAINS}"
PYTHON_DOMAIN_LIST="$(printf "'%s', " "${DETECTOR_DOMAIN_ARRAY[@]}" | sed 's/, $//')"
AUTOMATION_SSH_KEY="$(< "$(automation_public_key)")"

indent_file() {
  local file="$1"
  sed 's/^/      /' "$file"
}

indent_rendered_template() {
  local src="$1"
  shift
  local sed_args=()

  while (( $# >= 2 )); do
    local key="$1"
    local value="$2"
    shift 2

    value="${value//\\/\\\\}"
    value="${value//&/\\&}"
    value="${value//|/\\|}"
    sed_args+=(-e "s|__${key}__|${value}|g")
  done

  sed "${sed_args[@]}" "$src" | sed 's/^/      /'
}

cat > "$(generated_dir gateway)/meta-data.yaml" <<EOF
instance-id: ${GATEWAY_NAME}
local-hostname: ${GATEWAY_NAME}
EOF

cat > "$(generated_dir gateway)/network-config.yaml" <<EOF
version: 2
ethernets:
  gw-up:
    match:
      macaddress: "${GATEWAY_UP_MAC}"
    set-name: gw-up
    dhcp4: true
  gw-lab:
    match:
      macaddress: "${GATEWAY_LAB_MAC}"
    set-name: gw-lab
    dhcp4: false
    addresses:
      - ${GATEWAY_CIDR}
EOF

cat > "$(generated_dir gateway)/user-data.yaml" <<EOF
#cloud-config
hostname: ${GATEWAY_NAME}
manage_etc_hosts: true
package_update: true
package_upgrade: false
timezone: ${TIMEZONE}
packages:
  - openssh-server
  - tcpdump
  - tshark
  - iproute2
  - net-tools
  - dnsutils
  - dnsmasq
  - curl
  - iperf3
  - jq
users:
  - default
  - name: ${LAB_USER}
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    ssh_authorized_keys:
      - ${AUTOMATION_SSH_KEY}
ssh_pwauth: true
chpasswd:
  list: |
    ${LAB_USER}:${LAB_PASSWORD}
  expire: false
write_files:
  - path: /usr/local/sbin/mitm-lab-gateway.sh
    permissions: '0755'
    owner: root:root
    content: |
$(indent_rendered_template "${SHELL_SOURCE_DIR}/mitm-lab-gateway.sh" LAB_SUBNET "${LAB_SUBNET}")
  - path: /etc/systemd/system/mitm-lab-gateway.service
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${SERVICE_SOURCE_DIR}/mitm-lab-gateway.service")
  - path: /etc/dnsmasq.d/mitm-lab.conf
    permissions: '0644'
    owner: root:root
    content: |
$(indent_rendered_template "${CONFIG_SOURCE_DIR}/dnsmasq-mitm-lab.conf" GATEWAY_IP "${GATEWAY_IP}" UPSTREAM_DNS1 "${UPSTREAM_DNS1}" UPSTREAM_DNS2 "${UPSTREAM_DNS2}")
  - path: /etc/sysctl.d/99-mitm-lab.conf
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${CONFIG_SOURCE_DIR}/99-mitm-lab.conf")
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, dnsmasq]
  - [systemctl, enable, --now, mitm-lab-gateway.service]
EOF

cat > "$(generated_dir victim)/meta-data.yaml" <<EOF
instance-id: ${VICTIM_NAME}
local-hostname: ${VICTIM_NAME}
EOF

cat > "$(generated_dir victim)/network-config.yaml" <<EOF
version: 2
ethernets:
  vnic0:
    match:
      macaddress: "${VICTIM_MAC}"
    set-name: vnic0
    dhcp4: false
    addresses:
      - ${VICTIM_CIDR}
    routes:
      - to: default
        via: ${GATEWAY_IP}
    nameservers:
      addresses:
        - ${DNS_SERVER}
EOF

cat > "$(generated_dir victim)/user-data.yaml" <<EOF
#cloud-config
hostname: ${VICTIM_NAME}
manage_etc_hosts: true
package_update: true
package_upgrade: false
timezone: ${TIMEZONE}
packages:
  - openssh-server
  - tcpdump
  - tshark
  - iproute2
  - net-tools
  - dnsutils
  - curl
  - iperf3
  - python3
  - python3-pip
  - python3-scapy
  - jq
users:
  - default
  - name: ${LAB_USER}
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    ssh_authorized_keys:
      - ${AUTOMATION_SSH_KEY}
ssh_pwauth: true
chpasswd:
  list: |
    ${LAB_USER}:${LAB_PASSWORD}
  expire: false
write_files:
  - path: /usr/local/bin/mitm_lab_detector.py
    permissions: '0755'
    owner: root:root
    content: |
$(indent_rendered_template "${PYTHON_SOURCE_DIR}/mitm_lab_detector.py" GATEWAY_IP "${GATEWAY_IP}" DNS_SERVER "${DNS_SERVER}" ATTACKER_IP "$(cidr_addr "${ATTACKER_CIDR}")" VICTIM_IP "$(cidr_addr "${VICTIM_CIDR}")" PYTHON_DOMAIN_LIST "${PYTHON_DOMAIN_LIST}")
  - path: /etc/systemd/system/mitm-lab-detector.service
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${SERVICE_SOURCE_DIR}/mitm-lab-detector.service")
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, mitm-lab-detector.service]
EOF

cat > "$(generated_dir attacker)/meta-data.yaml" <<EOF
instance-id: ${ATTACKER_NAME}
local-hostname: ${ATTACKER_NAME}
EOF

cat > "$(generated_dir attacker)/network-config.yaml" <<EOF
version: 2
ethernets:
  vnic0:
    match:
      macaddress: "${ATTACKER_MAC}"
    set-name: vnic0
    dhcp4: false
    addresses:
      - ${ATTACKER_CIDR}
    routes:
      - to: default
        via: ${GATEWAY_IP}
    nameservers:
      addresses:
        - ${DNS_SERVER}
EOF

cat > "$(generated_dir attacker)/user-data.yaml" <<EOF
#cloud-config
hostname: ${ATTACKER_NAME}
manage_etc_hosts: true
package_update: true
package_upgrade: false
timezone: ${TIMEZONE}
packages:
  - openssh-server
  - tcpdump
  - tshark
  - iproute2
  - net-tools
  - dnsutils
  - curl
  - iperf3
  - python3
  - python3-pip
  - jq
  - python3-scapy
users:
  - default
  - name: ${LAB_USER}
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    ssh_authorized_keys:
      - ${AUTOMATION_SSH_KEY}
ssh_pwauth: true
chpasswd:
  list: |
    ${LAB_USER}:${LAB_PASSWORD}
  expire: false
EOF

info "Cloud-init data generated under ${LAB_DIR}/generated"
