#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mkdir -p "$(generated_dir gateway)" "$(generated_dir victim)" "$(generated_dir attacker)"
TMP_RENDER_DIR="${LAB_DIR}/generated/rendered"
mkdir -p "${TMP_RENDER_DIR}"

IFS=' ' read -r -a DETECTOR_DOMAIN_ARRAY <<< "${DETECTOR_DOMAINS}"
PYTHON_DOMAIN_LIST="$(printf "'%s', " "${DETECTOR_DOMAIN_ARRAY[@]}" | sed 's/, $//')"

cat > "${TMP_RENDER_DIR}/mitm-lab-gateway.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

LAB_SUBNET="${LAB_SUBNET}"
UP_IF="gw-up"
LAB_IF="gw-lab"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -s "\${LAB_SUBNET}" -o "\${UP_IF}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "\${LAB_SUBNET}" -o "\${UP_IF}" -j MASQUERADE

iptables -C FORWARD -i "\${UP_IF}" -o "\${LAB_IF}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "\${UP_IF}" -o "\${LAB_IF}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i "\${LAB_IF}" -o "\${UP_IF}" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "\${LAB_IF}" -o "\${UP_IF}" -j ACCEPT

systemctl restart dnsmasq
EOF

cat > "${TMP_RENDER_DIR}/mitm-lab-gateway.service" <<'EOF'
[Unit]
Description=MITM lab gateway NAT bootstrap
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mitm-lab-gateway.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "${TMP_RENDER_DIR}/dnsmasq-mitm-lab.conf" <<EOF
interface=gw-lab
listen-address=${GATEWAY_IP}
bind-interfaces
domain-needed
bogus-priv
server=${UPSTREAM_DNS1}
server=${UPSTREAM_DNS2}
cache-size=1000
log-facility=/var/log/dnsmasq-mitm-lab.log
EOF

cat > "${TMP_RENDER_DIR}/mitm_lab_detector.py" <<EOF
#!/usr/bin/env python3
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

GATEWAY_IP = "${GATEWAY_IP}"
DNS_SERVER = "${DNS_SERVER}"
DOMAINS = [${PYTHON_DOMAIN_LIST}]
LOG_PATH = Path("/var/log/mitm-lab-detector.jsonl")
STATE_PATH = Path("/var/lib/mitm-lab-detector/state.json")
POLL_SECONDS = 2
MAC_RE = re.compile(r"lladdr\s+([0-9a-f:]{17})", re.I)


def now():
    return datetime.now(timezone.utc).isoformat()


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def get_gateway_mac():
    result = run(["ip", "neigh", "show", GATEWAY_IP])
    match = MAC_RE.search(result.stdout)
    return match.group(1).lower() if match else None


def resolve_a(domain):
    result = run(["dig", "+short", "A", domain, f"@{DNS_SERVER}"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def load_state():
    if not STATE_PATH.exists():
        return {"seen_gateway_macs": [], "domain_baselines": {}}
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {"seen_gateway_macs": [], "domain_baselines": {}}


def save_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True))


def log_event(event_type, **payload):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": now(), "event": event_type, **payload}
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def main():
    state = load_state()
    seen_gateway_macs = set(state.get("seen_gateway_macs", []))
    domain_baselines = dict(state.get("domain_baselines", {}))
    expected_gateway_mac = state.get("expected_gateway_mac")

    log_event("detector_started", gateway_ip=GATEWAY_IP, dns_server=DNS_SERVER, domains=DOMAINS)

    while True:
        current_mac = get_gateway_mac()
        if current_mac and not expected_gateway_mac:
            expected_gateway_mac = current_mac
            log_event("gateway_baseline_set", expected_gateway_mac=expected_gateway_mac)

        if current_mac:
            seen_gateway_macs.add(current_mac)

        if expected_gateway_mac and current_mac and current_mac != expected_gateway_mac:
            log_event(
                "gateway_mac_changed",
                expected_gateway_mac=expected_gateway_mac,
                current_gateway_mac=current_mac,
            )

        if len(seen_gateway_macs) > 1:
            log_event("multiple_gateway_macs_seen", gateway_macs=sorted(seen_gateway_macs))

        resolutions = {}
        for domain in DOMAINS:
            answers = resolve_a(domain)
            resolutions[domain] = answers
            if answers and domain not in domain_baselines:
                domain_baselines[domain] = answers
                log_event("domain_baseline_set", domain=domain, answers=answers)
            elif answers and domain in domain_baselines and answers != domain_baselines[domain]:
                log_event(
                    "domain_resolution_changed",
                    domain=domain,
                    baseline=domain_baselines[domain],
                    current=answers,
                )

        log_event(
            "heartbeat",
            expected_gateway_mac=expected_gateway_mac,
            current_gateway_mac=current_mac,
            seen_gateway_macs=sorted(seen_gateway_macs),
            resolutions=resolutions,
        )

        save_state({
            "expected_gateway_mac": expected_gateway_mac,
            "seen_gateway_macs": sorted(seen_gateway_macs),
            "domain_baselines": domain_baselines,
        })
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
EOF

cat > "${TMP_RENDER_DIR}/mitm-lab-detector.service" <<'EOF'
[Unit]
Description=MITM lab victim detector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mitm_lab_detector.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

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
$(indent_file "${TMP_RENDER_DIR}/mitm-lab-gateway.sh")
  - path: /etc/systemd/system/mitm-lab-gateway.service
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${TMP_RENDER_DIR}/mitm-lab-gateway.service")
  - path: /etc/dnsmasq.d/mitm-lab.conf
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${TMP_RENDER_DIR}/dnsmasq-mitm-lab.conf")
  - path: /etc/sysctl.d/99-mitm-lab.conf
    permissions: '0644'
    owner: root:root
    content: |
      net.ipv4.ip_forward=1
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
users:
  - default
  - name: ${LAB_USER}
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
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
$(indent_file "${TMP_RENDER_DIR}/mitm_lab_detector.py")
  - path: /etc/systemd/system/mitm-lab-detector.service
    permissions: '0644'
    owner: root:root
    content: |
$(indent_file "${TMP_RENDER_DIR}/mitm-lab-detector.service")
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
ssh_pwauth: true
chpasswd:
  list: |
    ${LAB_USER}:${LAB_PASSWORD}
  expire: false
EOF

info "Cloud-init data generated under ${LAB_DIR}/generated"
