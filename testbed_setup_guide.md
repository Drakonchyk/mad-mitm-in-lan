# MITM Diploma Testbed Setup Guide (Ubuntu Host)

This guide is for a safe, isolated lab only. Do not run any poisoning, spoofing, forwarding, or packet-injection steps on your home router LAN, campus network, office network, or public Wi-Fi.

## 1. Recommended architecture

Use one Ubuntu host laptop and three virtual machines:

- Victim VM
- Attacker VM
- Gateway VM

Use two virtual networks:

- `default` libvirt NAT network for the gateway's upstream side
- an **isolated** lab network for victim/attacker/gateway communication

This keeps all attack traffic inside the lab.

## 2. Host packages to install on Ubuntu

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager cpu-checker \
  wireshark tshark tcpdump python3-pip git jq curl iperf3 dnsutils
```

Then verify hardware virtualization:

```bash
kvm-ok
```

If your user is not already allowed to manage libvirt:

```bash
sudo adduser $USER libvirt
```

Log out and back in after adding the group.

## 3. VM plan

### Victim VM

Use Ubuntu Server or a minimal Ubuntu Desktop install.

Base packages:

```bash
sudo apt update
sudo apt install tcpdump tshark iproute2 net-tools dnsutils curl iperf3 python3 python3-pip jq
```

### Gateway VM

Use Ubuntu Server.

Base packages:

```bash
sudo apt update
sudo apt install tcpdump tshark iproute2 net-tools dnsutils dnsmasq curl iperf3 jq
```

Enable routing:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

To make that persistent, add this line to `/etc/sysctl.conf`:

```text
net.ipv4.ip_forward=1
```

### Attacker VM

Use Ubuntu Server if you want a cleaner academic setup, or Kali if you want faster tool availability.

If you stay with Ubuntu, install:

```bash
sudo apt update
sudo apt install tcpdump tshark iproute2 net-tools dnsutils curl iperf3 python3 python3-pip jq python3-scapy
```

This is enough for custom Scapy-based ARP/DNS experiments.

## 4. Network design

Use static IPs first. It is simpler and makes traces easier to read.

Suggested lab addresses:

- Gateway lab NIC: `10.20.20.1/24`
- Victim: `10.20.20.10/24`
- Attacker: `10.20.20.66/24`
- Victim default gateway: `10.20.20.1`
- Victim DNS server: `10.20.20.1`

Gateway VM should have:

- NIC 1 on libvirt `default` NAT network
- NIC 2 on isolated `mitm-lab` network

Victim and attacker should each have **only** one NIC on `mitm-lab`.

## 5. Minimum viable tooling

### Must-have

- KVM/libvirt + virt-manager
- tcpdump / tshark / Wireshark
- Python 3 + Scapy
- iperf3
- dnsutils (`dig`)

### Strongly recommended

- bettercap on attacker VM for quick ARP and DNS spoofing tests
- Suricata on monitor/gateway side for packet-rule comparison
- Zeek if you want richer network logs

## 6. Detector plan

Start with a custom Python detector before adding large IDS tools.

Recommended first detector features:

- store the expected gateway MAC at baseline
- poll `ip neigh show` and compare the gateway binding
- count ARP replies in a sliding time window
- flag when one IP is seen with multiple MACs
- flag when selected domains resolve to unexpected IPs
- log everything as JSON with timestamps

## 7. Captures you should always save

For each run, save:

- attacker-side pcap
- victim-side pcap
- gateway-side pcap
- victim `ip neigh` output before, during, after attack
- detector logs
- exact attack start/stop timestamps

## 8. Recommended experiment order

1. Build the three-VM isolated lab.
2. Confirm normal routing and DNS.
3. Capture a clean baseline.
4. Test ARP poisoning without forwarding.
5. Test ARP poisoning with forwarding.
6. Add selected DNS spoofing for one or two test domains.
7. Turn your detector on and repeat each scenario multiple times.
8. Add optional Suricata or Zeek only after the custom detector works.

## 9. What to put in the thesis appendix

Document these items exactly:

- host hardware
- host Ubuntu version
- VM image versions
- package versions for attack and detector tools
- IP plan
- VM resource allocation
- exact commands or scripts used for each scenario
- where captures and logs are stored

## 10. Best practical thesis strategy

For your diploma, the cleanest path is:

- **core implementation:** Ubuntu host + 3 Ubuntu VMs + Python/Scapy detector + tcpdump/Wireshark
- **convenience tooling:** bettercap for fast attack execution
- **optional comparison:** Suricata or Zeek
- **optional extension:** Mininet later, only if you want a scaling/simulation section

This gives you a realistic, reproducible, and laptop-friendly setup without making the project too wide.
