# MITM Diploma Lab

This repo builds a **safe, isolated** 3-VM libvirt lab described in
`testbed_setup_guide.md`.

- `mitm-gateway`
- `mitm-victim`
- `mitm-attacker`
- libvirt NAT network: `default`
- isolated lab network: `mitm-lab`

It also renders repeatable lab assets for:

- static guest network config
- gateway NAT and DNS forwarding
- a simple victim-side detector service
- libvirt provisioning, experiment capture, and teardown

## Important

- This project is for an **isolated local lab only**.
- It does **not** automate poisoning, spoofing, packet injection, or attack tooling.
- The scripts target system libvirt at `qemu:///system`.
- Downloaded images live under `storage/`.
- Rendered cloud-init and helper files live under `generated/`.
- Experiment artifacts are written under `results/`.
- If your shell cannot talk to system libvirt directly yet, the scripts fall back to `sg libvirt -c ...`.

## Project Layout

- `lab.conf` - main lab configuration
- `Makefile` - polished entry point for common lab tasks
- `dangerous-scenarios/` - clearly marked wrappers for recording manual high-risk lab scenarios
- `libvirt/*.xml` - network definitions
- `shell/` - Bash scripts for host orchestration plus the guest gateway bootstrap script
- `python/` - Python utilities such as the guest detector source, config helpers, and result summarization
- `services/` - static systemd unit files copied into guests
- `config/` - static config files copied into guests

## Default Network Plan

- Gateway: `10.20.20.1/24`
- Victim: `10.20.20.10/24`
- Attacker: `10.20.20.66/24`
- Victim and attacker gateway: `10.20.20.1`
- Victim and attacker DNS: `10.20.20.1`

## Host Prerequisites

Install the host packages from the guide first:

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager cpu-checker \
  wireshark tshark tcpdump python3-pip git jq curl iperf3 dnsutils
```

Recommended extra package for easier cloud image work:

```bash
sudo apt install cloud-image-utils
```

Optional host-side comparison tooling:

```bash
sudo apt install suricata
```

If `suricata` is installed and `/etc/suricata/suricata.yaml` exists, runs automatically analyze the saved `victim.pcap` and write artifacts under `results/<run>/suricata/`.
That offline pass now also generates a small lab-specific ruleset per run so Suricata can alert on ICMP redirects from the attacker and DNS answers that point to the attacker IP.

If needed, add your user to the libvirt group:

```bash
sudo adduser "$USER" libvirt
```

Then log out and back in before provisioning the lab.

## Quick Start

Run everything from the repository root:

```bash
cd /path/to/mad-mitm-in-lan
```

Review the main settings if needed:

```bash
nano lab.conf
```

See the available commands:

```bash
make help
```

Provision the full lab:

```bash
make setup
```

Check status later with:

```bash
make status
```

If direct libvirt access still fails from your current shell, log out and back in once, or use the `sg libvirt -c ...` examples below.

The repo ignores `generated/`, `storage/`, and `results/` so local lab artifacts do not clutter version control.

Useful day-to-day commands:

```bash
make prereqs
make setup
make start
make status
make baseline
make smoke-test
make evaluate
make destroy
```

Keep `SMOKE_DURATION_SECONDS` at `8` or higher. Shorter windows can miss the attack simply because the ARP poison and DNS spoof do not have enough time to become visible in the victim probes.

If you created the VMs before the automation key was added, run `make rebuild` once so the experiment scripts can SSH into the guests reproducibly.

## Experiment Workflow

The repo now automates the safe and repeatable parts of the methodology:

- `make baseline` starts the lab if needed, runs a clean traffic pass, saves packet captures plus ARP and DNS artifacts, and prints a short summary
- `make smoke-test` runs a short baseline plus short automated ARP and ARP+DNS checks to validate the end-to-end research pipeline
- `make record-scenario NAME=arp-mitm DURATION=60` opens a capture window for a manual scenario while the victim generates background traffic
- `make summarize` prints a compact summary for everything under `results/`
- `make evaluate` compares ground truth, detector alerts, and Suricata alerts for one run or a whole results tree

Key run artifacts to read first:

- `summary.txt` for top-level metrics
- `victim/detector-explained.txt` for a concise attack timeline from the detector and victim probes
- `evaluation-summary.txt` for ground-truth attack events versus detector and Suricata alert counts plus time to detection
- `evaluation.json` for machine-readable evaluation inputs
- `pcap/*.tshark-summary.txt` for quick packet-level comparisons
- `suricata/` when host-side Suricata is available

Examples:

```bash
make baseline
make smoke-test
make record-scenario NAME=arp-mitm DURATION=90 NOTE="Manual ARP MITM run in isolated lab"
make record-scenario NAME=arp-mitm-dns DURATION=90 NOTE="Manual ARP + DNS scenario in isolated lab"
make summarize
```

The attack and mitigation actions themselves are intentionally left manual inside the isolated lab, but the setup, traffic generation, capture collection, and result summaries are scripted so the runs stay reproducible.

```bash
./shell/dangerous/record-arp-mitm.sh
./shell/dangerous/record-arp-dns.sh
./shell/dangerous/record-mitigation.sh
```

## What Gets Configured

### Gateway VM

- upstream NIC on libvirt `default`
- lab NIC on `mitm-lab`
- static IP `10.20.20.1/24` on the lab NIC
- IPv4 forwarding enabled
- iptables MASQUERADE from lab to upstream
- `dnsmasq` bound to `10.20.20.1`

### Victim VM

- static IP `10.20.20.10/24`
- gateway `10.20.20.1`
- DNS `10.20.20.1`
- detector service logging JSON to `/var/log/mitm-lab-detector.jsonl`

### Attacker VM

- static IP `10.20.20.66/24`
- gateway `10.20.20.1`
- DNS `10.20.20.1`
- base lab tooling only from the guide

## Access

The default guest user is configured in `lab.conf`.

Console examples:

```bash
sg libvirt -c 'virsh -c qemu:///system console mitm-gateway'
sg libvirt -c 'virsh -c qemu:///system console mitm-victim'
sg libvirt -c 'virsh -c qemu:///system console mitm-attacker'
```

Exit a console session with:

```text
Ctrl + ]
```

## Teardown

```bash
make destroy
```

That removes the VMs, networks, libvirt storage pool, downloaded images, and the generated lab artifacts under `storage/` and `generated/`.
