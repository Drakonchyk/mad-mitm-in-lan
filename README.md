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
- libvirt provisioning and teardown

## Important

- This project is for an **isolated local lab only**.
- It does **not** automate poisoning, spoofing, packet injection, or attack tooling.
- The scripts target system libvirt at `qemu:///system`.
- Downloaded images live under `storage/`.
- Rendered cloud-init and helper files live under `generated/`.
- If your shell cannot talk to system libvirt directly yet, the scripts fall back to `sg libvirt -c ...`.

## Project Layout

- `lab.conf` - main lab configuration
- `libvirt/*.xml` - network definitions
- `scripts/setup-all.sh` - full setup flow
- `scripts/60-status.sh` - current lab status
- `scripts/90-destroy-lab.sh` - teardown

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

Provision the full lab:

```bash
./scripts/setup-all.sh
```

Check status later with:

```bash
./scripts/60-status.sh
```

If direct libvirt access still fails from your current shell, log out and back in once, or use the `sg libvirt -c ...` examples below.

The repo ignores `generated/` and `storage/` so local lab artifacts do not clutter version control.

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
./scripts/90-destroy-lab.sh
```

That removes the VMs, networks, and overlay disks created by this project while leaving the downloaded base image in place.
