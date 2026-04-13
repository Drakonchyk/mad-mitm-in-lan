# Dangerous Scenarios

This directory is a deliberately marked staging area for manual high-risk lab
scenarios that should only be performed inside the isolated `mitm-lab`
environment.

What is included here:

- user-friendly wrappers for recording manual scenarios
- an isolation check before each run
- explicit confirmation prompts
- a forced `sudo` password refresh before the wrapper proceeds
- placeholders showing where your own private/manual scenario scripts would
  live

What is intentionally not included here:

- automated ARP spoofing
- automated DNS spoofing
- any script that performs poisoning, spoofing, interception, or injection

## Layout

- `Makefile` - friendly entry point
- `verify-isolated-lab.sh` - confirm the lab looks like the expected isolated setup
- `record-arp-mitm.sh` - wrapper for recording a manual ARP-focused scenario
- `record-arp-dns.sh` - wrapper for recording a manual ARP + DNS scenario
- `record-mitigation.sh` - wrapper for recording a manual mitigation scenario
- `compare-runs.sh` - quick comparison helper for saved experiment runs
- `manual-steps/` - placeholders for your own manual/private notes or scripts

## Usage

From the repository root:

```bash
make danger-help
make danger-verify
make danger-arp-mitm DURATION=90
make danger-arp-dns DURATION=90
make danger-mitigation DURATION=90
```

Or from this directory:

```bash
make help
make verify
make record-arp-mitm DURATION=90
```

Each recording wrapper:

- verifies that the VMs and networks match the expected isolated lab
- asks for your `sudo` password refresh
- asks for explicit confirmation
- starts the matching `record-scenario` run
- points you at the matching placeholder file in `manual-steps/`

