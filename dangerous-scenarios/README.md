# Dangerous Scenarios

This directory is a deliberately marked staging area for high-risk lab
scenarios that should only be performed inside the isolated `mitm-lab`
environment.

What is included here:

- user-friendly wrappers for recording manual scenarios
- automated wrappers that run the attacker-side Python research helpers
- an isolation check before each run
- explicit confirmation prompts
- a forced `sudo` password refresh before the wrapper proceeds
- placeholders showing where your own private/manual scenario scripts would
  live
- a local `Makefile` that calls the shared shell wrappers under `../shell/dangerous/`

The automated wrappers are still scoped to this isolated lab only.

## Layout

- `Makefile` - friendly entry point
- `../shell/dangerous/verify-isolated-lab.sh` - confirm the lab looks like the expected isolated setup
- `../shell/dangerous/record-arp-mitm.sh` - wrapper for recording a manual ARP-focused scenario
- `../shell/dangerous/record-arp-dns.sh` - wrapper for recording a manual ARP + DNS scenario
- `../shell/dangerous/record-arp-mitm-auto.sh` - wrapper for recording an automated attacker-side ARP MITM scenario
- `../shell/dangerous/record-arp-dns-auto.sh` - wrapper for recording an automated attacker-side ARP + DNS scenario
- `../shell/dangerous/record-mitigation.sh` - wrapper for recording a manual mitigation scenario
- `../shell/dangerous/compare-runs.sh` - quick comparison helper for saved experiment runs
- `manual-steps/` - placeholders for your own manual/private notes or scripts

## Usage

From the repository root:

```bash
make danger-help
make danger-verify
make danger-arp-mitm DURATION=90
make danger-arp-dns DURATION=90
make danger-arp-mitm-auto DURATION=90
make danger-arp-dns-auto DURATION=90
make danger-mitigation DURATION=90
```

Or from this directory:

```bash
make help
make verify
make record-arp-mitm DURATION=90
make record-arp-mitm-auto DURATION=90
```

Each recording wrapper:

- verifies that the VMs and networks match the expected isolated lab
- asks for your `sudo` password refresh
- asks for explicit confirmation
- starts the matching `record-scenario` run
- either points you at the matching placeholder file in `manual-steps/` or launches the attacker-side Python helper under `/opt/mitm-lab`
