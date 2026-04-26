.PHONY: help

help:
	@printf '%s\n' \
		'MITM Diploma Lab' \
		'' \
		'Targets:' \
		'  make prereqs    Check host prerequisites and libvirt access' \
		'  make networks   Define and start libvirt networks' \
		'  make storage    Download base image and prepare storage pool' \
		'  make render     Generate cloud-init guest files' \
		'  make create-vms Create the lab virtual machines' \
		'  make start      Start all lab VMs' \
		'  make status     Show lab status and console hints' \
		'  make baseline   Run an automated clean-traffic experiment and collect artifacts' \
		'                 Optional env: ZEEK_ENABLE=0 SURICATA_ENABLE=0 PCAP_ENABLE=0' \
		'  make smoke-test Run a short end-to-end validation of baseline and automated scenario flows' \
		'  make summarize  Summarize one run or the whole results/ directory' \
		'  make experiment-plan ARGS="--skip 2 --skip-scenario baseline"' \
		'                 Run the main diploma experiment plan with optional skip/start controls' \
		'  make experiment-plan-extra ARGS="--skip 1"' \
		'                 Run supplementary scenarios separately from the main thesis dataset' \
		'  make visibility-plan' \
		'                 Run the automated packet-visibility degradation campaign' \
		'  make starvation-takeover-plan' \
		'                 Run DHCP starvation worker scaling with lease logging and rogue-DHCP takeover probes' \
		'  make experiment-report' \
		'                 Build one combined report from all runs under results/' \
		'  make experiment-report-extra' \
		'                 Compatibility alias for make experiment-report' \
		'  make demo-ui PORT=8765' \
		'                 Open the localhost thesis demo dashboard with live status, logs, and scenario buttons' \
		'  make scenario-verify' \
		'                 Verify the isolated lab before an automated scenario run' \
		'  make scenario-arp-poison-no-forward DURATION=90' \
		'                 Run automated ARP poisoning without forwarding' \
		'  make scenario-arp-mitm-forward DURATION=90' \
		'                 Run automated ARP MITM with forwarding enabled' \
		'  make scenario-arp-mitm-dns DURATION=90' \
		'                 Run the canonical focused arp-mitm-dns scenario used in the plan' \
		'  make scenario-dhcp-spoof DURATION=60' \
		'                 Run a focused rogue-DHCP verification scenario on the lab LAN' \
		'  make scenario-dhcp-starvation DURATION=60 WORKERS=1' \
		'                 Run focused DHCP starvation with a selected number of spoofing workers' \
		'  make scenario-dhcp-starvation-rogue-dhcp DURATION=90 WORKERS=32 TAKEOVER=1' \
		'                 Run starvation lease logging, optionally with reactive rogue DHCP takeover' \
		'  make scenario-mitigation-recovery DURATION=120' \
		'                 Run automated mitigation and recovery' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'
