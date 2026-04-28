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
		'                 Optional env: ZEEK_ENABLE=0 SURICATA_ENABLE=0 PCAP_ENABLE=1' \
		'  make smoke-test Run a short end-to-end validation of baseline and automated scenario flows' \
		'  make summarize  Summarize one run or the whole results/ directory' \
		'  make results-db Rebuild results/experiment-results.sqlite from retained run files' \
		'  make results-db-overview' \
		'                 Print the newest rows from the compact results DB' \
		'  make experiment-plan ARGS="--skip 2 --skip-scenario arp-mitm-forward"' \
		'                 Run the main diploma experiment plan with optional skip/start controls' \
		'  make reliability RUNS=3' \
		'                 Run thesis reliability: ARP/DNS plus focused DHCP rogue-server, loss 0%..100%' \
		'  make reliability-plan' \
		'                 Run NetEm reliability campaigns with packet loss, delay, jitter, and rate knobs' \
		'  make reliability-thesis-plan RUNS=3' \
		'                 Run ARP/DNS plus focused DHCP rogue-server reliability, loss 0%..100%' \
		'  make reliability-dhcp-rogue-plan' \
		'                 Compare Detector, Zeek, and Suricata on DHCP rogue-server packet loss from 0% to 100%' \
		'  make experiment-report' \
		'                 Build one combined report from all runs under results/' \
		'  make demo-ui PORT=8765' \
		'                 Open the localhost thesis demo dashboard with live status, logs, and scenario buttons' \
		'  make scenario-verify' \
		'                 Verify the isolated lab before an automated scenario run' \
		'  make scenario-arp-poison-no-forward DURATION=30' \
		'                 Run automated ARP poisoning without forwarding' \
		'  make scenario-arp-mitm-forward DURATION=30' \
		'                 Run automated ARP MITM with forwarding enabled' \
		'  make scenario-arp-mitm-dns DURATION=45' \
		'                 Run the canonical focused arp-mitm-dns scenario used in the plan' \
		'  make scenario-dhcp-spoof DURATION=30' \
		'                 Run a focused rogue-DHCP verification scenario on the lab LAN' \
		'  make scenario-reliability-arp-mitm-dns LOSS=5' \
		'                 Run ARP/DNS attack through the NetEm reliability path' \
		'  make scenario-reliability-dhcp-spoof LOSS=5' \
		'                 Run rogue DHCP through the NetEm reliability path' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'
