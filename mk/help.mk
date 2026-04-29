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
		'                 Optional flags: ZEEK_ENABLE=0 SURICATA_ENABLE=0 DEBUG=1 PCAP=1 PORT_PCAP=1' \
		'  make smoke-test Run a short end-to-end validation of baseline and automated scenario flows' \
		'  make summarize  Summarize one run or the whole results/ directory' \
		'  make results-db Rebuild results/experiment-results.sqlite from retained run files' \
		'  make results-db-overview' \
		'                 Print the newest rows from the compact results DB' \
		'  make experiment-plan RUNS=5' \
		'                 Run the main diploma attack plan; optional SCENARIOS, SKIP, START, START_SCENARIO, SKIP_SCENARIO' \
		'  make reliability RUNS=3' \
		'                 Run thesis reliability: ARP/DNS plus focused DHCP spoofing, loss 0%..100%' \
		'  make reliability LOSS_LEVELS="70 80 90 100" RUNS=3' \
		'                 Run the thesis reliability set on selected packet-loss levels' \
		'  make reliability-arp-dns RUNS=3' \
		'                 Run only ARP/DNS reliability, loss 0%..100%' \
		'  make reliability-dhcp RUNS=3 LOSS_LEVELS="70 80 90 100"' \
		'                 Compare Detector, Zeek, and Suricata on DHCP spoofing under packet loss' \
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
		'                 Run a focused DHCP spoof verification scenario on the lab LAN' \
		'  make scenario-reliability-arp-mitm-dns LOSS=5' \
		'                 Run ARP/DNS attack through the NetEm reliability path' \
		'  make scenario-reliability-dhcp-spoof LOSS=5' \
		'                 Run DHCP spoofing through the NetEm reliability path' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'
