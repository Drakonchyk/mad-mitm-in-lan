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
		'  make experiment-report' \
		'                 Build one combined report from all runs under results/' \
		'  make experiment-report-extra' \
		'                 Compatibility alias for make experiment-report' \
		'  make demo-start' \
		'                 Provision if needed and ensure the demo lab is up' \
		'  make demo-scenario DURATION=90' \
		'                 Run one focused arp-mitm-dns demo scenario (detector always on, comparators on by default)' \
		'  make demo-capture HOST=sensor IFACE=mitm-sensor0 FILTER="arp or icmp or port 53 or port 67 or port 68"' \
		'                 Open a live tcpdump capture on the mirrored switch port or on a lab VM' \
		'  make demo-report' \
		'                 Build a small deterministic report from the latest retained run per scenario' \
		'  make scenario-help' \
		'                 Show the direct automated scenario commands' \
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
		'  make scenario-intermittent-dhcp-spoof DURATION=90' \
		'                 Run pulsed rogue-DHCP spoofing windows for short-burst validation' \
		'  make scenario-dhcp-offer-only DURATION=60' \
		'                 Run rogue DHCP offer-only traffic without ACKs' \
		'  make scenario-mitigation-recovery DURATION=120' \
		'                 Run automated mitigation and recovery' \
		'  make scenario-compare TARGET=results' \
		'                 Summarize runs collected via the direct shell scenario helpers' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'
