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
		'                 Optional env: ZEEK_ENABLE=1 SURICATA_ENABLE=1 PCAP_ENABLE=0' \
		'  make smoke-test Run a short end-to-end validation of baseline and automated scenario flows' \
		'  make summarize  Summarize one run or the whole results/ directory' \
		'  make experiment-plan ARGS="--skip 2 --skip-scenario baseline"' \
		'                 Run the main diploma experiment plan with optional skip/start controls' \
		'  make experiment-plan-extra ARGS="--skip 1"' \
		'                 Run supplementary scenarios separately from the main thesis dataset' \
		'  make experiment-report' \
		'                 Export CSV/JSON data, figures, tables, and report markdown from results/' \
		'  make experiment-report-extra' \
		'                 Export CSV/JSON data, figures, tables, and report markdown for supplementary runs' \
		'  make demo-start' \
		'                 Provision if needed and ensure the demo lab is up' \
		'  make demo-scenario DURATION=90' \
		'                 Run one focused arp-mitm-dns demo scenario (detector always on, comparators optional)' \
		'  make demo-capture HOST=victim IFACE=vnic0 FILTER="arp or icmp or port 53"' \
		'                 Open a live tcpdump capture on a lab VM for the demo path' \
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
		'  make scenario-mitigation-recovery DURATION=120' \
		'                 Run automated mitigation and recovery' \
		'  make scenario-compare TARGET=results' \
		'                 Summarize runs collected via the direct shell scenario helpers' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'
