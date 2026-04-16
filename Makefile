.DEFAULT_GOAL := help

.PHONY: help prereqs networks storage render create-vms start status baseline smoke-test record-scenario summarize evaluate danger-help danger-verify danger-arp-mitm danger-arp-dns danger-arp-mitm-auto danger-arp-dns-auto danger-mitigation danger-compare setup destroy rebuild

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
		'  make smoke-test Run a short end-to-end validation of baseline and automated dangerous flows' \
		'  make record-scenario NAME=arp-mitm DURATION=60' \
		'                 Record a time-boxed manual scenario with captures and logs' \
		'  make summarize  Summarize one run or the whole results/ directory' \
		'  make evaluate   Compare ground truth, detector alerts, and Suricata alerts' \
		'  make danger-help' \
		'                 Show wrappers for manually executed high-risk lab scenarios' \
		'  make danger-verify' \
		'                 Verify the isolated lab before a manual scenario window' \
		'  make danger-arp-mitm DURATION=90' \
		'                 Record a manual ARP-focused scenario window' \
		'  make danger-arp-dns DURATION=90' \
		'                 Record a manual ARP + DNS scenario window' \
		'  make danger-arp-mitm-auto DURATION=90' \
		'                 Record an automated attacker-side ARP MITM scenario window' \
		'  make danger-arp-dns-auto DURATION=90' \
		'                 Record an automated attacker-side ARP + DNS scenario window' \
		'  make danger-mitigation DURATION=90' \
		'                 Record a manual mitigation scenario window' \
		'  make danger-compare TARGET=results' \
		'                 Summarize runs collected via dangerous-scenarios helpers' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'

prereqs:
	./shell/00-host-prereqs.sh

networks:
	./shell/10-define-networks.sh

storage:
	./shell/20-prepare-storage.sh

render:
	./shell/30-build-cloud-init.sh

create-vms:
	./shell/40-create-vms.sh

start:
	./shell/50-start-lab.sh

status:
	./shell/60-status.sh

baseline:
	./shell/70-run-baseline.sh

smoke-test:
	./shell/75-smoke-test.sh

record-scenario:
	./shell/80-record-manual-scenario.sh "$(or $(NAME),manual-scenario)" "$(or $(DURATION),60)" "$(NOTE)"

summarize:
	python3 ./python/summarize_results.py "$(or $(TARGET),results)"

evaluate:
	python3 ./python/evaluate_run.py "$(or $(TARGET),results)"

danger-help:
	$(MAKE) -C dangerous-scenarios help

danger-verify:
	$(MAKE) -C dangerous-scenarios verify

danger-arp-mitm:
	$(MAKE) -C dangerous-scenarios record-arp-mitm DURATION="$(or $(DURATION),90)"

danger-arp-dns:
	$(MAKE) -C dangerous-scenarios record-arp-dns DURATION="$(or $(DURATION),90)"

danger-arp-mitm-auto:
	$(MAKE) -C dangerous-scenarios record-arp-mitm-auto DURATION="$(or $(DURATION),90)"

danger-arp-dns-auto:
	$(MAKE) -C dangerous-scenarios record-arp-dns-auto DURATION="$(or $(DURATION),90)"

danger-mitigation:
	$(MAKE) -C dangerous-scenarios record-mitigation DURATION="$(or $(DURATION),90)"

danger-compare:
	$(MAKE) -C dangerous-scenarios compare TARGET="$(or $(TARGET),../results)"

setup:
	./shell/setup-all.sh

destroy:
	./shell/90-destroy-lab.sh

rebuild:
	./shell/90-destroy-lab.sh
	./shell/setup-all.sh
