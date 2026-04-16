.DEFAULT_GOAL := help

.PHONY: help verify record-arp-mitm record-arp-dns record-arp-mitm-auto record-arp-dns-auto record-arp-poison-no-forward-auto record-arp-dns-iana-auto record-mitigation record-mitigation-auto compare

help:
	@printf '%s\n' \
		'Dangerous Scenarios' \
		'' \
		'Targets:' \
		'  make verify                 Confirm the isolated lab looks ready' \
		'  make record-arp-mitm        Record a manual ARP MITM scenario window' \
		'  make record-arp-dns         Record a manual ARP + DNS scenario window' \
		'  make record-arp-mitm-auto   Record an automated attacker-side ARP MITM scenario window' \
		'  make record-arp-dns-auto    Record an automated attacker-side ARP + DNS scenario window' \
		'  make record-arp-poison-no-forward-auto' \
		'                              Record automated ARP poisoning without forwarding' \
		'  make record-arp-dns-iana-auto' \
		'                              Record automated ARP + DNS spoofing focused on iana.org' \
		'  make record-mitigation      Record a manual mitigation scenario window' \
		'  make record-mitigation-auto Record automated mitigation and recovery scenario window' \
		'  make compare TARGET=../results' \
		'                              Summarize saved runs'

verify:
	../shell/dangerous/verify-isolated-lab.sh

record-arp-mitm:
	../shell/dangerous/record-arp-mitm.sh "$(or $(DURATION),90)"

record-arp-dns:
	../shell/dangerous/record-arp-dns.sh "$(or $(DURATION),90)"

record-arp-mitm-auto:
	../shell/dangerous/record-arp-mitm-auto.sh "$(or $(DURATION),90)"

record-arp-dns-auto:
	../shell/dangerous/record-arp-dns-auto.sh "$(or $(DURATION),90)"

record-arp-poison-no-forward-auto:
	../shell/dangerous/record-arp-poison-no-forward-auto.sh "$(or $(DURATION),90)"

record-arp-dns-iana-auto:
	../shell/dangerous/record-arp-dns-iana-auto.sh "$(or $(DURATION),90)"

record-mitigation:
	../shell/dangerous/record-mitigation.sh "$(or $(DURATION),90)"

record-mitigation-auto:
	../shell/dangerous/record-mitigation-auto.sh "$(or $(DURATION),120)"

compare:
	../shell/dangerous/compare-runs.sh "$(or $(TARGET),../results)"
