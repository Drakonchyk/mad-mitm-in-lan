.DEFAULT_GOAL := help

.PHONY: help verify record-arp-mitm record-arp-dns record-mitigation compare

help:
	@printf '%s\n' \
		'Dangerous Scenarios' \
		'' \
		'Targets:' \
		'  make verify                 Confirm the isolated lab looks ready' \
		'  make record-arp-mitm        Record a manual ARP MITM scenario window' \
		'  make record-arp-dns         Record a manual ARP + DNS scenario window' \
		'  make record-mitigation      Record a manual mitigation scenario window' \
		'  make compare TARGET=../results' \
		'                              Summarize saved runs'

verify:
	./verify-isolated-lab.sh

record-arp-mitm:
	./record-arp-mitm.sh "$(or $(DURATION),90)"

record-arp-dns:
	./record-arp-dns.sh "$(or $(DURATION),90)"

record-mitigation:
	./record-mitigation.sh "$(or $(DURATION),90)"

compare:
	./compare-runs.sh "$(or $(TARGET),../results)"
