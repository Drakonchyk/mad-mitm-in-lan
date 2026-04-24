.PHONY: scenario-help scenario-verify scenario-arp-poison-no-forward scenario-arp-mitm-forward scenario-arp-mitm-dns scenario-dhcp-spoof scenario-intermittent-dhcp-spoof scenario-dhcp-offer-only scenario-mitigation-recovery scenario-compare

scenario-help:
	@printf '%s\n' \
		'Scenario Commands' \
		'' \
		'  make scenario-verify' \
		'  make scenario-arp-poison-no-forward DURATION=90' \
		'  make scenario-arp-mitm-forward DURATION=90' \
		'  make scenario-arp-mitm-dns DURATION=90' \
		'  make scenario-dhcp-spoof DURATION=60' \
		'  make scenario-intermittent-dhcp-spoof DURATION=90' \
		'  make scenario-dhcp-offer-only DURATION=60' \
		'  make scenario-mitigation-recovery DURATION=120' \
		'  make scenario-compare TARGET=results'

scenario-verify:
	./shell/scenarios/verify-isolated-lab.sh

scenario-arp-poison-no-forward:
	./shell/scenarios/record-arp-poison-no-forward.sh "$(or $(DURATION),90)"

scenario-arp-mitm-forward:
	./shell/scenarios/record-arp-mitm-forward.sh "$(or $(DURATION),90)"

scenario-arp-mitm-dns:
	./shell/scenarios/record-arp-mitm-dns.sh "$(or $(DURATION),90)"

scenario-dhcp-spoof:
	./shell/scenarios/record-dhcp-spoof.sh "$(or $(DURATION),60)"

scenario-intermittent-dhcp-spoof:
	./shell/scenarios/record-intermittent-dhcp-spoof.sh "$(or $(DURATION),90)"

scenario-dhcp-offer-only:
	./shell/scenarios/record-dhcp-offer-only.sh "$(or $(DURATION),60)"

scenario-mitigation-recovery:
	./shell/scenarios/record-mitigation-recovery.sh "$(or $(DURATION),120)"

scenario-compare:
	./shell/scenarios/compare-runs.sh "$(or $(TARGET),results)"
