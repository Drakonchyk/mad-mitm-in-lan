.PHONY: scenario-verify scenario-arp-poison-no-forward scenario-arp-mitm-forward scenario-arp-mitm-dns scenario-dhcp-spoof scenario-dhcp-starvation scenario-dhcp-starvation-rogue-dhcp scenario-visibility-arp-mitm-dns scenario-visibility-dhcp-spoof scenario-mitigation-recovery

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

scenario-dhcp-starvation:
	./shell/scenarios/record-dhcp-starvation.sh "$(or $(DURATION),60)" "$(or $(WORKERS),1)"

scenario-dhcp-starvation-rogue-dhcp:
	./shell/scenarios/record-dhcp-starvation-rogue-dhcp.sh "$(or $(DURATION),90)" "$(or $(WORKERS),1)" "$(or $(TAKEOVER),1)"

scenario-visibility-arp-mitm-dns:
	./shell/scenarios/record-visibility-arp-mitm-dns.sh "$(or $(DURATION),90)" "$(or $(VISIBILITY),100)"

scenario-visibility-dhcp-spoof:
	./shell/scenarios/record-visibility-dhcp-spoof.sh "$(or $(DURATION),60)" "$(or $(VISIBILITY),100)"

scenario-mitigation-recovery:
	./shell/scenarios/record-mitigation-recovery.sh "$(or $(DURATION),120)"
