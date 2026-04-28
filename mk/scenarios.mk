.PHONY: scenario-verify scenario-arp-poison-no-forward scenario-arp-mitm-forward scenario-arp-mitm-dns scenario-dhcp-spoof scenario-reliability-arp-mitm-dns scenario-reliability-dhcp-spoof

scenario-verify:
	./shell/scenarios/verify-isolated-lab.sh

scenario-arp-poison-no-forward:
	./shell/scenarios/record-arp-poison-no-forward.sh "$(or $(DURATION),30)"

scenario-arp-mitm-forward:
	./shell/scenarios/record-arp-mitm-forward.sh "$(or $(DURATION),30)"

scenario-arp-mitm-dns:
	./shell/scenarios/record-arp-mitm-dns.sh "$(or $(DURATION),45)"

scenario-dhcp-spoof:
	./shell/scenarios/record-dhcp-spoof.sh "$(or $(DURATION),30)"

scenario-reliability-arp-mitm-dns:
	./shell/scenarios/record-reliability-arp-mitm-dns.sh "$(or $(DURATION),30)" "$(or $(LOSS),0)"

scenario-reliability-dhcp-spoof:
	./shell/scenarios/record-reliability-dhcp-spoof.sh "$(or $(DURATION),20)" "$(or $(LOSS),0)"
