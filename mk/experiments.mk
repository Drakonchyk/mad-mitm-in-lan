.PHONY: baseline smoke-test experiment-plan experiment-plan-extra demo-start demo-scenario demo-capture demo-ui

baseline:
	./shell/experiments/run-baseline.sh

smoke-test:
	./shell/experiments/smoke-test.sh

experiment-plan:
	./shell/experiments/run-experiment-plan.sh $(ARGS)

experiment-plan-extra:
	./shell/experiments/run-supplementary-plan.sh $(ARGS)

demo-start:
	./shell/lab/setup-lab.sh

demo-scenario:
	$(MAKE) scenario-arp-mitm-dns DURATION="$(or $(DURATION),90)"

demo-capture:
	./shell/tools/open-live-capture.sh "$(or $(HOST),victim)" "$(or $(IFACE),)" "$(or $(FILTER),arp or icmp or port 53)"

demo-ui:
	HOST="$(or $(HOST),127.0.0.1)" PORT="$(or $(PORT),8765)" ./shell/demo/run-ui.sh
