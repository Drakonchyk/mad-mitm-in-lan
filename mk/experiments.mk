.PHONY: baseline smoke-test experiment-plan reliability reliability-arp-dns reliability-dhcp demo-ui

RUN_COUNT = $(or $(RUNS),1)
PLAN_SCENARIO_LIST = $(SCENARIOS)
PLAN_FILTER_ARGS = $(if $(SKIP),--skip "$(SKIP)") $(if $(START),--start "$(START)") $(if $(START_SCENARIO),--start-scenario "$(START_SCENARIO)") $(if $(SKIP_SCENARIO),--skip-scenario "$(SKIP_SCENARIO)")
RELIABILITY_LEVEL_ARGS = $(if $(LOSS_LEVELS),--loss-levels "$(LOSS_LEVELS)")
COMMON_RUN_ENV = \
	$(if $(filter 1 true on,$(DEBUG)),DEBUG="$(DEBUG)") \
	$(if $(PCAP),PCAP="$(PCAP)") \
	$(if $(PORT_PCAP),PORT_PCAP="$(PORT_PCAP)") \
	$(if $(GUEST_PCAP),GUEST_PCAP="$(GUEST_PCAP)") \
	$(if $(PCAP_SUMMARIES),PCAP_SUMMARIES="$(PCAP_SUMMARIES)")
NETEM_ENV = \
	$(if $(DELAY_MS),DELAY_MS="$(DELAY_MS)") \
	$(if $(JITTER_MS),JITTER_MS="$(JITTER_MS)") \
	$(if $(RATE),RATE="$(RATE)") \
	$(if $(DUPLICATE_PERCENT),DUPLICATE_PERCENT="$(DUPLICATE_PERCENT)") \
	$(if $(REORDER_PERCENT),REORDER_PERCENT="$(REORDER_PERCENT)") \
	$(if $(CORRUPT_PERCENT),CORRUPT_PERCENT="$(CORRUPT_PERCENT)")

baseline:
	$(COMMON_RUN_ENV) ./shell/experiments/run-baseline.sh

smoke-test:
	$(COMMON_RUN_ENV) ./shell/experiments/smoke-test.sh

experiment-plan:
	$(COMMON_RUN_ENV) $(if $(PLAN_SCENARIO_LIST),SCENARIOS="$(PLAN_SCENARIO_LIST)") ./shell/experiments/run-experiment-plan.sh --runs "$(RUN_COUNT)" $(PLAN_FILTER_ARGS) $(ARGS)

reliability:
	$(COMMON_RUN_ENV) $(NETEM_ENV) ./shell/experiments/run-reliability-plan.sh --thesis --runs "$(RUN_COUNT)" $(RELIABILITY_LEVEL_ARGS) $(ARGS)

reliability-arp-dns:
	$(COMMON_RUN_ENV) $(NETEM_ENV) ./shell/experiments/run-reliability-plan.sh --arp-dns-only --runs "$(RUN_COUNT)" $(RELIABILITY_LEVEL_ARGS) $(ARGS)

reliability-dhcp:
	$(COMMON_RUN_ENV) $(NETEM_ENV) ./shell/experiments/run-reliability-plan.sh --dhcp-only --runs "$(RUN_COUNT)" $(RELIABILITY_LEVEL_ARGS) $(ARGS)

demo-ui:
	HOST="$(or $(HOST),127.0.0.1)" PORT="$(or $(PORT),8765)" ./shell/demo/run-ui.sh
