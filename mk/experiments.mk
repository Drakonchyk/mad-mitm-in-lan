.PHONY: baseline smoke-test experiment-plan experiment-plan-extra reliability reliability-plan reliability-thesis-plan reliability-dhcp-rogue-plan demo-ui

baseline:
	./shell/experiments/run-baseline.sh

smoke-test:
	./shell/experiments/smoke-test.sh

experiment-plan:
	./shell/experiments/run-experiment-plan.sh --runs "$(or $(MEASURED_RUNS),$(or $(RUNS),$(or $(REPS),1)))" $(ARGS)

experiment-plan-extra:
	./shell/experiments/run-supplementary-plan.sh $(ARGS)

reliability-plan:
	./shell/experiments/run-reliability-plan.sh $(ARGS)

reliability:
	./shell/experiments/run-reliability-plan.sh --thesis --runs "$(or $(RUNS),$(or $(REPS),1))" $(if $(LOSS_LEVELS),--loss-levels "$(LOSS_LEVELS)") $(ARGS)

reliability-thesis-plan:
	./shell/experiments/run-reliability-plan.sh --thesis --runs "$(or $(RUNS),$(or $(REPS),1))" $(if $(LOSS_LEVELS),--loss-levels "$(LOSS_LEVELS)") $(ARGS)

reliability-dhcp-rogue-plan:
	./shell/experiments/run-reliability-plan.sh --dhcp-rogue-only --runs "$(or $(RUNS),$(or $(REPS),1))" $(if $(LOSS_LEVELS),--loss-levels "$(LOSS_LEVELS)") $(ARGS)

demo-ui:
	HOST="$(or $(HOST),127.0.0.1)" PORT="$(or $(PORT),8765)" ./shell/demo/run-ui.sh
