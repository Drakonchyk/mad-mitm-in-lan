.PHONY: baseline smoke-test experiment-plan experiment-plan-extra reliability reliability-plan reliability-thesis-plan reliability-dhcp-rogue-plan overload-plan overload-plan-huge overload-plan-blast demo-ui

baseline:
	./shell/experiments/run-baseline.sh

smoke-test:
	./shell/experiments/smoke-test.sh

experiment-plan:
	./shell/experiments/run-experiment-plan.sh $(ARGS)

experiment-plan-extra:
	./shell/experiments/run-supplementary-plan.sh $(ARGS)

reliability-plan:
	./shell/experiments/run-reliability-plan.sh $(ARGS)

reliability:
	./shell/experiments/run-reliability-plan.sh --thesis --runs "$(or $(RUNS),$(or $(REPS),1))" $(ARGS)

reliability-thesis-plan:
	./shell/experiments/run-reliability-plan.sh --thesis --runs "$(or $(RUNS),$(or $(REPS),1))" $(ARGS)

reliability-dhcp-rogue-plan:
	./shell/experiments/run-reliability-plan.sh --dhcp-rogue-only --runs "$(or $(RUNS),$(or $(REPS),1))" $(ARGS)

overload-plan:
	./shell/experiments/run-overload-plan.sh $(ARGS)

overload-plan-huge:
	./shell/experiments/run-overload-plan.sh --preset huge $(ARGS)

overload-plan-blast:
	./shell/experiments/run-overload-plan.sh --preset blast $(ARGS)

demo-ui:
	HOST="$(or $(HOST),127.0.0.1)" PORT="$(or $(PORT),8765)" ./shell/demo/run-ui.sh
