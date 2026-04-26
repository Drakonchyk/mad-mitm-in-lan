.PHONY: baseline smoke-test experiment-plan experiment-plan-extra visibility-plan starvation-takeover-plan demo-ui

baseline:
	./shell/experiments/run-baseline.sh

smoke-test:
	./shell/experiments/smoke-test.sh

experiment-plan:
	./shell/experiments/run-experiment-plan.sh $(ARGS)

experiment-plan-extra:
	./shell/experiments/run-supplementary-plan.sh $(ARGS)

visibility-plan:
	./shell/experiments/run-visibility-plan.sh $(ARGS)

starvation-takeover-plan:
	./shell/experiments/run-starvation-takeover-plan.sh $(ARGS)

demo-ui:
	HOST="$(or $(HOST),127.0.0.1)" PORT="$(or $(PORT),8765)" ./shell/demo/run-ui.sh
