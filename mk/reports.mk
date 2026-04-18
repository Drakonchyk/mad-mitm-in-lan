.PHONY: summarize experiment-report experiment-report-extra demo-report

summarize:
	PYTHONPATH=./python python3 -m metrics.summary_cli "$(or $(TARGET),results)"

experiment-report:
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)"

experiment-report-extra:
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile supplementary --output-dir results/experiment-report-extra

demo-report:
	./shell/tools/build-demo-report.sh "$(or $(TARGET),results)" "results/demo-report"
