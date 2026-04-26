.PHONY: summarize experiment-report experiment-report-extra

summarize:
	PYTHONPATH=./python python3 -m metrics.summary_cli "$(or $(TARGET),results)"

experiment-report:
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile all --output-dir results/experiment-report

experiment-report-extra:
	@printf '%s\n' 'experiment-report-extra is now an alias of experiment-report and uses all runs under the target directory.'
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile all --output-dir results/experiment-report
