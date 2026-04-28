.PHONY: summarize results-db results-db-overview overload-summary experiment-report experiment-report-extra

summarize:
	PYTHONPATH=./python python3 -m metrics.summary_cli "$(or $(TARGET),results)"

results-db:
	PYTHONPATH=./python python3 -m metrics.results_db rebuild "$(or $(TARGET),results)"

results-db-overview:
	@if ! test -f "$(or $(DB),results/experiment-results.sqlite)"; then \
		PYTHONPATH=./python python3 -m metrics.results_db rebuild "$(or $(TARGET),results)" --db "$(or $(DB),results/experiment-results.sqlite)"; \
	fi
	PYTHONPATH=./python python3 -m metrics.results_db overview --db "$(or $(DB),results/experiment-results.sqlite)"

overload-summary:
	PYTHONPATH=./python python3 -m metrics.overload_cli "$(or $(TARGET),results)"

experiment-report:
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile all --output-dir results/experiment-report

experiment-report-extra:
	@printf '%s\n' 'experiment-report-extra is now an alias of experiment-report and uses all runs under the target directory.'
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile all --output-dir results/experiment-report
