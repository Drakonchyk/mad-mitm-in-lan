.PHONY: summarize results-db results-db-overview experiment-report

summarize:
	PYTHONPATH=./python python3 -m metrics.summary_cli "$(or $(TARGET),results)"

results-db:
	PYTHONPATH=./python python3 -m metrics.results_db rebuild "$(or $(TARGET),results)"

results-db-overview:
	@if ! test -f "$(or $(DB),results/experiment-results.sqlite)"; then \
		PYTHONPATH=./python python3 -m metrics.results_db rebuild "$(or $(TARGET),results)" --db "$(or $(DB),results/experiment-results.sqlite)"; \
	fi
	PYTHONPATH=./python python3 -m metrics.results_db overview --db "$(or $(DB),results/experiment-results.sqlite)"

experiment-report:
	PYTHONPATH=./python python3 -m reporting.cli "$(or $(TARGET),results)" --profile all --output-dir results/experiment-report
