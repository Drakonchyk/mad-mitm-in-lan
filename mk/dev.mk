.PHONY: check lint

PYTHON_SOURCES := python
SHELL_SOURCES := shell
RUFF := $(shell command -v ruff 2>/dev/null || [ ! -x .venv/bin/ruff ] || printf '%s\n' .venv/bin/ruff)

check:
	python3 -m compileall -q $(PYTHON_SOURCES)
	find $(SHELL_SOURCES) -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n

lint:
	@if [ -z "$(RUFF)" ]; then \
		printf '%s\n' 'Ruff is not installed. Install it with:'; \
		printf '%s\n' '  python3 -m venv .venv'; \
		printf '%s\n' '  . .venv/bin/activate'; \
		printf '%s\n' '  pip install -r requirements-dev.txt'; \
		exit 127; \
	fi
	$(RUFF) check $(PYTHON_SOURCES)
