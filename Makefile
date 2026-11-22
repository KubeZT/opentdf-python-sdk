PYTHON ?= python

.PHONY: check format test package

check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy
	$(PYTHON) -m pytest

format:
	$(PYTHON) -m ruff format .

test:
	$(PYTHON) -m pytest

package:
	$(PYTHON) -m build --no-isolation
