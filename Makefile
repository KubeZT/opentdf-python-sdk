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

RUST_SDK ?= ../opentdf-rust-sdk

.PHONY: test-e2e
test-e2e:
	RUST_SDK="$(RUST_SDK)" "$(PYTHON)" -m pytest -m e2e -s tests/interop/test_e2e.py

.PHONY: test-federation
test-federation:
	RUST_SDK="$(RUST_SDK)" "$(PYTHON)" -m pytest -m e2e -k federation -s tests/interop/test_e2e.py

.PHONY: test-large
test-large:
	RUST_SDK="$(RUST_SDK)" "$(PYTHON)" -m pytest -m e2e -k large_payloads -s tests/interop/test_e2e.py
