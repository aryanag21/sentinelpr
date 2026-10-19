.PHONY: install lint format test test-unit test-integration validate-sam clean scan-local

PYTHON ?= python

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --fix .

test:
	pytest

test-unit:
	pytest tests/unit/

test-integration:
	pytest tests/integration/

validate-sam:
	sam validate --template infrastructure/template.yaml

scan-local:
	sentinelpr scan --staged --offline

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
