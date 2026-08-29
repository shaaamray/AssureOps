.PHONY: help dev test cover lint security demo clean all

help:
	@echo "dev       install with development extras"
	@echo "test      run the test suite"
	@echo "cover     run the suite with a coverage report"
	@echo "lint      run ruff"
	@echo "security  run bandit"
	@echo "demo      run the full pipeline against the sample data"
	@echo "all       lint, security and cover"

dev:
	pip install -e ".[dev]"

test:
	pytest

cover:
	pytest --cov=assureops --cov-report=term-missing --cov-report=html

lint:
	ruff check src tests

security:
	bandit -q -r src/assureops

demo:
	assureops assess \
	  --config config/assureops.example.yaml \
	  --vendors config/samples/vendors.csv \
	  --answers config/samples/answers.csv \
	  --observations config/samples/observations.json \
	  --findings config/samples/findings.csv \
	  --as-of 2026-08-22 \
	  --i-am-authorised \
	  --report var/reports || true
	assureops access-review \
	  --config config/assureops.example.yaml \
	  --entitlements config/samples/entitlements.csv \
	  --as-of 2026-08-22 || true
	assureops audit verify --path var/audit/assureops_audit.jsonl

all: lint security cover

clean:
	rm -rf var .pytest_cache .coverage htmlcov build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
