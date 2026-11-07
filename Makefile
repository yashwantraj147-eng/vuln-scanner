.PHONY: help install test coverage lint format docker-build clean

PYTHON ?= python
PIP ?= pip
PYTEST ?= pytest

help:
	@echo "VulnScanner — Industry-Grade Automation Commands"
	@echo "------------------------------------------------"
	@echo "  make install       Install dependencies in editable mode"
	@echo "  make test          Run pytest test suite"
	@echo "  make coverage      Run tests and display coverage report"
	@echo "  make lint          Run Ruff linter check"
	@echo "  make format        Format code using Ruff"
	@echo "  make docker-build  Build production Docker image"
	@echo "  make clean         Remove build, cache, and test artifacts"

install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

test:
	$(PYTEST) -v

coverage:
	$(PYTEST) -v --cov=scanner --cov=cve_matcher --cov=report_generator --cov-report=term-missing tests/

lint:
	ruff check .

format:
	ruff format .

docker-build:
	docker build -t vulnscanner:latest .

clean:
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info 2>/dev/null || true

