# Makefile for the SCANOSS open crypto detection rules
#
# Targets for testing the Semgrep/OpenGrep cryptographic detection rules.
# See TESTING.md for the full testing guide.

.PHONY: help

.DEFAULT_GOAL := help

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test-deps: ## Install Python test dependencies
	@echo "Installing Python test dependencies..."
	@pip install -q -r tests/requirements.txt
	@echo "Dependencies installed!"

test: test-deps ## Run all tests
	@echo "Running tests with opengrep..."
	@cd tests && python -m pytest -v --tb=short

test-parallel: test-deps ## Run tests in parallel (all CPU cores)
	@echo "Running tests in parallel..."
	@cd tests && python -m pytest -v -n auto --tb=short

test-quick: test-deps ## Run a quick subset of tests
	@echo "Running quick test subset..."
	@cd tests && python -m pytest -v -k "aes or md5" --maxfail=5 --tb=line

test-debug: test-deps ## Run tests with verbose output for debugging
	@echo "Running tests with debug output..."
	@cd tests && python -m pytest -v -s --tb=long

docker-build-test: ## Build the Docker test image
	@echo "Building Docker test image..."
	@docker build -f Dockerfile.test -t crypto-rules-test:latest .
	@echo "Docker test image built successfully!"

docker-test: docker-build-test ## Run tests in a Docker container
	@echo "============================================"
	@echo "Running tests in Docker"
	@echo "============================================"
	@docker run --rm crypto-rules-test:latest

docker-shell: docker-build-test ## Open an interactive shell in the test container
	@echo "Opening shell in test container..."
	@docker run --rm -it crypto-rules-test:latest /bin/bash

docker-clean: ## Remove Docker test images
	@echo "Removing Docker test images..."
	@docker rmi crypto-rules-test:latest 2>/dev/null || true
	@echo "Docker images cleaned!"
