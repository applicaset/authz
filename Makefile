GO_CMD?=go

GOLANGCI_LINT_CMD?=$(GO_CMD) tool golangci-lint

.DEFAULT_GOAL := .default

.default: format build lint test

.PHONY: help
help: ## Show help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build bin/authz
	$(GO_CMD) build -o bin/ ./cmd/...

.PHONY: format
format: ## Format the code and tidy go.mod
	$(GO_CMD) fix ./...
	$(GOLANGCI_LINT_CMD) fmt ./...
	$(GO_CMD) mod tidy

.PHONY: lint
lint: ## Run the linters
	$(GOLANGCI_LINT_CMD) run ./...

.PHONY: test
test: ## Run the tests
	$(GO_CMD) test ./...
