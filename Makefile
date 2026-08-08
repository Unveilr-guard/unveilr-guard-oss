# SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
# SPDX-License-Identifier: AGPL-3.0-only

GO      ?= go
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/unveilr/unveilr-guard/internal/version.Version=$(VERSION)

.DEFAULT_GOAL := check

.PHONY: build
build: ## Build the unveilr binary into ./bin
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/unveilr ./cmd/unveilr

.PHONY: test
test: ## Run all tests with the race detector
	$(GO) test -race $(PKG)

.PHONY: conformance
conformance: ## Cross-engine effect-combination conformance (see conformance/README.md)
	# The whole package, not a -run filter: a name-based filter silently drops
	# any test whose name stops matching, which is how a conformance suite
	# quietly stops conforming.
	$(GO) test -v -count=1 ./pkg/schema/

.PHONY: fuzz
fuzz: ## Short fuzz run over the offline detector
	$(GO) test -run '^$$' -fuzz FuzzScan -fuzztime 30s ./internal/scanner/detect/

.PHONY: fmt
fmt: ## Rewrite source with gofmt
	gofmt -w .

.PHONY: lint
lint: ## gofmt check + go vet
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet $(PKG)

.PHONY: license-check
license-check: ## ADR-007: the AGPL binary must not import proprietary Unveilr code
	bash scripts/check-no-proprietary-imports.sh

.PHONY: check
check: lint test license-check ## Everything CI runs
	@echo "ok"

.PHONY: help
help:
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
