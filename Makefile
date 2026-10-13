# bwgate — build and test helpers
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-race e2e smoke-build docker tidy clean

build: ## Build a static binary into ./bwgate
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bwgate ./cmd/bwgate

test: ## Unit tests
	go test ./...

test-race: ## Unit tests with the race detector
	go test -race ./...

e2e: ## End-to-end tests (needs VW_BASE pointing at a running Vaultwarden)
	VW_BASE=$${VW_BASE:-http://127.0.0.1:8111} go test -tags e2e ./test/e2e/ -v

smoke-build: ## Build smoke harness (seed + auto-allow mock Telegram) and smoke client into bin/
	go build -tags smoke -o bin/ ./test/e2e/cmd/...

docker: ## Build the Alpine image
	docker build --build-arg VERSION=$(VERSION) -t bwgate:$(VERSION) .

tidy:
	go mod tidy

clean:
	rm -f bwgate
