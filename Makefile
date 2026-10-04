# uspace-ansp developer targets. CI (.github/workflows/ci.yml) runs the
# same commands. On Windows set GOROOT and GO, for example:
#   make test GO=/c/Users/<you>/AppData/Local/anaconda3/bin/go
#
# bash, not /bin/sh: the recipes use pipefail, which ubuntu's dash lacks.
# -e and pipefail on every recipe line: a command that fails anywhere in
# a line, also on the left of a pipe into tee or tail, fails the target.
# Without them only the last command of a line decides.
SHELL       := bash
.SHELLFLAGS := -eo pipefail -c
GO    ?= go
PKGS  ?= ./...

# Tool versions, pinned here and mirrored in .github/workflows/ci.yml;
# change both in one `ci:` commit. The linters equal uspace-core's.
GOLANGCI_LINT_VERSION ?= v2.14.0
STATICCHECK_VERSION   ?= v0.8.1
GOVULNCHECK_VERSION   ?= v1.8.0
# The gitleaks version CI runs (GITLEAKS_VERSION in its gitleaks job).
GITLEAKS_VERSION      ?= v8.24.3

FUZZTIME ?= 10s

# Development stack (deploy/compose.yaml): random local passwords and the
# NATS keys live in local/ (git-ignored).
DEV_ENV  = local/dev.env
COMPOSE  = docker compose --env-file $(DEV_ENV) -f deploy/compose.yaml
PROJECT  = uspace-ansp
IMAGE   ?= ghcr.io/rootxkit/uspace-ansp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build vet fmt fmt-check tools staticcheck lint tidy test race cover \
        integration dss-live vectors generate generate-check lint-api check-contracts fuzz-smoke bench lint-docs vulncheck \
        secrets web-install web-lint web-test web-build web-e2e web-types image compose-up \
        compose-down ci clean

all: ci

build:
	CGO_ENABLED=0 $(GO) build $(PKGS)

vet:
	$(GO) vet $(PKGS)
	$(GO) vet -tags integration $(PKGS)

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(PKGS)

# Refuses to run a golangci-lint other than the pinned one: a different
# version enables different checks and would pass here but fail in CI.
lint: fmt-check vet staticcheck
	@v="v$$(golangci-lint version --short 2>/dev/null)"; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
	  echo "golangci-lint $$v found, CI runs $(GOLANGCI_LINT_VERSION): run 'make tools'"; exit 1; fi
	golangci-lint run $(PKGS)
	golangci-lint run --build-tags integration $(PKGS)

tidy:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

test:
	$(GO) test -count=1 -shuffle=on $(PKGS)

# The race detector needs cgo (and a C toolchain) for the test binary
# only; the shipped binaries stay CGO_ENABLED=0.
race:
	CGO_ENABLED=1 $(GO) test -race -count=1 -shuffle=on $(PKGS)

cover:
	$(GO) test -count=1 -shuffle=on -coverprofile=coverage.out -covermode=atomic $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -n 1

# Real TimescaleDB (both databases) and NATS JetStream, from
# ANSP_RELATIONAL_DSN, ANSP_TIMESERIES_DSN and ANSP_NATS_URL (CI, or
# `make compose-up`). Without them it is skipped and says so (E-04).
# With them it fails when a test fails and when zero tests ran: a suite
# that ran nothing proves nothing.
integration:
	@missing=""; for v in ANSP_RELATIONAL_DSN ANSP_TIMESERIES_DSN ANSP_NATS_URL; do \
	  if [ -z "$${!v:-}" ]; then missing="$$missing $$v"; fi; done; \
	if [ -n "$$missing" ]; then echo "integration: SKIPPED, not set:$$missing"; exit 0; fi; \
	rc=0; \
	$(GO) test -tags integration -count=1 -p 1 -run Integration -v $(PKGS) 2>&1 | tee integration.log || rc=$$?; \
	n=$$(grep -c '^--- PASS' integration.log || true); \
	f=$$(grep -c '^--- FAIL' integration.log || true); \
	echo "integration: $$n top-level tests passed, $$f failed"; \
	if [ "$$rc" -ne 0 ]; then echo "integration: go test exited $$rc"; exit "$$rc"; fi; \
	if [ "$$n" -eq 0 ]; then echo "integration: zero tests ran"; exit 1; fi

# The DSS path of WP-9 against a real InterUSS DSS. uspace-lab has no
# DSS compose yet, so this says it is skipped (E-04, PLAN section 15 row
# 41 (8)); the same path runs in make integration against the in-test
# DSS of internal/dss/dsstest.
dss-live:
	@echo "dss-live: SKIPPED, uspace-lab publishes no DSS compose yet; make integration runs the DSS path against internal/dss/dsstest"

# This repository's RunOwned vector tests (none before WP-4), then
# uspace-core's own vectors at the pinned version with this module's
# build list (docs/PLAN.md section 10).
vectors:
	$(GO) test -count=1 -run 'Vectors' $(PKGS)
	$(GO) test -count=1 -run 'Vectors' github.com/rootxkit/uspace-core/...

# oapi-codegen, opsgen and sqlc (go generate), the api/gen source hash
# and the web types (scripts/generate.sh).
generate:
	GO=$(GO) scripts/generate.sh

generate-check:
	GO=$(GO) scripts/generate-check.sh

# api/openapi.yaml lints with the pinned @redocly/cli (needs npx).
lint-api:
	scripts/lint-api.sh

# The pinned sibling OpenAPI copies and lab schemas equal their sources
# at the pinned commits (needs the network).
check-contracts:
	scripts/check-contracts.sh

fuzz-smoke:
	GO=$(GO) FUZZTIME=$(FUZZTIME) scripts/fuzz-smoke.sh

# The budgets of docs/PLAN.md section 9, reported and not gated.
bench:
	$(GO) test -run '^$$' -bench . -benchmem -count=1 $(PKGS) | tee bench.txt
	@echo "bench: $$(grep -c '^Benchmark' bench.txt || true) benchmark(s) reported"

# The Markdown checks, the only CI job a docs-only change runs.
lint-docs:
	scripts/lint-docs.sh

# Known vulnerabilities the code can reach (symbol level).
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PKGS)

# Secret scan of the history and of every file that could be committed
# (tracked or untracked, not git-ignored), with .gitleaks.toml.
secrets:
	gitleaks detect --no-banner --redact
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	git ls-files -z -co --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$$tmp"; \
	gitleaks detect --no-banner --redact --no-git --source "$$tmp"

# web/ (WP-11): the console. Node 22 and pnpm through corepack; every
# target installs nothing but web-install, which is frozen to the lockfile.
WEB_GUARD = if [ ! -f web/package.json ]; then echo "$@: SKIPPED, no web/package.json"; exit 0; fi

web-install:
	@$(WEB_GUARD); cd web && pnpm install --frozen-lockfile

# The kit's ESLint config and the three project rules (no geometry
# import, no hard-coded string, no server code outside the BFF), then
# next typegen before tsc.
web-lint:
	@$(WEB_GUARD); cd web && pnpm run lint && pnpm exec next typegen && pnpm exec tsc --noEmit

web-test:
	@$(WEB_GUARD); cd web && pnpm run test

web-build:
	@$(WEB_GUARD); cd web && pnpm exec next build && pnpm run check:bundle

# The Playwright smoke run against the fixture server (after web-build).
web-e2e:
	@$(WEB_GUARD); cd web && pnpm run e2e

# The committed API types equal what uspace-ui-gen-api makes of
# api/openapi.yaml now (a changed or a new file fails).
web-types:
	@$(WEB_GUARD); cd web && pnpm run types:check

image:
	docker build -f deploy/Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

$(DEV_ENV):
	@mkdir -p $(dir $(DEV_ENV))
	@rnd() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }; \
	echo "POSTGRES_PASSWORD=$$(rnd)" > $@
	@echo "wrote $@ (random local password)"

compose-up: $(DEV_ENV)
	scripts/nats-creds.sh
	$(COMPOSE) up -d --build --wait
	$(COMPOSE) ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'

# Removes containers, volumes and the network, then checks that nothing
# of the project is left and says so (E-02: the success path of teardown
# is verified, not assumed).
compose-down:
	@if [ -f $(DEV_ENV) ]; then $(COMPOSE) down -v --remove-orphans; \
	else docker compose -p $(PROJECT) down -v --remove-orphans; fi
	@left="$$(docker ps -aq --filter label=com.docker.compose.project=$(PROJECT))$$(docker volume ls -q --filter label=com.docker.compose.project=$(PROJECT))"; \
	if [ -n "$$left" ]; then echo "compose-down: $(PROJECT) left containers or volumes behind"; exit 1; fi; \
	echo "compose-down: no container or volume of $(PROJECT) left"

# deploy/ (WP-13): shellcheck, the production compose rendered and read
# back, and the Caddy site proved against the pinned Caddy (needs docker;
# the certificate checks need a curl that is not Schannel: Linux or WSL).
check-deploy:
	scripts/check-deploy.sh

# The stack for uspace-lab's conformance suite with lab-issued keys
# (testdata/conformance/README.md); `make compose-down` removes it.
conformance-target: $(DEV_ENV)
	scripts/conformance-target.sh

ci: lint-docs build lint tidy race generate-check lint-api check-contracts vectors fuzz-smoke bench vulncheck secrets integration web-types web-lint web-test web-build

clean:
	rm -f coverage.out integration.log bench.txt
