include build/toolchain.env

GO ?= bash build/go.sh
BOOTSTRAP_GO ?= go
export GOTOOLCHAIN := local
export CC := gcc
export GOPROXY := off
export GOSUMDB := off
GO_BUILD_CACHE ?= $(CURDIR)/dist/cache/go
export GOCACHE := $(GO_BUILD_CACHE)
export GOMODCACHE := $(CURDIR)/dist/cache/mod

.PHONY: prepare prepare-linux toolchain-check format-check validate-schemas verify acceptance acceptance-linux verify-linux foundation-linux compiler-check compiler-probe elf-fixtures build demo demo-linux library library-linux package package-linux

# Network-enabled setup; verification recipes below cannot download modules.
prepare:
	@mkdir -p dist/cache/go dist/cache/mod
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org $(BOOTSTRAP_GO) mod download all

prepare-linux:
	bash build/linux.sh prepare

toolchain-check:
	@test "$$($(GO) env GOVERSION)" = "$(GO_TOOLCHAIN)" || { printf '%s\n' 'Exact $(GO_TOOLCHAIN) is required; run make prepare or use make prepare-linux.' >&2; exit 1; }

format-check:
	@gofmt_cmd="$$($(GO) env GOROOT)/bin/gofmt"; \
	unformatted=$$(find . -type d \( -name .git -o -name dist \) -prune -o -type f -name '*.go' -exec "$$gofmt_cmd" -l {} +); \
	test -z "$$unformatted" || { printf 'Run gofmt on:\n%s\n' "$$unformatted" >&2; exit 1; }

validate-schemas: toolchain-check
	$(GO) test ./internal/model -run TestContractSchemas -count=1

verify: toolchain-check format-check
	$(GO) vet ./...
	$(GO) test -race ./... -count=1

acceptance: toolchain-check
	@test -f scripts/acceptance.sh || { printf '%s\n' 'Acceptance is unavailable: scripts/acceptance.sh has not been implemented.' >&2; exit 1; }
	bash scripts/acceptance.sh

verify-linux:
	bash build/linux.sh verify

acceptance-linux:
	bash build/linux.sh acceptance

# Narrow contract/toolchain check; full product acceptance uses verify-linux.
foundation-linux:
	bash build/linux.sh foundation

compiler-check:
	bash build/check-linux-toolchain.sh

compiler-probe: compiler-check
	bash build/compiler-probe.sh

elf-fixtures: compiler-check
	@test -f testdata/elf-src/build.sh || { printf '%s\n' 'ELF fixtures are unavailable: testdata/elf-src/build.sh has not been implemented.' >&2; exit 1; }
	bash testdata/elf-src/build.sh "$(CURDIR)/dist/elf-fixtures"

build: toolchain-check
	@test -d cmd/firmwaredelta || { printf '%s\n' 'CLI build is unavailable: cmd/firmwaredelta has not been implemented.' >&2; exit 1; }
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o dist/firmwaredelta ./cmd/firmwaredelta

package: toolchain-check
	@test -f scripts/package.sh || { printf '%s\n' 'Packaging is unavailable: scripts/package.sh has not been implemented.' >&2; exit 1; }
	bash scripts/package.sh

demo:
	@test -f examples/demo/prepare.sh || { printf '%s\n' 'Demo is unavailable: examples/demo/prepare.sh has not been implemented.' >&2; exit 1; }
	bash examples/demo/prepare.sh "$(CURDIR)/dist/demo"

demo-linux:
	bash build/linux.sh demo

library: toolchain-check
	$(GO) run ./examples/library

library-linux:
	bash build/linux.sh library

package-linux:
	bash build/linux.sh package
