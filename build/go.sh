#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source build/toolchain.env
export GOCACHE="${GOCACHE:-$(pwd -P)/dist/cache/go}"
export GOMODCACHE="${GOMODCACHE:-$(pwd -P)/dist/cache/mod}"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local

# Invoke an exact, already installed toolchain without Go's download launcher.
if test "$(GOTOOLCHAIN=local go env GOVERSION)" = "$GO_TOOLCHAIN"; then
  exec env GOTOOLCHAIN=local go "$@"
fi
host_os=$(GOTOOLCHAIN=local go env GOHOSTOS)
host_arch=$(GOTOOLCHAIN=local go env GOHOSTARCH)
cached_go="$GOMODCACHE/golang.org/toolchain@v0.0.1-$GO_TOOLCHAIN.$host_os-$host_arch/bin/go"
if ! test -x "$cached_go"; then
  printf 'Exact %s is unavailable; run make prepare or use make prepare-linux.\n' "$GO_TOOLCHAIN" >&2
  exit 1
fi
exec env GOTOOLCHAIN=local "$cached_go" "$@"
