#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source build/toolchain.env
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 || {
  printf '%s\n' 'The pinned compiler requires Linux amd64; use the documented container.' >&2
  exit 1
}
test "$(go env GOVERSION)" = "$GO_TOOLCHAIN"
test "$(gcc -dumpfullversion)" = "$GCC_VERSION"
test "$(dpkg-query -W -f='${Version}' gcc-12)" = "$GCC_PACKAGE_VERSION"
test "$(dpkg-query -W -f='${Version}' binutils)" = "$BINUTILS_PACKAGE_VERSION"
