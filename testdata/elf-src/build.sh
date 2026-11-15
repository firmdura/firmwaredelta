#!/usr/bin/env bash
# Copyright 2026 FirmwareDelta contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd -P)
test "$#" -eq 1 && [[ "$1" = /* ]] || {
  printf '%s\n' 'Usage: build.sh ABSOLUTE_DIST_OUTPUT_DIRECTORY' >&2
  exit 2
}
out=$(realpath -m -- "$1")
case "$out" in
  "$repo_dir/dist/"*) ;;
  *) printf '%s\n' 'ELF fixture output must be under this checkout dist/.' >&2; exit 2 ;;
esac
bash "$repo_dir/build/check-linux-toolchain.sh"
mkdir -p "$out/baseline/usr/bin" "$out/baseline/usr/lib" \
  "$out/candidate/usr/bin" "$out/candidate/usr/lib" "$out/malformed"
src="$repo_dir/testdata/elf-src"
flags=(-fno-ident "-ffile-prefix-map=$repo_dir=." -Wl,--build-id=none)

gcc "${flags[@]}" -shared -fPIC -DMAINTENANCE_VALUE=1 \
  -Wl,-soname,libmaintenance.so.1 -o "$out/baseline/usr/lib/libmaintenance.so.1" "$src/library.c"
gcc "${flags[@]}" -shared -fPIC -DMAINTENANCE_VALUE=2 \
  -Wl,-soname,libmaintenance.so.1 -o "$out/candidate/usr/lib/libmaintenance.so.1" "$src/library.c"
gcc "${flags[@]}" -shared -fPIC -Wl,-soname,libextra.so.1 \
  -o "$out/candidate/usr/lib/libextra.so.1" "$src/extra.c"
gcc "${flags[@]}" -no-pie "$src/program.c" -L "$out/baseline/usr/lib" \
  -Wl,--no-as-needed -l:libmaintenance.so.1 -Wl,-rpath,'$ORIGIN/../lib' \
  -o "$out/baseline/usr/bin/maintenance"
gcc "${flags[@]}" -no-pie -DWITH_EXTRA "$src/program.c" -L "$out/candidate/usr/lib" \
  -Wl,--no-as-needed -l:libmaintenance.so.1 -l:libextra.so.1 -Wl,-rpath,'$ORIGIN/../lib' \
  -o "$out/candidate/usr/bin/maintenance"
printf '\177ELFmalformed-original-fixture\n' > "$out/malformed/broken"

# Inspect metadata only. None of these fixture executables is ever run.
readelf -h "$out/baseline/usr/bin/maintenance" > "$out/baseline-header.txt"
readelf -d "$out/baseline/usr/bin/maintenance" > "$out/baseline-dynamic.txt"
readelf -d "$out/candidate/usr/bin/maintenance" > "$out/candidate-dynamic.txt"
readelf -d "$out/candidate/usr/lib/libextra.so.1" > "$out/library-dynamic.txt"
