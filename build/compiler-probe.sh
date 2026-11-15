#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist/compiler-probe
gcc -Wall -Wextra -Werror -Wl,--build-id=none \
  -o dist/compiler-probe/probe build/compiler-probe.c
readelf -h dist/compiler-probe/probe > dist/compiler-probe/header.txt
grep -q 'Class:.*ELF64' dist/compiler-probe/header.txt
grep -q 'Machine:.*Advanced Micro Devices X86-64' dist/compiler-probe/header.txt
printf '%s\n' 'Compiled and statically inspected an ELF64 x86-64 probe; it was not executed.'
