#!/usr/bin/env bash
# Copyright 2026 FirmwareDelta contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd -P)
test "$#" -eq 1 && [[ "$1" = /* ]] || {
  printf '%s\n' 'Usage: bash examples/demo/prepare.sh ABSOLUTE_DIST_OUTPUT' >&2
  exit 2
}
test ! -L "$1" || { printf '%s\n' 'Demo output cannot be a symlink.' >&2; exit 2; }
out=$(realpath -m -- "$1")
case "$out" in
  "$repo_dir/dist/"*) ;;
  *) printf '%s\n' 'Demo output must be under this checkout dist/.' >&2; exit 2 ;;
esac
marker=firmwaredelta-original-demo-v1
if test -e "$out"; then
  test -d "$out" || { printf '%s\n' 'Demo output must be a directory.' >&2; exit 2; }
  if test -f "$out/.firmwaredelta-demo" && test ! -L "$out/.firmwaredelta-demo"; then
    test "$(cat "$out/.firmwaredelta-demo")" = "$marker" || {
      printf '%s\n' 'Demo output has an unknown ownership marker.' >&2; exit 2;
    }
  else
    shopt -s nullglob dotglob
    children=("$out"/*)
    test "${#children[@]}" -eq 0 || {
      printf '%s\n' 'Refusing to replace a nonempty directory not created by this demo.' >&2; exit 2;
    }
  fi
fi
mkdir -p "$repo_dir/dist" "$(dirname "$out")"
stage=$(mktemp -d "$repo_dir/dist/.demo-prepare.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
bash "$repo_dir/testdata/elf-src/build.sh" "$stage"
mkdir -p "$stage/baseline/etc" "$stage/candidate/etc"
printf '%s\n' 'service_enabled=yes' 'update_channel=stable' > "$stage/baseline/etc/maintenance.conf"
printf '%s\n' 'service_enabled=yes' 'update_channel=testing' > "$stage/candidate/etc/maintenance.conf"
chmod 0644 "$stage/baseline/etc/maintenance.conf" "$stage/candidate/etc/maintenance.conf"
cat > "$stage/policy.json" <<'EOF'
{"schema_version":1,"allow":[{"path":"usr/bin/maintenance","fields":["content"],"reason":"Approved maintenance executable rebuild"}]}
EOF
chmod 0644 "$stage/policy.json"
printf '%s\n' "$marker" > "$stage/.firmwaredelta-demo"
# The destination is either empty or a previous owned generated demo. Rebuild
# only that owned output; never accept arbitrary input roots as destinations.
if test -d "$out"; then rm -rf -- "$out"; fi
mv -- "$stage" "$out"
trap - EXIT
printf 'Prepared original demo in %s\n' "$out"
