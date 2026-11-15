#!/usr/bin/env bash
# Copyright 2026 FirmwareDelta contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
repo_dir=$(pwd -P)
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 || {
  printf '%s\n' 'Packaging requires Linux amd64; use make package-linux.' >&2
  exit 1
}
for command in python3 make tar gzip sha256sum readelf; do
  command -v "$command" >/dev/null || { printf 'Required packaging tool is missing: %s\n' "$command" >&2; exit 1; }
done
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
make build demo
source build/toolchain.env
go_root=$(bash build/go.sh env GOROOT)
test -f "$go_root/LICENSE" && test ! -L "$go_root/LICENSE"
name=firmwaredelta-v1.0.0-linux-amd64
work=$(mktemp -d "$repo_dir/dist/.package.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
stage="$work/$name"
mkdir -p "$stage/licenses"
cp -- dist/firmwaredelta "$stage/firmwaredelta"
cp -- "$go_root/LICENSE" "$stage/licenses/GO-LICENSE"
# This flat list is the complete source-input allowlist for the binary bundle.
# In particular, no directory from dist or the local checkout is copied whole.
inputs=(
  LICENSE
  build/README.md
  docs/usage.md docs/limits.md docs/library.md docs/contracts.md
  schemas/inventory-v1.json schemas/policy-v1.json schemas/report-v1.json
  examples/demo/README.md
  examples/library/main.go examples/library/README.md
)
for input in "${inputs[@]}"; do
  test -f "$input" && test ! -L "$input" || {
    printf 'Required regular release input is unavailable: %s\n' "$input" >&2
    exit 1
  }
  mkdir -p "$stage/$(dirname "$input")"
  cp -- "$input" "$stage/$input"
done
cat > "$stage/README.md" <<'README'
# FirmwareDelta v1.0.0 Linux amd64 binary bundle

This bundle provides a ready-to-run CLI, reference documentation and schemas.
Run the CLI on Linux amd64; no Go installation, compiler, Docker or network
connection is needed for comparison.

After extraction, open a terminal in this directory and verify every bundled
file:

    sha256sum -c SHA256SUMS

Supply two extracted firmware root directories that remain unchanged throughout
the comparison:

    ./firmwaredelta compare --baseline OLD_ROOT --candidate NEW_ROOT --format json

Replace OLD_ROOT and NEW_ROOT with your directory paths. The report goes to
stdout. Exit 0 means no unexpected changes, exit 1 means at least one unexpected
change, and exit 2 means invalid input, missing evidence or an output failure.
An expected change matched an exact policy allowance; this does not establish
security, ABI compatibility or runtime safety.

See docs/usage.md for the CLI, policy and report formats, and docs/limits.md for
supported evidence and omissions. schemas/ contains the JSON schemas.

## Run the original demo

Demo generation, library examples and development checks need a source checkout
of https://github.com/firmdura/firmwaredelta. Follow that checkout's README and
build/README.md to prepare the tools and generate its dist/demo directory.
Setup uses network access; comparison itself remains offline.

Once the demo exists in the source checkout, this bundled CLI can compare it:

    ./firmwaredelta compare --baseline /path/to/source/dist/demo/baseline \
      --candidate /path/to/source/dist/demo/candidate \
      --policy /path/to/source/dist/demo/policy.json --format json

Replace /path/to/source with the checkout's absolute path. The command returns
1 because the narrow policy leaves configuration, library and dependency
changes unexpected.

The bundled build/README.md, examples/demo/README.md, docs/library.md and
examples/library/ files describe commands to run from a source checkout.
The preparation scripts, test fixtures and complete Go module are not included
in this binary bundle.

Original FirmwareDelta code and synthetic fixtures are Apache-2.0 licensed (see
LICENSE). The binary contains the Go runtime; its exact toolchain license is
preserved in licenses/GO-LICENSE.
README
chmod 0755 "$stage/firmwaredelta"
chmod 0755 "$stage"
python3 -I - "$stage" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
for path in root.rglob("*"):
    if path.is_dir():
        path.chmod(0o755)
    else:
        path.chmod(0o755 if path.name == "firmwaredelta" else 0o644)
lines = []
for path in sorted(path for path in root.rglob("*") if path.is_file()):
    lines.append(hashlib.sha256(path.read_bytes()).hexdigest()+"  "+path.relative_to(root).as_posix()+"\n")
(root/"SHA256SUMS").write_text("".join(lines))
(root/"SHA256SUMS").chmod(0o644)
PY
tar --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -C "$work" -cf - "$name" | gzip -n > "$work/$name.tar.gz"
python3 -I - "$repo_dir" "$work" "$name" "$go_root/LICENSE" <<'PY'
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
repo, work = map(Path, sys.argv[1:3])
name, go_license = sys.argv[3], Path(sys.argv[4])
archive = work/(name+".tar.gz")
expected = {
    "firmwaredelta", "LICENSE", "licenses/GO-LICENSE", "README.md", "SHA256SUMS",
    "build/README.md",
    "docs/usage.md", "docs/limits.md", "docs/library.md", "docs/contracts.md",
    "schemas/inventory-v1.json", "schemas/policy-v1.json", "schemas/report-v1.json",
    "examples/demo/README.md",
    "examples/library/main.go", "examples/library/README.md",
}
allowed_dirs = {"."}
for filename in expected:
    allowed_dirs.update(parent.as_posix() for parent in Path(filename).parents)
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    assert len({m.name for m in members}) == len(members), "duplicate archive member"
    files = set()
    for member in members:
        parts = Path(member.name).parts
        assert not Path(member.name).is_absolute() and parts[0] == name and ".." not in parts, "unsafe archive path"
        assert member.isfile() or member.isdir(), "nonregular archive member"
        assert member.uid == member.gid == member.mtime == 0, "unstable archive metadata"
        relative = Path(*parts[1:]).as_posix()
        assert member.mode == (0o755 if member.isdir() or relative == "firmwaredelta" else 0o644), "unexpected archive mode"
        if member.isfile():
            files.add(relative)
        else:
            assert relative in allowed_dirs, "directory outside archive allowlist"
    assert files == expected, ("archive allowlist differs", files ^ expected)
    # Member paths and types are validated before extracting into a fresh owned
    # directory; no links or preexisting output paths are permitted.
    unpack = work/"unpack"
    unpack.mkdir()
    for member in members:
        target = unpack/member.name
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            target.chmod(0o755 if target.name == "firmwaredelta" else 0o644)
root = unpack/name
assert (root/"licenses/GO-LICENSE").read_bytes() == go_license.read_bytes(), "Go license differs from exact GOROOT"
assert (root/"LICENSE").read_bytes() == (repo/"LICENSE").read_bytes(), "Apache notice changed"
for guide in ("docs/contracts.md", "docs/limits.md"):
    assert "../build/README.md" in (root/guide).read_text(), "build guide reference missing"
    assert (root/guide).parent.joinpath("../build/README.md").is_file(), "bundled build guide link is broken"
assert (root/"build/README.md").read_bytes() == (repo/"build/README.md").read_bytes(), "build guide differs from source"
checked = subprocess.run(["sha256sum","-c","SHA256SUMS"], cwd=root, capture_output=True)
assert checked.returncode == 0, checked.stderr.decode(errors="backslashreplace")
binary = root/"firmwaredelta"
assert binary.read_bytes() == (repo/"dist/firmwaredelta").read_bytes(), "archive binary differs from verified build"
header = binary.read_bytes()[:20]
assert header[:4] == b"\x7fELF" and header[4:6] == b"\x02\x01" and struct.unpack_from("<H",header,18)[0] == 62, "binary is not Linux amd64 ELF"
inspected = subprocess.run(["readelf","-h",str(binary)], capture_output=True)
assert inspected.returncode == 0, "packaged ELF header cannot be inspected"
args = [str(binary),"compare","--baseline",str(repo/"dist/demo/baseline"),"--candidate",str(repo/"dist/demo/candidate"),"--policy",str(repo/"dist/demo/policy.json"),"--format","json"]
run = subprocess.run(args, capture_output=True, timeout=30)
assert run.returncode == 1 and not run.stderr, "packaged binary demo failed"
report = json.loads(run.stdout)
facts = {(c["path"],c["field"]):c for c in report["changes"]}
assert facts[("usr/bin/maintenance","content")]["expected"] is True
assert facts[("usr/bin/maintenance","elf.needed")]["expected"] is False
assert facts[("etc/maintenance.conf","content")]["expected"] is False
assert report["verdict"] == "unexpected_changes"
print("Package verified: exact archive allowlist, checksums, Apache/Go notices, Linux amd64 ELF and extracted-binary demo.")
PY
for output in "dist/$name.tar.gz" dist/SHA256SUMS; do
  test ! -L "$output" && { test ! -e "$output" || test -f "$output"; } || {
    printf 'Refusing nonregular package output: %s\n' "$output" >&2
    exit 1
  }
done
mv -T -- "$work/$name.tar.gz" "dist/$name.tar.gz"
(cd dist && sha256sum firmwaredelta "$name.tar.gz") > "$work/SHA256SUMS"
mv -T -- "$work/SHA256SUMS" dist/SHA256SUMS
printf 'Package prepared: dist/%s.tar.gz and dist/SHA256SUMS\n' "$name"
