#!/usr/bin/env bash
# Copyright 2026 FirmwareDelta contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
repo_dir=$(pwd -P)
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 || {
  printf '%s\n' 'Acceptance requires Linux amd64; use make acceptance-linux.' >&2
  exit 1
}
test "$(id -u)" -ne 0 || {
  printf '%s\n' 'Acceptance requires an unprivileged user for unreadability checks.' >&2
  exit 1
}
for command in python3 make readelf; do
  command -v "$command" >/dev/null || { printf 'Required acceptance tool is missing: %s\n' "$command" >&2; exit 1; }
done
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
make build compiler-check
work=$(mktemp -d "$repo_dir/dist/acceptance.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
bash examples/demo/prepare.sh "$work/demo"
# Isolated mode ignores PYTHONOPTIMIZE/PYTHONPATH so mandatory assertions cannot
# silently disappear because of a developer's Python environment.
python3 -I - "$repo_dir" "$work" <<'PY'
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

repo, work = map(Path, sys.argv[1:])
binary = repo / "dist/firmwaredelta"
base, candidate, policy = work/"demo/baseline", work/"demo/candidate", work/"demo/policy.json"
captured = []

def state(root):
    result = {}
    def visit(path):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1 << 20), b""):
                    digest.update(chunk)
            value = ("file", mode, digest.hexdigest())
        elif stat.S_ISLNK(info.st_mode):
            value = ("symlink", mode, os.readlink(path))
        else:
            value = (stat.S_IFMT(info.st_mode), mode)
        result[str(path.relative_to(root))] = value
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)
    visit(root)
    return result

def invoke(before=base, after=candidate, policy_path=None, fmt="json", code=1, extra=()):
    args = [str(binary), "compare", "--baseline", str(before), "--candidate", str(after)]
    if policy_path is not None:
        args += ["--policy", str(policy_path)]
    if fmt is not None:
        args += ["--format", fmt]
    args += list(extra)
    process = subprocess.run(args, capture_output=True, timeout=30)
    captured.extend([process.stdout, process.stderr])
    assert process.returncode == code, (args, process.returncode, process.stderr.decode(errors="backslashreplace"))
    if code == 2:
        assert not process.stdout and process.stderr, "invalid evidence produced a report"
        return None
    assert not process.stderr and process.stdout, "valid comparison stream separation failed"
    if fmt not in (None, "markdown"):
        report = json.loads(process.stdout)
        assert report["schema_version"] == 1
        changes = report["changes"]
        assert [(c["path"], c["field"]) for c in changes] == sorted((c["path"], c["field"]) for c in changes)
        assert len({(c["path"], c["field"]) for c in changes}) == len(changes)
        expected = sum(c["expected"] for c in changes)
        assert report["counts"] == {"total":len(changes), "expected":expected, "unexpected":len(changes)-expected}
        verdict = "unexpected_changes" if len(changes)-expected else ("expected_changes" if changes else "unchanged")
        assert report["verdict"] == verdict
        assert all(len(report[key]) == 64 and all(c in "0123456789abcdef" for c in report[key]) for key in ("baseline_digest", "candidate_digest"))
        return report, process.stdout
    assert process.stdout.startswith(b"# FirmwareDelta report\n")
    return process.stdout

original = {path:state(path) for path in (base, candidate, policy, repo/"testdata/cli/baseline", repo/"testdata/cli/candidate", repo/"testdata/cli/policy.json")}
empty, _ = invoke(after=base, code=0)
assert empty["verdict"] == "unchanged" and empty["baseline_digest"] == empty["candidate_digest"]
observed, _ = invoke()
expected_fields = {
    ("etc/maintenance.conf","content"),
    ("usr/bin/maintenance","content"),
    ("usr/bin/maintenance","elf.needed"),
    ("usr/lib/libextra.so.1","presence"),
    ("usr/lib/libmaintenance.so.1","content"),
}
assert {(c["path"],c["field"]) for c in observed["changes"]} == expected_fields
assert observed["counts"] == {"total":5,"expected":0,"unexpected":5}
narrow, narrow_bytes = invoke(policy_path=policy)
_, repeated_bytes = invoke(policy_path=policy)
assert narrow_bytes == repeated_bytes, "JSON repeats differ"
changes = {(c["path"], c["field"]):c for c in narrow["changes"]}
assert set(changes) == expected_fields
assert narrow["counts"] == {"total":5,"expected":1,"unexpected":4} and narrow["policy_warnings"] == []
assert [(c["path"],c["category"],c["field"],c["before"],c["after"]) for c in observed["changes"]] == [(c["path"],c["category"],c["field"],c["before"],c["after"]) for c in narrow["changes"]]
assert {key for key,c in changes.items() if c["expected"]} == {("usr/bin/maintenance","content")}
assert changes[("etc/maintenance.conf","content")]["expected"] is False
needed = changes[("usr/bin/maintenance","elf.needed")]
assert needed["expected"] is False and "libextra.so.1" not in needed["before"] and "libextra.so.1" in needed["after"]
assert needed["before"] == sorted(set(needed["before"])) and needed["after"] == sorted(set(needed["after"]))
library = changes[("usr/lib/libextra.so.1","presence")]["after"]["elf"]
assert (library["class"],library["endian"],library["machine"],library["soname"]) == ("64","little",62,"libextra.so.1")
assert changes[("usr/lib/libmaintenance.so.1","content")]["expected"] is False
markdown = invoke(policy_path=policy, fmt="markdown")
assert markdown == invoke(policy_path=policy, fmt="markdown") == invoke(policy_path=policy, fmt=None)
assert b"\nChanged paths: 4 (4 with unexpected changes)\n" in markdown, "mixed-policy path not counted once"
assert b"maintenance&#46;conf" in markdown and b"elf&#46;needed" in markdown
assert b"Approved maintenance executable rebuild" in markdown

all_rules = collections.defaultdict(list)
for path, field in sorted(expected_fields):
    all_rules[path].append(field)
all_policy = work/"all.json"
all_policy.write_text(json.dumps({"schema_version":1,"allow":[{"path":path,"fields":fields,"reason":"Acceptance acknowledgment only"} for path,fields in sorted(all_rules.items())]}))
all_report, _ = invoke(policy_path=all_policy, code=0)
assert all_report["verdict"] == "expected_changes" and all_report["counts"]["unexpected"] == 0
prefix_policy = work/"prefix.json"
prefix_policy.write_text(json.dumps({"schema_version":1,"allow":[{"path":"usr/bin/maintenanc","fields":["content"],"reason":"Literal different path"}]}))
prefix, _ = invoke(policy_path=prefix_policy)
assert prefix["counts"]["expected"] == 0 and prefix["policy_warnings"] == [{"path":"usr/bin/maintenanc","code":"unused_rule"}]

mode_root = work/"mode-candidate"
shutil.copytree(candidate, mode_root, symlinks=True)
(mode_root/"usr/bin/maintenance").chmod(0o644)
mode_before = state(mode_root)
mode_report, _ = invoke(after=mode_root, policy_path=policy)
mode = next(c for c in mode_report["changes"] if c["path"] == "usr/bin/maintenance" and c["field"] == "mode")
assert mode["expected"] is False and (mode["before"],mode["after"]) == ("0755","0644")
assert state(mode_root) == mode_before, "mode-case input changed"

bad_policy = work/"invalid.json"
for data in (
    '{"schema_version":2,"allow":[]}',
    '{"schema_version":1,"schema_version":1,"allow":[]}',
    '{"schema_version":1,"allow":[{"path":"/absolute","fields":["content"],"reason":"invalid"}]}',
    '{"schema_version":1,"allow":[{"path":"usr/bin/maintenance","fields":["unknown"],"reason":"invalid"}]}',
    '{"schema_version":1,"allow":[{"path":"usr/bin/maintenance","fields":["content"],"reason":""}]}',
):
    bad_policy.write_text(data)
    invoke(policy_path=bad_policy, code=2)
invoke(after=work/"missing", code=2)
root_link = work/"root-link"
root_link.symlink_to(base, target_is_directory=True)
invoke(after=root_link, code=2)
broken = work/"malformed"
broken.mkdir()
(broken/"broken").write_bytes(b"\x7fELFACCEPTANCE_PRIVATE_SENTINEL_NEVER_PRINT")
invoke(after=broken, code=2)
unreadable = work/"unreadable"
unreadable.mkdir()
(unreadable/"private").write_text("ACCEPTANCE_PRIVATE_SENTINEL_NEVER_PRINT")
(unreadable/"private").chmod(0)
try:
    invoke(after=unreadable, code=2)
finally:
    (unreadable/"private").chmod(0o600)
unreadable.chmod(0)
try:
    invoke(after=unreadable, code=2)
finally:
    unreadable.chmod(0o700)
special = work/"special"
special.mkdir()
os.mkfifo(special/"fifo")
(special/"loop").symlink_to("loop")
(special/"absolute").symlink_to("/firmwaredelta-absent-literal-target")
empty_root = work/"empty"
empty_root.mkdir()
special_report, _ = invoke(before=empty_root, after=special)
special_entries = {c["path"]:c["after"] for c in special_report["changes"]}
assert special_entries["fifo"]["kind"] == "fifo"
assert special_entries["loop"]["target"] == "loop" and special_entries["absolute"]["target"] == "/firmwaredelta-absent-literal-target"
invoke(policy_path=special/"fifo", code=2)

invoke(before=repo/"testdata/cli/baseline", after=repo/"testdata/cli/candidate", policy_path=repo/"testdata/cli/policy.json")
example = subprocess.run(["bash","build/go.sh","run","./examples/library","--baseline",str(base),"--candidate",str(candidate),"--policy",str(policy),"--format","json"], cwd=repo, capture_output=True, timeout=300)
captured.extend([example.stdout, example.stderr])
assert example.returncode == 0 and not example.stderr and example.stdout == narrow_bytes, "library example/CLI reports disagree"
for path, before in original.items():
    assert state(path) == before, "input bytes, modes or link metadata changed"
private_values = [b"ACCEPTANCE_PRIVATE_SENTINEL_NEVER_PRINT"]
for root in (base,candidate):
    data = (root/"etc/maintenance.conf").read_bytes()
    private_values += [data.strip()] + [line for line in data.splitlines() if line]
for output in captured:
    assert all(value and value not in output for value in private_values), "file content leaked"
    assert str(repo).encode() not in output and str(work).encode() not in output, "host root leaked"
print("Acceptance passed: CLI/library, exact exits and policies, real ELF, read-only source roots, confidentiality, immutable inputs and byte-identical repeats.")
PY
