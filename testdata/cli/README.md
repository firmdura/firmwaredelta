# CLI integration fixtures

These original Apache-2.0 test inputs describe an executable rebuild and an
unrelated configuration edit. The files contain invented text, not third-party
firmware, and are never executed.

Tests copy `baseline/` and `candidate/` into temporary directories and set
predictable modes: `0755` for directories and `usr/bin/tool`, and `0644`
for other files. The policy in `policy.json` acknowledges only the executable's
content change. The configuration change remains unexpected, and the unused
rule produces a warning.

The `compare.json.golden` and `compare.md.golden` files contain the exact
expected reports. They retain both changes without including the input files'
text. CLI and process tests compare their output with these files.
