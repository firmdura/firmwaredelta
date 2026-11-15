# FirmwareDelta v1.0.0 design

FirmwareDelta is a Go library and CLI for reviewing changes between extracted
firmware filesystems. This document summarizes its design; the
[version 1 contracts](../docs/contracts.md) define the exact data and API behavior.

## Purpose and scope

FirmwareDelta compares two extracted firmware root filesystems and reports
which maintenance changes match an explicit policy. Callers supply readable,
immutable directory trees. The tool reads those trees without extracting
images, running firmware programs, modifying inputs or using a network.

Comparison runs on Linux amd64. It inventories regular files, directories,
symlinks and special-file metadata, streams regular files through SHA-256,
and records Unix permission and special mode bits. Static ELF inspection uses
Go's `debug/elf` package to read class, byte order, numeric machine type,
SONAME and sorted `DT_NEEDED` library names.

The comparison records added and removed paths, changed file kinds, contents,
modes, symlink targets and ELF fields. Paths are relative to the supplied root,
use slashes, and have no leading slash. Reports contain no absolute input-root
locations, timestamps or regular-file contents. A configuration edit is shown
by its path, size and hashes, without its text.

Categories help organize the review. They follow this precedence: paths under
`etc/` are `config`; otherwise an ELF file with a SONAME is `library`;
otherwise an ELF ET_EXEC file or a regular file with any execute bit is
`executable`; everything else is `other`. These labels do not express risk.
Matching SONAMEs do not establish ABI compatibility.

Raw images and archives, package databases, SBOM/CVE scanning, boot and runtime
tests, ABI analysis, hardening and compliance assessments are outside this
release. Ownership, capabilities and xattrs are not compared. FirmwareDelta
does not infer security risk, approve deployment, or provide a UI or cloud
integration. The full list of omissions is in [limits](../docs/limits.md).

## CLI, policy and library

The CLI accepts:

```text
firmwaredelta compare --baseline OLD_ROOT --candidate NEW_ROOT \
  [--policy policy.json] [--format json|markdown]
```

Markdown is the default. A report reaches stdout only after both inventories
and the policy validate; diagnostics go to stderr. Exit 0 means there are no
unexpected changes, exit 1 means at least one change is unexpected, and exit 2
means invalid input or an execution/output failure. Missing evidence cannot
produce a successful comparison.

An optional schema-1 JSON policy allows specific fields at exact paths:

```json
{"schema_version":1,"allow":[{"path":"usr/bin/wget","fields":["content"],"reason":"Approved maintenance rebuild"}]}
```

There is one rule per path, and every rule needs a rationale. Unknown versions,
members and change fields, duplicate JSON keys or rules, invalid relative
paths and empty rationales are errors. Paths have no glob or regular-expression
matching. Unused rules produce sorted warnings without failing the comparison.
Without a policy, every observed change is unexpected. Matching a rule keeps
the change visible with its rationale; it acknowledges intent rather than
verifying that the bytes are safe.

The public Go package is `github.com/firmdura/firmwaredelta/pkg/firmwaredelta`:

```go
func ReadPolicy(io.Reader) (Policy, error)
func Compare(context.Context, string, string, Options) (Report, error)
func WriteJSON(io.Writer, Report) error
func WriteMarkdown(io.Writer, Report) error
```

`Options.Policy` is an optional `*Policy`. The library returns typed input,
scan and policy errors, preserves cancellation, and never prints or exits.
The [library guide](../docs/library.md) explains embedding and includes a runnable
example. Implementation packages share `internal/model` and do not import the
public package, which avoids import cycles.

## Reports and input requirements

Inventory entries contain `path`, `kind`, `mode` and `category`, with `size`,
`sha256`, `target` and `elf` where applicable. Each schema-1 report contains
the canonical inventory digests, sorted changes, policy warnings, counts and
one verdict: `unchanged`, `expected_changes` or `unexpected_changes`.

Each change records its path, category, field, before/after values, expected
decision and, for an expected change, the matched rationale. The independently
reported fields are `presence`, `kind`, `content`, `mode`, `target`,
`elf.class`, `elf.endian`, `elf.machine`, `elf.soname` and `elf.needed`.
An addition or removal produces one `presence` record with the available
entry; a type change produces one `kind` record with both entries. Otherwise,
each changed field has its own record. Size accompanies the content value.
Records sort by path and field, and needed-library names are sorted and
deduplicated.

Inventory digests hash canonical sorted JSON, excluding root locations,
clocks, host uid/gid and inode numbers. JSON output and escaped Markdown
output are deterministic. All observed changes remain visible, including
unallowed fields at a path where another field matched a policy rule.

Root arguments cannot be symlinks. Child symlinks are recorded literally and
never followed, including absolute targets and loops. Devices, FIFOs and
sockets are never opened. A malformed file with an ELF magic header is an
error, rather than falling back to a non-ELF result.

The scanner checks file metadata before and after reads and rejects observed
mutation or disappearance. These checks do not create an atomic filesystem
snapshot: inputs must remain immutable throughout the operation. Cancellation
stops scanning promptly. Limits are 250,000 entries per root, 4096 bytes per
relative path, 1 MiB of policy input and 10,000 policy rules. Exceeding a limit
fails explicitly.

## Verification and release contents

`make verify` checks formatting, runs `go vet ./...` and `go test -race ./...`,
and includes deterministic CLI golden-output and input-immutability tests.
`make acceptance` builds the CLI, prepares an original two-root demo and
checks exits 0/1/2, both formats, real ELF metadata, exact policy matching,
invalid inputs and byte-identical repeats. `make verify-linux` runs both in
the fixed Linux container with read-only source and no network after setup.
See the [build guide](../build/README.md) for complete prerequisites and commands.

The tests compile small original C fixtures with the fixed compiler version
and inspect them without executing them. Fixtures include malformed ELF and
a dynamically linked executable pair with different `DT_NEEDED` entries.
The final clean-checkout Linux review checked that the CLI and library agree,
unexpected facts reach the report and exit status, allowances do not hide
unrelated fields, invalid or unreadable evidence fails, contents stay private,
inputs remain unchanged and repeated reports match byte for byte.

The release includes a Linux amd64 binary bundle and checksums, a runnable
maintenance demo, a public-library example, schemas and documentation. The
guides cover immutable extracted roots, compared and omitted attributes,
policy/report formats, errors, cancellation, limits and interpretation. The
README also explains how this focused review complements diffoscope and Yocto
buildhistory. Original code and synthetic fixtures use Apache-2.0; binary
bundles preserve the applicable Go runtime notice.
