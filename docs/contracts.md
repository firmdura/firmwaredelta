# Version 1 contracts

This document defines the schema-1 data formats and package behavior used by
FirmwareDelta v1.x. It is a reference for developers implementing or consuming
these contracts. For practical examples, start with the [library guide](library.md).

Original source and synthetic fixtures are Apache-2.0 licensed. Comparison runs
on Linux amd64; other development hosts can use the fixed Linux environment
described in the [build guide](../build/README.md).

## Package boundaries

All implementation packages import `github.com/firmdura/firmwaredelta/internal/model`.
They do not import the public package. The internal entrypoints are:

```go
// internal/inventory: read-only filesystem evidence, including static ELF.
func Scan(ctx context.Context, root string) (model.Inventory, error)

// internal/delta: pure comparison of validated inventories, no policy.
func Compare(baseline, candidate model.Inventory) (model.Report, error)

// internal/policy: bounded parsing and pure exact path/field decisions.
func Read(r io.Reader) (model.Policy, error)
func Apply(report model.Report, policy *model.Policy) (model.Report, error)

// internal/render: validated, normalized output; no new decisions.
func WriteJSON(w io.Writer, report model.Report) error
func WriteMarkdown(w io.Writer, report model.Report) error
```

The public `pkg/firmwaredelta` package connects these stages and exports aliases
for their shared types, constants and typed errors. Callers need no `internal`
imports. Its entrypoints are `ReadPolicy(io.Reader) (Policy, error)`,
`Compare(context.Context, string, string, Options) (Report, error)`,
`WriteJSON(io.Writer, Report) error` and `WriteMarkdown(io.Writer, Report) error`.
`Options.Policy` is `*Policy`: nil allows nothing; a supplied policy must validate
even if constructed in Go. The public package preserves cancellation and errors,
and never prints or exits.

Inventory errors are `*model.InputError` for arguments/unsupported hosts and
`*model.ScanError` for missing or malformed evidence. Policy errors are
`*model.PolicyError`. The structs expose `Op` and `Err`; scan errors also expose a
root-relative `Path`, empty for the root. They implement `Unwrap` and preserve the
results of `errors.Is(err, context.Canceled)` and
`errors.Is(err, context.DeadlineExceeded)`. Shared sentinel errors are
`ErrLimitExceeded`, `ErrInputChanged` and `ErrUnsupportedHost`. Errors must
not contain file contents. Model validators return ordinary errors, which the
calling implementation package wraps in the appropriate typed error. Writers
return validation and I/O errors to their caller.

## Inventory and canonical digests

An `Inventory` describes one supplied root as
`{schema_version: 1, entries: [...]}`. It excludes the root entry itself.
Entries have these fields in this JSON property order:

| Field | Representation |
| --- | --- |
| `path` | Root-relative, slash-separated UTF-8 string |
| `kind` | `file`, `directory`, `symlink`, `block_device`, `char_device`, `fifo`, `socket` |
| `mode` | Exactly four octal digits, such as `0644` or `4755`; permission and special bits only |
| `category` | `config`, `library`, `executable`, `other` |
| `size` | Nonnegative byte count, required only for regular files |
| `sha256` | 64 lowercase hex digits, required only for regular files |
| `target` | Literal symlink target, required only for symlinks |
| `elf` | Required for ELF regular files, absent for non-ELF files and all other kinds |

Inapplicable fields are absent, never null. Empty directories and special files
retain path, kind, mode and category. Device identities, ownership, capabilities,
xattrs, timestamps, inode numbers and hardlink identity are outside the contract.
Hardlinked paths are separate entries. No special file is opened.

Paths have no leading/trailing slash, empty segment, `.` or `..` segment, or NUL.
They are at most 4096 UTF-8 bytes. Invalid UTF-8 fails explicitly rather than
being replaced during JSON encoding. Backslashes, newlines, glob characters and
other valid Linux filename characters are literal, never expanded. Empty paths
and `.` cannot name the excluded root. Symlink targets are literal UTF-8 strings;
absolute targets and loops are recorded without following them.

`ELF` property order is `class`, `endian`, `machine`, `soname`, `needed`.
Class is `"32"` or `"64"`; endian is `"little"` or `"big"`; machine is the
numeric ELF `e_machine` value (uint16), including unfamiliar architectures.
SONAME is the declared shared-library name, represented as a string or an empty
string when absent. Needed contains the `DT_NEEDED` library names as an array,
empty when absent. Canonical needed names are sorted and deduplicated.
Inspection never runs ELF code. A file with ELF magic that cannot be parsed as
valid ELF is an error, not a non-ELF result.

Categories use this precedence: paths beginning `etc/` are config; otherwise an
ELF file with a nonempty SONAME is library; otherwise ELF ET_EXEC or a regular
file with any execute bit is executable; otherwise other. The path `etc` itself
is not under `etc/`. Classification belongs to the scanner; the ELF type is used
for category selection but is not an independently compared field. Model
validation checks the category enum, while the scanner must enforce the rule.
These labels are review aids, not risk, safety or compatibility judgments.

`model.NormalizeInventory` returns an independent validated copy, sorting entries
by path and ELF needed names by Go string order (UTF-8 byte order). It rejects
duplicate paths and unknown schema/enum values. It sorts and deduplicates needed
names without changing the caller's evidence. Nil lists become `[]` in canonical JSON.
`model.CanonicalInventoryJSON` uses compact Go `encoding/json` with the property
orders above, default HTML escaping, no indentation and no trailing newline.
The envelope order is `schema_version`, `entries`. `model.InventoryDigest`
returns the lowercase SHA-256 of exactly those bytes. Host roots and clocks do
not participate. Empty inventory bytes are:

```json
{"schema_version":1,"entries":[]}
```

## Atomic changes and report values

An atomic change is one independently reported field difference.
`delta.Compare` validates both inventories and computes their canonical digests,
then emits the following facts without filesystem access or policy decisions:

| Condition / `field` | `before` and `after` JSON values |
| --- | --- |
| Added/removed path: `presence` | `null` on absent side; full Entry on present side |
| Different kinds: `kind` | Full Entry on each side; no additional records for that path |
| Same file, different size or hash: `content` | Object `{size, sha256}` on each side |
| Same kind, different mode: `mode` | Four-digit octal strings |
| Same symlink, different target: `target` | Literal target strings |
| `elf.class` | `"32"` / `"64"` strings |
| `elf.endian` | `"little"` / `"big"` strings |
| `elf.machine` | uint16 numbers |
| `elf.soname` | Strings, including empty SONAME |
| `elf.needed` | Sorted, deduplicated arrays of strings, including `[]` |

ELF values are `null` on a side with no ELF. Thus an ELF appearing/disappearing
on an existing file emits each differing ELF field, as well as changed content.
`null` differs from an empty SONAME, empty needed array or machine zero. Same-kind
changes emit every changed atomic field exactly once, without hiding mode or
ELF changes behind content changes. Size accompanies content; it is not a
separate change field. Category is taken from the candidate entry, or baseline
for a removal. Category alone is not an atomic comparison field.

In Go, `model.Value` represents one of the allowed value types through its
`Entry`, `Content`, `String`, `Machine` and `Needed` pointer members. At most one
may be set. The zero value is JSON null.
Construct with `EntryValue`, `ContentValue`, `StringValue`, `MachineValue`,
`NeededValue` or `NullValue`. Its JSON encoding is the direct value in the table,
without an extra wrapper. Constructors copy entry metadata and needed slices.
`Change.Validate` rejects a wrong union member, equal values, mismatched full
entry paths/categories and invalid presence/kind pairs.

Report property order is `schema_version`, `baseline_digest`, `candidate_digest`,
`changes`, `policy_warnings`, `counts`, `verdict`. Every change has `path`,
`category`, `field`, `before`, `after`, `expected`, and, only when expected,
`reason`. Counts contain `total`, `expected`, `unexpected` and count atomic
records, not paths. All observed changes remain in the report. Verdict is
`unchanged` for no records, `expected_changes` for expected-only records, or
`unexpected_changes` if any record is unexpected. Delta initializes every record
as unexpected, with no rationale or warnings.

Changes sort lexicographically by path, then field. `model.NormalizeReport`
validates and sorts a copy. It preserves the supplied counts, verdict and
decisions; inconsistent conclusions are errors rather than values to repair.
Renderers call it and refuse invalid reports. JSON output is that normalized
struct, compact with a trailing newline.
Markdown shows all facts, counts, digests, rationales and warnings, escapes all
untrusted strings including Markdown/HTML/terminal controls, and must not create
automatic clickable links. Neither renderer reads input files or includes their
contents.

## Policy and execution boundaries

Policy schema 1 has `schema_version` and `allow`. Each allow rule has one exact
`path`, a nonempty list of distinct atomic `fields` from the table, and a
non-whitespace `reason`. Duplicate JSON keys, duplicate path rules, unknown
members/versions/fields, invalid paths and empty rationales fail. Path and field
matching is exact; glob characters remain literal. No prefix, glob or regular
expression matching is performed. Parsing permits at most 1 MiB total input
bytes, including whitespace, and 10,000 rules; both limits are inclusive.

`policy.Apply` validates the whole report and supplied policy before returning a
new independent report. It clears previous decisions and recomputes them from
the supplied policy: a nil policy makes all facts unexpected. A rule is used if
at least one observed path/field pair matches it. Otherwise it produces one
warning `{path, code: "unused_rule"}`. Warnings sort by path, then code; they do
not affect change counts or verdict. Matching one field cannot allow unlisted
fields. Allowances acknowledge maintenance changes, not the safety of bytes.

Each root permits at most 250,000 entries (excluding the root); every path permits
at most 4096 bytes. A limit violation is an explicit error. Scanning rejects root
symlinks, never follows child links, streams SHA-256 and checks stat evidence
before/after reading. Observed mutation/disappearance fails. Cancellation must
stop scanning promptly. Inputs must remain immutable and quiescent throughout
the comparison: these checks do not create an atomic filesystem snapshot.
No comparison writes inputs, runs firmware programs or uses network access.

The CLI accepts `firmwaredelta compare --baseline OLD_ROOT --candidate NEW_ROOT`
with optional `--policy policy.json` and `--format json|markdown` arguments.
Markdown is the default. It emits a report to stdout only after complete input
validation and comparison. Diagnostics go to stderr. Exit 0 means unchanged or
expected-only; exit 1 means unexpected
changes; exit 2 means invalid input, execution or writer failure. Missing evidence
must never become a clean report. Build/setup networking is separate from
comparison and offline verification.

## Schemas and executable checks

[`schemas/`](../schemas/) contains standalone JSON Schema 2020-12 definitions for
inventories, policies and reports. In the source checkout, `testdata/model/`
contains original synthetic empty, normal and invalid examples.
`make validate-schemas` compiles the schemas and checks those examples with a
test-only validator whose version is fixed in `go.mod`.

After preparing the source checkout's toolchain and modules, run
`bash build/go.sh test ./internal/model -run TestContract -count=1` to check
semantic validation, canonicalization, value round trips and error wrapping.
Schema validation checks the JSON structure; Go validation also checks
byte-based limits, unique path keys, count/verdict consistency and relationships
between values that JSON Schema cannot express. Go helpers perform canonical
sorting.

`make verify` checks formatting, vet and race tests.
`make foundation-linux` runs those checks, validates schema examples and checks
the compiler by compiling and inspecting an original C ELF without running it.
`make verify-linux` runs `make verify` and full CLI/library acceptance. These container
commands run offline after `make prepare-linux`. The [build guide](../build/README.md)
explains prerequisites, native commands and the separate setup step. All test,
fixture-generation and build commands in this section require a source checkout;
the binary bundle includes the schemas and contract text as reference material.
