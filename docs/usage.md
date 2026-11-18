# Using the CLI and writing a policy

Run FirmwareDelta on Linux amd64 after extracting both firmware images. The
examples below use `./firmwaredelta` from an unpacked release. If you built from
source, use `dist/firmwaredelta` from the repository directory instead.

```sh
./firmwaredelta compare --baseline /snapshots/old-root \
  --candidate /snapshots/new-root --format json > report.json
```

Each **root directory** is the top of an extracted filesystem. For example, a
file named `etc/service.conf` inside the old root is compared with the same path
inside the new root. Use your existing extraction or build tools to prepare
these directories, preserving Linux permissions and symlinks. Keep the files
unchanged and readable for the whole comparison; a live target filesystem may
change while it is being scanned. Save reports outside both input directories.

## Arguments and output

The command accepts:

```text
firmwaredelta compare --baseline OLD_ROOT --candidate NEW_ROOT \
  [--policy policy.json] [--format json|markdown]
```

Both roots are required. `--policy` names a regular JSON file; omit it to treat
all changes as unexpected. Markdown is the default output format. Duplicate
flags, extra positional arguments, empty or missing values, unknown flags, and
unsupported formats are errors. Run `./firmwaredelta --help` for a reminder of
the syntax; help is written to stderr and exits 0.

Run `./firmwaredelta --version` on its own to identify the installed release.
It prints `firmwaredelta v1.0.1` to stdout and exits 0 without requiring firmware
roots or opening any inputs. A version-output failure exits 2.

A completed comparison writes its report to stdout. Diagnostics go to stderr.
Use the exit status as follows:

| Exit | Meaning | Report verdict |
| --- | --- | --- |
| 0 | No differences in the compared attributes | `unchanged` |
| 0 | Every reported change matches a policy rule | `expected_changes` |
| 1 | At least one change does not match a policy rule | `unexpected_changes` |
| 2 | Invalid input, scan failure, cancellation, or output failure | No completed report |

Exit 1 is a review result, not an execution failure. In a script using `set -e`,
put the comparison in an `if` statement so that this result does not stop the
script before you can handle it.

FirmwareDelta finishes validating the roots and policy before it starts
writing a report. Missing or unreadable files, detected input changes, malformed
ELF data, and exceeded limits produce exit 2 with no report. Ctrl+C cancels a
scan. If the destination fails while a report is being written, it may already
have received some bytes; the command still exits 2.

## Mark specific changes as expected

A policy lists changes you intended to make. This example acknowledges a
rebuild of one program:

```json
{
  "schema_version": 1,
  "allow": [
    {
      "path": "usr/bin/maintenance",
      "fields": ["content"],
      "reason": "Approved maintenance executable rebuild"
    }
  ]
}
```

Pass it with `--policy policy.json`. The rule marks only the content change at
`usr/bin/maintenance` as expected. A permission change or new library dependency
at that same path remains unexpected, as does a change anywhere else. Expected
changes stay in the report along with the reason you supplied.

Paths match exactly. There are no wildcard, prefix, or regular-expression
matches: `usr/bin/*` would name a file containing a literal `*`. Use slash
separators relative to the root, without a leading or trailing slash, empty
segment, `.` or `..` segment, or NUL character. Paths must be valid UTF-8 and no
more than 4096 bytes. Backslashes and other valid Linux filename characters
remain literal.

Each path may have one rule. Its `fields` list must contain at least one supported
field, with no duplicates, and its `reason` must contain more than whitespace.
The supported fields are `presence`, `kind`, `content`, `mode`, `target`,
`elf.class`, `elf.endian`,
`elf.machine`, `elf.soname`, and `elf.needed`; their meanings are described below.

The parser rejects unsupported schema versions, unknown members or fields,
duplicate JSON keys or rules, duplicate fields, invalid paths, empty reasons,
trailing JSON, and invalid JSON or UTF-8. A policy may contain up to 10,000 rules
and occupy up to 1 MiB, including whitespace. Invalid policy is an error even
when the two roots are identical. See the
[policy schema](../schemas/policy-v1.json) for the JSON structure.

A rule that matches no observed path and field produces an `unused_rule`
warning. Warnings are sorted by path and do not change the verdict or exit
status. If a rule matches one of its fields, its other unused fields do not
produce separate warnings. A matching rule records your intent; it does not
verify the changed bytes.

## Read the report

A report breaks changes into individual records. Each record describes one
aspect of a change at one path; this is what the API and schema call an
**atomic change**. Rebuilding a program and adding a dependency can therefore
produce separate `content` and `elf.needed` records at the same path.

| Difference | Field | Values before and after |
| --- | --- | --- |
| A path was added or removed | `presence` | Full entry on one side, `null` on the other |
| A path changed type, such as file to symlink | `kind` | Full entries; no other records for that path |
| A regular file changed size or SHA-256 hash | `content` | Objects containing `size` and `sha256` |
| Permission or special mode bits changed | `mode` | Four octal digits, such as `0644` |
| A symlink target changed | `target` | Literal target strings |
| Static ELF metadata changed | One of the five `elf.*` fields | The corresponding metadata values |

ELF, the Executable and Linkable Format, is commonly used for Linux programs
and shared libraries. FirmwareDelta reads its headers and dependency metadata
without running the program. If an existing file becomes ELF, or stops being
ELF, absent metadata is represented by `null`. This differs from an empty
library name, an empty dependency list, or machine value zero. Dependency names
are sorted and deduplicated.

The JSON report contains `schema_version`, `baseline_digest`,
`candidate_digest`, `changes`, `policy_warnings`, `counts`, and `verdict`.
`counts.total`, `counts.expected`, and `counts.unexpected` count individual
records, not paths. Each record has `path`, `category`, `field`, `before`,
`after`, and `expected`, plus `reason` when it is expected. The category comes
from the new entry, or the old entry for a removal; categories help organize
review and do not indicate risk.

Records are sorted by path and then field, using UTF-8 byte order. Warnings are
sorted by path and then code. Each inventory digest is the SHA-256 hash of its
canonical, sorted JSON inventory. Inventories contain file metadata and hashes,
not file contents. Their digests do not depend on host root locations,
timestamps, ownership, or inode numbers. Reports have no wall-clock timestamp.
The same unchanged inputs and policy produce byte-identical repeated reports.
The [version 1 contracts](contracts.md) describe the canonical encoding in detail;
the [inventory](../schemas/inventory-v1.json) and
[report](../schemas/report-v1.json) schemas describe the JSON structure.

Markdown presents the same changes, counts, digests, reasons, and warnings. It
escapes caller-supplied text to prevent Markdown, HTML, links, or terminal
controls from being interpreted. JSON represents that text as JSON strings.
Reports exclude regular-file contents, but include names, literal symlink
targets, library names, and policy text. See [limits and privacy](limits.md)
before sharing a report.
