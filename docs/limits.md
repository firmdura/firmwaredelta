# What a comparison can tell you

FirmwareDelta reports differences in a defined set of filesystem attributes.
It helps you review a maintenance update, but does not decide whether that
update is safe to deploy. This page describes the inputs it supports, what it
compares, and what remains outside the report.

## Supported hosts and inputs

Comparison runs on **Linux amd64**, meaning 64-bit x86 Linux. The firmware being
compared may target a different processor: ELF machine values are recorded as
numbers, including architectures unfamiliar to the host. Policy parsing and
report rendering also work on other hosts. The
[build guide](../build/README.md) explains the Linux container and the ARM Mac
fallback for source examples and development.

Supply two already extracted filesystem directories. Keep them readable and
unchanged for the entire scan. FirmwareDelta reads files without running any
firmware program, writing to the inputs, or using a network connection.

The root argument itself cannot be a symlink. Symlinks inside a root are
recorded by their literal targets and never followed, including absolute links,
dangling links, and loops. Hardlinked paths are recorded separately. Empty
directories are included. Devices, named pipes (FIFOs), and sockets contribute
metadata only; their contents are never opened or read.

The scanner checks file identity, size, permissions, and time metadata before
and after reading, and checks directory and path metadata while walking. It
fails if it observes replacement, modification, or disappearance. These checks
cannot turn a changing filesystem into a consistent snapshot: a file might
change and revert between checks, or change after it has been read. Use stable
build outputs or filesystem snapshots. A read-only mount protects against writes
through that mount, but does not prevent changes made elsewhere to the same
underlying data.

## Attributes included in a comparison

| Attribute | What is recorded |
| --- | --- |
| Path and type | Regular file, directory, symlink, block device, character device, FIFO, or socket; the root entry itself is excluded |
| Mode | Unix permissions plus setuid, setgid, and sticky bits, as four octal digits |
| File content | Byte count and a streamed SHA-256 hash; the file's text or bytes are not included |
| Symlink | Literal UTF-8 target string |
| ELF metadata | Class (32/64), byte order, numeric `e_machine`, `SONAME`, and sorted, deduplicated `DT_NEEDED` names |

ELF is the Executable and Linkable Format used by many Linux programs and
shared libraries. `SONAME` is a shared library's declared name; `DT_NEEDED`
lists the shared library names recorded as dependencies. FirmwareDelta reads
these values without loading or running the program. A file with ELF magic
bytes but invalid ELF data is an error, including invalid or unavailable
dynamic-string data. It is not silently treated as an ordinary non-ELF file.

Each reported change describes one attribute at a path. File size accompanies
the content hash in a `content` record rather than becoming a separate change.
If several attributes change, each remains visible; the
[report guide](usage.md#read-the-report) explains these records.

Entries are grouped into categories using the first matching rule:

| Category | Rule |
| --- | --- |
| `config` | The path begins with `etc/`; the path `etc` itself does not match |
| `library` | The entry is an ELF regular file with a nonempty `SONAME` |
| `executable` | The entry is ELF type `ET_EXEC`, or a regular file with any execute bit |
| `other` | None of the preceding rules applies |

These categories organize review; they do not indicate risk. ELF type is used
for classification but is not a separately compared field. A category change
alone does not create a change record. An unchanged `SONAME` does not establish
binary compatibility.

## Attributes and conclusions outside the report

FirmwareDelta does not compare ownership (uid/gid), capabilities, extended
attributes (xattrs), access control lists (ACLs), timestamps, inode or hardlink
identity, device numbers, sparse allocation, filesystem layout, or mounted
filesystem identity. Changing only one of these attributes can leave the report
unchanged. Some metadata is checked to detect input changes during a scan even
though it is not part of the comparison.

The tool does not extract images or archives, query package databases, or
reconstruct build recipes. It does not interpret configuration settings,
disassemble programs, inspect symbols or ABI contracts, resolve a dependency
tree, validate patch application, generate a software bill of materials, scan
for known vulnerabilities, or test boot and runtime behavior. It makes no
security, hardening, compliance, or compatibility assessment.

Read the verdict within that scope. `unchanged` means the compared attributes
did not differ. `expected_changes` means every reported change matched an
explicit policy rule. Neither verdict establishes that the firmware is safe,
compatible, bootable, or ready for deployment. An error means the comparison or
report delivery could not finish; a policy cannot turn missing data into a
successful comparison.

## Size limits

These limits include their stated maximum values:

| Limit | Maximum |
| --- | --- |
| Entries in each root, excluding the root itself | 250,000 |
| Each relative UTF-8 path | 4096 bytes |
| Entire JSON policy, including whitespace | 1 MiB (1,048,576 bytes) |
| Rules in a policy | 10,000 |

Exceeding a limit is an error. Invalid UTF-8 in paths, symlink targets, or ELF
text is also rejected rather than changed during JSON encoding. There is no
total byte limit for regular files; hashing time grows with the amount of data.
Library callers can cancel scanning or set a deadline through a Go context.

## Privacy of reports

Reports and diagnostics leave out regular-file contents, including
configuration text. A changed configuration file is shown by its path, size,
and hashes. The tool does not add host root directory locations or report
timestamps.

Reports do include file names, metadata, literal symlink targets, library names,
and policy reasons. Those values can reveal information of their own, and
policy text is not redacted. Consider their contents before storing or sharing
a report.
