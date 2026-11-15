# Using FirmwareDelta from Go

Add the released module to your Go project:

```sh
go get github.com/firmdura/firmwaredelta@v1.0.0
```

The module requires Go 1.27.0 or later. Import its public package as follows:

```go
import fd "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
```

Comparing directories requires Linux amd64. Policy parsing and JSON or Markdown
rendering also work on other hosts. The library uses the Go standard library at
runtime; the repository's JSON Schema validator is only a test dependency.
The [API reference](https://pkg.go.dev/github.com/firmdura/firmwaredelta@v1.0.0/pkg/firmwaredelta)
lists every exported type and constant.

## Compare directories and write a report

The four main functions are:

```go
func ReadPolicy(r io.Reader) (Policy, error)
func Compare(ctx context.Context, baselineRoot, candidateRoot string, options Options) (Report, error)
func WriteJSON(w io.Writer, report Report) error
func WriteMarkdown(w io.Writer, report Report) error
```

`Compare` scans both directories, records their differences, and applies an
optional policy. It never prints, exits the process, or makes network requests.
The input directories must remain unchanged and readable throughout the scan;
see [input requirements and limits](limits.md).

For example, this function acknowledges only a particular program's content
change and writes the complete report as JSON:

```go
package comparison

import (
    "context"
    "io"

    fd "github.com/firmdura/firmwaredelta/pkg/firmwaredelta"
)

func WriteComparison(ctx context.Context, baselineRoot, candidateRoot string, output io.Writer) error {
    policy := fd.Policy{
        SchemaVersion: fd.SchemaVersion,
        Allow: []fd.Rule{{
            Path: "usr/bin/maintenance",
            Fields: []fd.Field{fd.FieldContent},
            Reason: "Approved maintenance executable rebuild",
        }},
    }
    report, err := fd.Compare(ctx, baselineRoot, candidateRoot, fd.Options{Policy: &policy})
    if err != nil {
        return err
    }
    return fd.WriteJSON(output, report)
}
```

A nil `Options.Policy` treats all changes as unexpected. A supplied policy is
validated whether it was constructed in Go or parsed with `ReadPolicy`.
Expected changes remain visible with their reasons. The
[policy guide](usage.md#mark-specific-changes-as-expected) explains exact matching.

Unexpected changes are a successful comparison result, not a Go error. Inspect
`report.Verdict` or `report.Counts.Unexpected` to decide what your application
should do. The CLI uses that same unexpected count to choose exit 0 or 1.
On a comparison error, `Compare` returns an empty `Report`.

## Handle errors and cancellation

Pass a non-nil context to `Compare`. This function sets a five-second deadline;
it uses the standard `context` and `time` packages and the `fd` import above:

```go
func CompareWithTimeout(baselineRoot, candidateRoot string) (fd.Report, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    return fd.Compare(ctx, baselineRoot, candidateRoot, fd.Options{})
}
```

Use `errors.Is(err, context.Canceled)` or
`errors.Is(err, context.DeadlineExceeded)` to recognize cancellation. Scanning
checks the context while walking directories, hashing files, and reading ELF
metadata, and preserves these errors through wrapping.

For other failures, use `errors.As` to inspect the error type:

| Type | Meaning |
| --- | --- |
| `*fd.InputError` | Invalid arguments or an unsupported host |
| `*fd.ScanError` | Missing, unreadable, malformed, or changing filesystem data |
| `*fd.PolicyError` | Invalid policy JSON or policy options |

Each type exposes `Op` and the underlying `Err`. `ScanError.Path` identifies the
path relative to the scanned root; it is empty for a failure at the root.
Errors unwrap their causes. Use `errors.Is` with `fd.ErrLimitExceeded`,
`fd.ErrInputChanged`, and `fd.ErrUnsupportedHost` when you need those specific
conditions rather than an error category. No file contents are included in scan
diagnostics.

`ReadPolicy` does not close its reader. Your application owns its lifetime; if
you read from a file, keep it unchanged while parsing. The report writers return
validation or I/O errors directly and have no context parameter. A writer may
fail after accepting some bytes. Buffer a report first if you need rendering to
finish before writing to its final destination.

## Work with report values

The public package exposes `Policy`, `Rule`, `Report`, `Change`, `Value`,
`Counts`, `Warning`, `Inventory`, `Entry`, `ELF`, and `Content`, along with their
constants, resource limits, and error types. You can use these without importing
an `internal` package. The types retain their validation and JSON methods.

If you construct reports yourself, use `NullValue`, `EntryValue`, `ContentValue`,
`StringValue`, `MachineValue`, or `NeededValue` for change values. These helpers
copy nested data. Both writers validate the report and sort a copy; they leave
your data, counts, verdict, and policy decisions unchanged. Inconsistent reports
are rejected rather than silently corrected.

## Run the complete example

The [source example](../examples/library/main.go) reads a policy, compares the
demo roots, uses both report writers, and handles typed errors and cancellation.
To run it with the prepared Linux container, start from a source checkout with
Git, Make, and Docker installed:

```sh
make prepare-linux
make library-linux
```

Preparation needs network access; the example runs offline in Linux amd64. On a
native Linux amd64 machine with the complete pinned development environment
already configured, you can instead run:

```sh
make demo
bash build/go.sh run ./examples/library
bash build/go.sh run ./examples/library --format json > dist/library.json
```

The [build guide](../build/README.md) explains the required Go and C tools.
These source commands are separate from installing the library in your own Go
project. The [example guide](../examples/library/README.md) explains its flags,
cancellation examples, and exit statuses.
