# Run a comparison from Go

This program shows how to embed FirmwareDelta: read a policy, compare two
filesystem directories, write JSON or Markdown, and handle errors or
cancellation. It imports only the public FirmwareDelta package and the Go
standard library. See the [library guide](../../docs/library.md) to add the
released module to your own project.

## Run the example with Docker

From a source checkout, with Make and Docker configured for Linux amd64:

```sh
make prepare-linux
make library-linux
```

The first command downloads the pinned image and Go modules. The second creates
the original demo and runs this program offline inside Linux. It prints the
Markdown report: one expected change and four unexpected changes.

## Run directly on Linux

On a Linux amd64 host, first configure the pinned Go and C development tools
from the [build guide](../../build/README.md). Then, from the repository
directory:

```sh
make demo
bash build/go.sh run ./examples/library
bash build/go.sh run ./examples/library --format json > dist/library.json
```

The wrapper uses the prepared Go toolchain without downloading modules. When
`go` itself is already the exact prepared toolchain, `go run ./examples/library`
also works. These commands run on the host; they do not start a Docker
container.

## Choose inputs and output

The example defaults to the generated demo. Its flags are:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--baseline` | `dist/demo/baseline` | Old extracted filesystem |
| `--candidate` | `dist/demo/candidate` | New extracted filesystem |
| `--policy` | `dist/demo/policy.json` | Policy file; use `--policy ''` to make every change unexpected |
| `--format` | `markdown` | Choose `json` or `markdown` |
| `--timeout` | `0` | Optional scan deadline, such as `5s`; zero means no deadline |
| `--cancel` | `false` | Cancel before scanning, to demonstrate error handling |

The program renders both formats from the same report before writing the chosen
format. Ctrl+C also cancels a running comparison. The source shows how to use
`errors.Is` for cancellation and `errors.As` for typed errors.

## Understand the exit status

This is a library example, so a completed comparison exits **0**, even if the
report contains unexpected changes. Your application decides how to act on
`report.Verdict`. The FirmwareDelta CLI instead returns 1 when unexpected
changes remain.

An example error exits **2**. To see the program's own exit status, build and
run it directly on Linux:

```sh
bash build/go.sh build -o dist/library-example ./examples/library
dist/library-example --cancel
echo "$?"
```

This prints `comparison canceled` to stderr, leaves stdout empty, and reports
exit 2. Running `dist/library-example --timeout 1ns` similarly reports
`comparison deadline exceeded` and exits 2. In a script using `set -e`, handle
these deliberate failures with an `if` statement.

When an example error is run through `go run`, the Go launcher returns its own
nonzero status and prints `exit status 2`; that launcher status is not the
program's direct exit status.
