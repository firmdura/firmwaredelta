# A sample firmware maintenance update

This demo shows why allowing one planned change should leave other changes
visible. The new firmware contains a rebuilt program, a configuration edit,
a rebuilt shared library, and an additional library dependency. A small policy
marks only the program's content change as expected.

The example uses original Apache-2.0 C sources and invented configuration files.
It contains no external firmware. The build compiles the sample programs and
reads their ELF metadata; it never runs them.

## Prepare the example

From the source repository directory, with Make and Docker configured to run
Linux amd64 containers:

```sh
make prepare-linux
make demo-linux
```

Preparation downloads the pinned image and Go modules, so it needs network
access. The demo build then runs offline. It creates the Linux CLI at
`dist/firmwaredelta` and two extracted filesystem directories at
`dist/demo/baseline` and `dist/demo/candidate`, plus `dist/demo/policy.json`.
The [build guide](../../build/README.md) covers Docker setup and the ARM Mac
fallback.

On native Linux amd64, you can use `make build demo` after configuring the full
pinned Go and C toolchains described in that guide. `make prepare` alone does
not install the compiler tools.

## Compare the two versions

The following commands run the generated CLI directly, so they require a Linux
amd64 host. From the repository directory, compare without a policy:

```sh
dist/firmwaredelta compare --baseline dist/demo/baseline \
  --candidate dist/demo/candidate --format json > dist/demo-without-policy.json
echo "$?"
```

The exit status is **1**, and the JSON report contains five unexpected changes.
Exit 1 means the comparison succeeded and found changes for review. The report
is saved outside the input directories.

Now compare with the supplied policy and read the Markdown report:

```sh
dist/firmwaredelta compare --baseline dist/demo/baseline \
  --candidate dist/demo/candidate --policy dist/demo/policy.json \
  --format markdown > dist/demo-with-policy.md
echo "$?"
cat dist/demo-with-policy.md
```

This also exits **1**: the policy acknowledges one change while four others
remain unexpected. These commands assume an interactive shell. In a script
using `set -e`, handle the comparison with an `if` statement so that exit 1 does
not stop the script before you can read the result.

On macOS or another host, run `make library-linux` to see the same comparison
through the Go example inside the Linux container. That example prints the
report and exits 0 after a completed comparison; it leaves the decision about
unexpected changes to its caller.

## What the policy allows

The supplied policy is:

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

The path and field must both match. The resulting report keeps all five records:

| Path | Field | Result with policy |
| --- | --- | --- |
| `etc/maintenance.conf` | `content` | unexpected configuration change |
| `usr/bin/maintenance` | `content` | expected program rebuild, with the supplied reason |
| `usr/bin/maintenance` | `elf.needed` | unexpected dependency on `libextra.so.1` |
| `usr/lib/libextra.so.1` | `presence` | unexpected new library file |
| `usr/lib/libmaintenance.so.1` | `content` | unexpected library rebuild |

The counts are `total: 5`, `expected: 1`, and `unexpected: 4`. The verdict is
`unexpected_changes`, with no unused-rule warnings. Counts refer to individual
changes, so the program's content and dependency changes count separately.

ELF is the format used by these sample Linux programs and shared libraries.
The program still records dependencies on `libmaintenance.so.1` and `libc.so.6`;
`libextra.so.1` is an additional dependency. These are static observations, not
claims about compatibility. The configuration record contains its size and
SHA-256 hash, never the configuration text.

For exit **0**, compare `dist/demo/baseline` with itself. For exit **2**, use a
missing root; the command writes an error to stderr and leaves stdout empty.
`make acceptance-linux` checks these cases along with the demo, input
preservation, and repeatable output.

## Regenerate or customize the demo

The preparation script accepts one absolute output directory under this
checkout's `dist/`:

```sh
bash examples/demo/prepare.sh "$(pwd -P)/dist/demo"
```

Run it only in the pinned Linux development environment. It prepares a complete
replacement before moving it into the output directory. It accepts an empty
directory or a previous demo it created, and refuses a symlink or an unrelated
nonempty directory. Keep your own extracted firmware elsewhere.

Regenerating the demo removes everything in that demo directory, including
reports saved there. Packaging also regenerates `dist/demo`. The report paths
shown above are outside it, so you can keep those reports when rebuilding the
demo.
