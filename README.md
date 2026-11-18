# FirmwareDelta

[![Latest release](https://img.shields.io/github/v/release/firmdura/firmwaredelta)](https://github.com/firmdura/firmwaredelta/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![Go package documentation](https://pkg.go.dev/badge/github.com/firmdura/firmwaredelta/pkg/firmwaredelta.svg)](https://pkg.go.dev/github.com/firmdura/firmwaredelta/pkg/firmwaredelta)

FirmwareDelta compares two extracted firmware filesystems and shows which files,
permissions, and symlink targets changed. It also reports the library dependency
names recorded in ELF files. ELF is a common format for Linux programs and shared
libraries. FirmwareDelta runs offline on Linux amd64 and is available as a
command-line tool and a Go library.

For example, a planned program rebuild may also change a configuration file or
add a shared library dependency. FirmwareDelta reports each change separately.
You can provide a policy that marks specific changes as expected while leaving
all other changes visible for review. An expected change records your intent;
it does not establish that the new firmware is safe or compatible.

## Use the command-line tool

Download the Linux amd64 archive from the
[v1.0.1 release](https://github.com/firmdura/firmwaredelta/releases/tag/v1.0.1).
On a 64-bit x86 Linux machine, unpack it and check the included file checksums:

```sh
tar -xzf firmwaredelta-v1.0.1-linux-amd64.tar.gz
cd firmwaredelta-v1.0.1-linux-amd64
sha256sum -c SHA256SUMS
./firmwaredelta --version
```

The binary needs no Go installation, compiler, Docker, or network connection.
Give it the directories containing the old and new extracted filesystems:

```sh
./firmwaredelta compare --baseline /snapshots/old-root \
  --candidate /snapshots/new-root --format json > report.json
```

A **root directory** is the top of an extracted firmware filesystem, usually
containing directories such as `etc/`, `usr/`, and `lib/`. Extract images with
your existing tools before comparing them, and keep both directories unchanged
during the comparison. FirmwareDelta reads their files without running firmware
programs or following symlinks.

Without a policy, every change is unexpected. The command's exit status tells
you how to interpret the result:

| Exit | Meaning |
| --- | --- |
| 0 | No changes, or every reported change matches a policy rule |
| 1 | The report contains changes that still need review |
| 2 | The comparison or report delivery failed |

Exit 1 still produces a valid report. Markdown is the default output format;
use `--format json` for structured output. Reports go to stdout and diagnostics
go to stderr. The [CLI guide](docs/usage.md) explains policy files, reports, and
error handling.

## Try a sample maintenance update

The source repository includes a small demo made from original C sources and
invented configuration files. With Git, Make, and Docker configured to run
Linux amd64 containers:

```sh
git clone https://github.com/firmdura/firmwaredelta.git
cd firmwaredelta
make prepare-linux
make library-linux
```

Cloning and preparation need network access. The final command builds the demo
and runs the Go library example inside the prepared Linux container, offline.
It prints five changes: one expected program rebuild and four other changes,
including a configuration edit and an added library dependency. The sample
firmware programs are compiled for inspection and never executed.

The [demo walkthrough](examples/demo/README.md) shows the corresponding CLI
commands and explains each reported change. On an ARM Mac, see the
[build guide](build/README.md) if your Docker runtime cannot run the pinned
amd64 toolchain reliably.

## Use the Go library

In an existing Go project, add the released module:

```sh
go get github.com/firmdura/firmwaredelta@v1.0.1
```

Import `github.com/firmdura/firmwaredelta/pkg/firmwaredelta`. The module requires
Go 1.27.0 or later; the repository's development tools use Go 1.27.4. Comparing
directories requires Linux amd64, while policy parsing and report rendering also
work on other hosts. See the [library guide](docs/library.md) and the
[Go API reference](https://pkg.go.dev/github.com/firmdura/firmwaredelta@v1.0.1/pkg/firmwaredelta)
for comparison, cancellation, and error handling.

## Build and contribute

The [build guide](build/README.md) covers building from source, the pinned Go and
C toolchains, offline tests, and local packaging. From a prepared source
checkout, `make verify-linux` runs the full tests and CLI acceptance checks in
the pinned Linux container. Generated files stay under `dist/`.

- [CLI, policy, and JSON reports](docs/usage.md)
- [Supported inputs and comparison limits](docs/limits.md)
- [Runnable Go example](examples/library/README.md)
- [Detailed version 1 contracts](docs/contracts.md)

## Where it fits

[diffoscope](https://diffoscope.org/) compares many file formats in depth,
including recursively unpacked archives. FirmwareDelta starts with extracted
filesystems and produces a focused report of file and metadata changes, with
explicit policy decisions. [Yocto buildhistory](https://docs.yoctoproject.org/dev-manual/build-quality.html)
records package, image, and SDK information during a build. FirmwareDelta can
compare directories from different build systems without their build history.

FirmwareDelta does not extract images, scan for vulnerabilities, test boot or
runtime behavior, or assess security, compliance, or binary compatibility.
Static library names and dependencies cannot establish those properties.
The [limits guide](docs/limits.md) explains what the report can and cannot tell
you.

## About Firmdura

This repository contains a standalone verification utility from
[Firmdura](https://firmdura.com). Firmdura's commercial offer is shared embedded
Linux security maintenance through versioned security layers or patch overlays
for agreed user-space components.

## License

Original code and synthetic test inputs are [Apache-2.0 licensed](LICENSE).
Binary bundles also include the Go runtime license.
