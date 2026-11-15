# Build and verification guide

Run these commands from the source repository root. FirmwareDelta compares
filesystems on Linux amd64. Docker provides the same Linux environment on other
development hosts; the compiled CLI needs neither Docker nor build tools.

The versions in [`build/toolchain.env`](https://github.com/firmdura/firmwaredelta/blob/main/build/toolchain.env) are fixed so developers use
the same tools: Go 1.27.4, GCC 12.2.0 (Debian package
`12.2.0-14+deb12u1`) and binutils package `2.40-2`. The Docker image is
selected by its content digest, which fixes its contents rather than following
a moving tag. Go 1.27.4 was the current stable release when checked against the
[official download API](https://go.dev/dl/?mode=json) on 2026-11-15.

## Verify with Docker

Install Docker with support for Linux amd64 containers, plus Bash and Make.
On an arm64 host, Docker also needs amd64 emulation. Run these commands as a
regular user: acceptance checks unreadable files and refuses to run as root.

First prepare the environment with network access:

```sh
make prepare-linux
```

This downloads the exact image and the Go modules needed by the tests. Modules
are cached in ignored `dist/cache/mod/`. It does not run the tests. Once setup
finishes, run the full offline checks:

```sh
make verify-linux
```

This runs `make verify` and `make acceptance` inside the prepared image. The
container has no network access, uses your user ID, and mounts the source tree
read-only. Only `dist/` and temporary space are writable. Go module downloads
and checksum lookups are disabled. Tests compile small original ELF fixtures
and inspect them; no firmware executable is run.

The other container targets use the same environment:

| Command | What it does |
| --- | --- |
| `make foundation-linux` | Runs formatting, vet, race tests, schema examples and a compiler probe; omits CLI acceptance |
| `make acceptance-linux` | Runs CLI acceptance alone |
| `make demo-linux` | Builds the CLI and creates `dist/demo/` from original sources |
| `make library-linux` | Creates the demo and prints its policy comparison through the Go API as Markdown |
| `make package-linux` | Builds and checks a local Linux amd64 binary bundle |

`demo-linux`, `library-linux` and `package-linux` regenerate `dist/demo/`,
including any reports saved there. Move reports you want to keep elsewhere
before running them. None of these targets publishes a release.

To use a particular Docker context without changing the default context, set
`FIRMWAREDELTA_DOCKER_CONTEXT` for the command. Its Docker daemon must be able
to bind-mount this checkout and `dist/` at the same absolute paths used on your
host; a remote daemon needs those shares configured first.

```sh
FIRMWAREDELTA_DOCKER_CONTEXT=my-amd64-host make prepare-linux
FIRMWAREDELTA_DOCKER_CONTEXT=my-amd64-host make verify-linux
```

Container builds use `dist/cache/linux-amd64/go/`, separate from the native Go
build cache. Compiler and linker work runs in the container's Linux `/tmp`
filesystem because shared filesystems such as 9p may not support the writable
memory mappings that linking requires. That temporary mount allows generated
Go test programs to run and retains the `nosuid,nodev` restrictions.

## Verify directly on Linux amd64

Use a **non-root Linux amd64 user** with Go 1.27.4 installed on your shell's
`PATH`, GCC 12.2.0 from Debian package `gcc-12=12.2.0-14+deb12u1`, and
`binutils=2.40-2`. The compiler check uses `dpkg-query` to verify the Debian
package versions. You also need Bash, Make, Python 3 and `readelf`; packaging
needs GNU tar, gzip and `sha256sum`. If your host does not match these
requirements, use the Docker instructions instead.

From a clean source checkout, prepare the Go modules and run the native checks:

```sh
make prepare             # network-enabled Go toolchain/module setup
make verify              # offline formatting, vet and race tests
make acceptance          # offline CLI and library acceptance
make demo                # original demo; compiles fixtures without running them
bash build/go.sh run ./examples/library
make package             # local archive and checksums
```

The native `make prepare` command needs an installed Go launcher with toolchain
download support. It can cache the required Go toolchain as well as modules.
The recipes use `build/go.sh` to invoke that exact installed version directly,
with automatic downloads disabled. This cache does not replace the native
compiler-check prerequisite: `go` on `PATH` must also be Go 1.27.4.

`make verify` runs `go vet ./...` and `go test -race ./...`, including CLI
process and input-immutability tests. `make acceptance` checks real CLI exits,
policy matching, static ELF metadata, JSON and Markdown, confidentiality,
unchanged inputs and byte-identical repeats. It also checks that the library
example and CLI produce the same JSON report. Unreadability checks require the
non-root user described above.

To run the example with plain `go run ./examples/library`, first make sure
`go` is the exact prepared toolchain and the demo exists. For a focused offline
test, use the wrapper directly:

```sh
bash build/go.sh test ./internal/model -run TestContract -count=1
```

Native setup does not prepare Docker. To repeat the checks in the isolated
container, install Docker and run `make prepare-linux` before
`make verify-linux`, as described above. Checks on another operating system
cannot establish Linux comparison behavior.

## Demo and local packages

`make demo` runs `examples/demo/prepare.sh` with this checkout's absolute
`dist/demo/` path. It builds a complete temporary demo, then replaces an empty
destination or a previous demo bearing its ownership marker. It refuses an
unowned nonempty directory or a symlink destination. Regeneration removes
reports saved inside that demo directory. See the
[demo walkthrough](../examples/demo/README.md) for comparisons and expected
results.

`make elf-fixtures` builds the original C inputs into `dist/elf-fixtures/`.
The builder checks the compiler version and uses `readelf` to inspect the
results. Linux inventory tests require this fixture build; missing tools or
wrong versions fail the tests instead of skipping them.

`make package` and `make package-linux` both rebuild the CLI and regenerate
the owned `dist/demo/` directory, removing reports saved there. Keep reports
outside that directory before packaging. The outputs are:

- `dist/firmwaredelta`, the raw Linux amd64 CLI;
- `dist/firmwaredelta-v1.0.0-linux-amd64.tar.gz`, the binary bundle;
- `dist/SHA256SUMS`, covering the raw CLI and archive.

The bundle contains the CLI, documentation, schemas, a Go example source file,
the Apache license and the Go runtime BSD notice. It contains only the files
explicitly listed in `scripts/package.sh`, never the whole `dist/` directory.
Demo generation and development commands require a source checkout; the bundle
includes their documentation as reference material.

Packaging checks the archive's actual members, modes, checksums and notices,
then runs the extracted CLI against the demo. To inspect the result yourself
on Linux amd64:

```sh
(cd dist && sha256sum -c SHA256SUMS)
mkdir -p dist/package-preview
tar -xzf dist/firmwaredelta-v1.0.0-linux-amd64.tar.gz -C dist/package-preview
if dist/package-preview/firmwaredelta-v1.0.0-linux-amd64/firmwaredelta compare \
  --baseline dist/demo/baseline --candidate dist/demo/candidate \
  --policy dist/demo/policy.json --format json > dist/package-preview/demo.json; then
  status=0
else
  status=$?
fi
test "$status" -eq 1
```

Exit 1 is the expected demo result: its narrow policy leaves configuration,
library and dependency changes unexpected. Local packaging replaces its own
outputs in `dist/`; it does not publish or replace GitHub release assets.

## ARM Mac fallback with a complete x86 Linux kernel

Use this optional fallback if your Docker runtime's amd64 userspace emulator
cannot run the toolchain. A native amd64 Linux Docker host is another option.
Older QEMU userspace versions can corrupt Go/compiler memory; see the
[Go upstream investigation](https://github.com/golang/go/issues/77572).

The bootstrap requires an ARM Mac, Colima, Docker CLI, Python 3, curl and SSH.
Preparation needs network access:

```sh
bash build/full-system.sh prepare
bash build/full-system.sh connect
FIRMWAREDELTA_DOCKER_CONTEXT=firmwaredelta-amd64 make prepare-linux
FIRMWAREDELTA_DOCKER_CONTEXT=firmwaredelta-amd64 make verify-linux
```

It creates a dedicated `firmwaredelta-verify` Colima profile with 2 CPUs,
4 GiB RAM and a 20 GiB data disk. The repository is its only host share, and it
does not activate the profile's Docker context automatically. Inside that
profile, QEMU boots a separate x86 Linux kernel with 2 CPUs, 2 GiB RAM and a
sparse 20 GiB disk. The official Ubuntu image URL, checksum and QEMU version
are fixed in `full-system.env`. This runs a complete x86 system rather than
emulating individual Linux system calls.

Generated VM disks, SSH keys, logs, sockets and ownership records stay in
ignored `dist/native-amd64/`; installed guest packages stay in the guest.
Preserve that directory while the VM is in use. SSH listens only on loopback,
and two SSH-protected Unix-socket forwards connect Docker to the guest. The
`firmwaredelta-amd64` context leaves your default Docker context unchanged.

The guest mounts source read-only and `dist/` writable; the verification
container adds its own read-only source mount and disables networking. Run
`bash build/full-system.sh status` to inspect the guest kernel and Docker
daemon. Reconnecting checks the guest, mounts and Docker identity before
reusing them. Existing profiles, contexts, processes or sockets with mismatched
ownership are rejected rather than replaced.

Keep the environment running during verification. It is a development aid;
the released CLI has no VM, Docker, compiler, Python or network dependency.
