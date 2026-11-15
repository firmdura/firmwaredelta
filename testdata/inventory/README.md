# Inventory test fixtures

Inventory tests create files, directory trees, literal symlinks, a FIFO and a
Unix socket in temporary directories. A FIFO is a named pipe; the tests
inventory its metadata without opening it for input or output.

The hand-built ELF headers in the tests and the C sources in
[`../elf-src/`](../elf-src/README.md) are original Apache-2.0 synthetic inputs.
Tests inspect them without running the generated programs. They also verify
that scanning records symlink targets literally and reads no special-file
contents.

Generated files stay in ignored `dist/` or temporary test directories. The
test suite needs no external firmware.
