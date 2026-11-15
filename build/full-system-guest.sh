#!/usr/bin/env bash
# Run inside the dedicated ARM64 Colima VM, not on the macOS host.
set -euo pipefail
repo_dir=${1:?repository path is required}
cd "$repo_dir/dist/native-amd64"
if test -f qemu.pid; then
  qemu_pid=$(cat qemu.pid)
  [[ "$qemu_pid" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'Invalid owned VM PID file.' >&2; exit 1; }
  if kill -0 "$qemu_pid" 2>/dev/null; then
    python3 - "$qemu_pid" "$PWD" <<'PY'
import os, pathlib, shutil, sys
pid, expected_dir = sys.argv[1:]
proc = pathlib.Path('/proc') / pid
args = (proc / 'cmdline').read_bytes().split(b'\0')
disk = pathlib.Path(expected_dir) / 'guest.qcow2'
expected_exe = pathlib.Path(shutil.which('qemu-system-x86_64')).resolve()
def require(condition, message):
    if not condition:
        sys.exit(message)
require((proc / 'exe').resolve() == expected_exe, 'PID is not the expected QEMU executable')
# QEMU's daemon changes cwd to / after opening its disk and other files.
require(b'-daemonize' in args and (proc / 'cwd').resolve() == pathlib.Path('/'), 'PID is not the expected daemonized process')
require(any(args[i:i+2] == [b'-name', b'firmwaredelta-amd64'] for i in range(len(args)-1)), 'PID has another VM name')
disk_args = {b'file=guest.qcow2,if=virtio,format=qcow2', f'file={disk},if=virtio,format=qcow2'.encode()}
require(any(args[i] == b'-drive' and args[i+1] in disk_args for i in range(len(args)-1)), 'PID has another disk command')
require(not disk.is_symlink(), 'VM disk is an unexpected symbolic link')
disk_stat = disk.stat()
require(any((os.stat(fd).st_dev, os.stat(fd).st_ino) == (disk_stat.st_dev, disk_stat.st_ino)
            for fd in (proc / 'fd').iterdir()), 'PID is not using the expected disk inode')
PY
    printf '%s\n' 'The dedicated x86 Linux VM is already running and its identity matches.'
    exit 0
  fi
fi
if ! test -f guest.qcow2; then
  qemu-img create -f qcow2 -F qcow2 -b base.img guest.qcow2 20G
fi
cloud-localds seed.img user-data meta-data
qemu-system-x86_64 -name firmwaredelta-amd64 -machine q35,accel=tcg \
  -cpu max -smp 2 -m 2048 -display none -daemonize \
  -serial file:console.log -pidfile qemu.pid \
  -monitor unix:monitor.sock,server=on,wait=off \
  -drive "file=$PWD/guest.qcow2,if=virtio,format=qcow2" \
  -drive "file=$PWD/seed.img,if=virtio,format=raw" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22228-:22 \
  -device virtio-net-pci,netdev=net0 \
  -virtfs "local,path=$repo_dir,mount_tag=source,security_model=none,readonly=on" \
  -virtfs "local,path=$repo_dir/dist,mount_tag=outputs,security_model=none"
printf '%s\n' 'Booting a dedicated x86 Linux kernel with full-system TCG.'
