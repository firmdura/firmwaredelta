#!/usr/bin/env bash
# Optional local bootstrap: a complete x86 Linux kernel inside a dedicated ARM VM.
set -euo pipefail
cd "$(dirname "$0")/.."
source build/full-system.env
repo_dir=$(pwd -P)
vm_dir="$repo_dir/dist/native-amd64"
mkdir -p "$vm_dir"

guest_ssh() {
  local guest_command
  printf -v guest_command '%q ' "$@"
  colima ssh --profile "$VM_PROFILE" -- ssh -i "$vm_dir/id_ed25519" \
    -p 22228 -o BatchMode=yes -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$vm_dir/inner-known-hosts" \
    firmwaredelta@127.0.0.1 "$guest_command"
}

ownership() {
  python3 build/full-system-state.py "$1" "$repo_dir" "$VM_PROFILE" "${@:2}"
}

case "${1:-}" in
  prepare)
    test "$(uname -s)" = Darwin && test "$(uname -m)" = arm64 || {
      printf '%s\n' 'This optional bootstrap requires an ARM Mac with Colima/VZ.' >&2
      exit 1
    }
    profile_list=$(colima list --json)
    profile_present=$(printf '%s\n' "$profile_list" | python3 -c 'import json,sys; print("yes" if any(json.loads(line)["name"] == sys.argv[1] for line in sys.stdin if line.strip()) else "no")' "$VM_PROFILE")
    if test "$profile_present" = yes; then
      ownership profile-check
    elif test -e "$vm_dir/owner.json"; then
      printf '%s\n' 'The recorded dedicated profile is missing; inspect it before recreating.' >&2
      exit 1
    fi
    outer_context="colima-$VM_PROFILE"
    if docker context inspect "$outer_context" >/dev/null 2>&1; then
      ownership profile-check
      expected_outer_endpoint=$(ownership profile-endpoint)
      test "$(docker context inspect "$outer_context" --format '{{.Endpoints.docker.Host}}')" = "$expected_outer_endpoint" || {
        printf '%s\n' 'The outer Colima context name belongs to another endpoint; refusing startup.' >&2
        exit 1
      }
    fi
    colima start "$VM_PROFILE" --runtime docker --arch aarch64 --vm-type vz \
      --activate=false --vz-rosetta=false --binfmt=false --cpus 2 --memory 4 --disk 20 \
      --mount "$repo_dir:w" --ssh-config=false --mount-inotify=false --template=false
    ownership profile-record
    colima ssh --profile "$VM_PROFILE" -- sudo apt-get update
    colima ssh --profile "$VM_PROFILE" -- sudo env DEBIAN_FRONTEND=noninteractive \
      apt-get install -y --no-install-recommends \
      "qemu-system-x86=$VM_QEMU_PACKAGE" "qemu-utils=$VM_QEMU_PACKAGE" cloud-image-utils=0.33-1
    if ! test -f "$vm_dir/base.img"; then
      curl -fL --retry 2 "$VM_IMAGE_URL" -o "$vm_dir/base.img"
    fi
    test "$(shasum -a 256 "$vm_dir/base.img" | cut -d ' ' -f 1)" = "$VM_IMAGE_SHA256"
    if ! test -f "$vm_dir/id_ed25519"; then
      ssh-keygen -q -t ed25519 -N '' -C firmwaredelta-local-verification -f "$vm_dir/id_ed25519"
    fi
    python3 - "$repo_dir" <<'PY'
import json, os, pathlib, sys
repo = pathlib.Path(sys.argv[1])
vm = repo / 'dist/native-amd64'
pub = (vm / 'id_ed25519.pub').read_text().strip()
data = {
    'hostname': 'firmwaredelta-amd64',
    'users': [{'name': 'firmwaredelta', 'uid': os.getuid(), 'groups': ['adm', 'sudo'],
               'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash',
               'lock_passwd': True, 'ssh_authorized_keys': [pub]}],
    'ssh_pwauth': False, 'package_update': True, 'packages': ['docker.io'],
    'bootcmd': [['mkdir', '-p', str(repo)]],
    'mounts': [['source', str(repo), '9p', 'ro,trans=virtio,version=9p2000.L,msize=1048576', '0', '0'],
               ['outputs', str(repo / 'dist'), '9p', 'rw,trans=virtio,version=9p2000.L,msize=1048576', '0', '0']],
    'runcmd': [['usermod', '-aG', 'docker', 'firmwaredelta'], ['systemctl', 'enable', '--now', 'docker']],
}
(vm / 'user-data').write_text('#cloud-config\n' + json.dumps(data, indent=2) + '\n')
(vm / 'meta-data').write_text('instance-id: firmwaredelta-amd64-v1\nlocal-hostname: firmwaredelta-amd64\n')
PY
    colima ssh --profile "$VM_PROFILE" -- bash "$repo_dir/build/full-system-guest.sh" "$repo_dir"
    printf '%s\n' 'Wait for initial cloud-init (Docker installation), then run: bash build/full-system.sh connect'
    ;;
  connect)
    ownership profile-check
    endpoint="unix://$vm_dir/docker.sock"
    if docker context inspect "$VM_CONTEXT" >/dev/null 2>&1; then
      test "$(docker context inspect "$VM_CONTEXT" --format '{{.Endpoints.docker.Host}}')" = "$endpoint" || {
        printf '%s\n' 'The context name already belongs to another endpoint; refusing reuse.' >&2
        exit 1
      }
    fi
    guest_ssh sudo timeout 900 cloud-init status --wait
    test "$(guest_ssh uname -m)" = x86_64
    test "$(guest_ssh docker info --format '{{.OSType}}')" = linux
    guest_arch=$(guest_ssh docker info --format '{{.Architecture}}')
    test "$guest_arch" = x86_64 || test "$guest_arch" = amd64
    test "$(guest_ssh findmnt -n -o FSTYPE "$repo_dir")" = 9p
    case ",$(guest_ssh findmnt -n -o OPTIONS "$repo_dir")," in
      *,ro,*) ;;
      *) printf '%s\n' 'The guest source mount is not read-only.' >&2; exit 1 ;;
    esac
    machine_id=$(guest_ssh cat /etc/machine-id)
    docker_id=$(guest_ssh docker info --format '{{.ID}}')
    ownership guest-check-or-record "$machine_id" "$docker_id"
    guest_ssh uname -a
    if docker context inspect "$VM_CONTEXT" >/dev/null 2>&1; then
      connected_id=$(docker --context "$VM_CONTEXT" info --format '{{.ID}}' 2>/dev/null || true)
      if test "$connected_id" = "$docker_id"; then
        printf '%s\n' 'The dedicated context is already connected to the verified x86 Linux guest.'
        exit 0
      fi
    fi
    outer_socket=/tmp/firmwaredelta-amd64-docker.sock
    test ! -e "$vm_dir/docker.sock" && test ! -e "$vm_dir/host-ssh-control" || {
      printf '%s\n' 'An existing local socket/control path needs inspection; refusing replacement.' >&2
      exit 1
    }
    colima ssh --profile "$VM_PROFILE" -- test ! -e "$outer_socket"
    colima ssh --profile "$VM_PROFILE" -- test ! -e /tmp/firmwaredelta-amd64-ssh-control
    colima ssh --profile "$VM_PROFILE" -- ssh -M -S /tmp/firmwaredelta-amd64-ssh-control \
      -fN -i "$vm_dir/id_ed25519" -p 22228 -o BatchMode=yes -o ExitOnForwardFailure=yes \
      -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$vm_dir/inner-known-hosts" \
      -L "$outer_socket:/var/run/docker.sock" firmwaredelta@127.0.0.1
    colima ssh-config "$VM_PROFILE" > "$vm_dir/outer-ssh-config"
    ssh -F "$vm_dir/outer-ssh-config" -M -S "$vm_dir/host-ssh-control" \
      -o ExitOnForwardFailure=yes -fN \
      -L "$vm_dir/docker.sock:$outer_socket" "colima-$VM_PROFILE"
    if docker context inspect "$VM_CONTEXT" >/dev/null 2>&1; then
      test "$(docker context inspect "$VM_CONTEXT" --format '{{.Endpoints.docker.Host}}')" = "$endpoint"
    else
      docker context create "$VM_CONTEXT" --docker "host=$endpoint"
    fi
    test "$(docker --context "$VM_CONTEXT" info --format '{{.ID}}')" = "$docker_id"
    docker --context "$VM_CONTEXT" version
    printf 'Use FIRMWAREDELTA_DOCKER_CONTEXT=%s with the Linux Make targets.\n' "$VM_CONTEXT"
    ;;
  status)
    colima status --profile "$VM_PROFILE"
    guest_ssh uname -a
    docker --context "$VM_CONTEXT" version
    ;;
  *)
    printf '%s\n' 'Usage: bash build/full-system.sh prepare|connect|status' >&2
    exit 2
    ;;
esac
