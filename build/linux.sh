#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source build/toolchain.env
repo_dir=$(pwd -P)
mkdir -p dist/cache/linux-amd64/go dist/cache/mod
docker_cmd=(docker)
if test -n "${FIRMWAREDELTA_DOCKER_CONTEXT:-}"; then
  docker_cmd+=(--context "$FIRMWAREDELTA_DOCKER_CONTEXT")
fi

docker_args=(run --rm --pull never --platform linux/amd64
  --read-only --cap-drop ALL --security-opt no-new-privileges
  --user "$(id -u):$(id -g)" --workdir /src
  --mount "type=bind,src=$repo_dir,dst=/src,readonly"
  --mount "type=bind,src=$repo_dir/dist,dst=/src/dist"
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777
  --env GOCACHE=/src/dist/cache/linux-amd64/go --env GOMODCACHE=/src/dist/cache/mod
  --env GOTOOLCHAIN=local)

case "${1:-}" in
  prepare)
    "${docker_cmd[@]}" pull --platform linux/amd64 "$LINUX_IMAGE"
    "${docker_cmd[@]}" "${docker_args[@]}" --env GOPROXY=https://proxy.golang.org \
      --env GOSUMDB=sum.golang.org "$LINUX_IMAGE" go mod download all
    ;;
  foundation)
    "${docker_cmd[@]}" "${docker_args[@]}" --network none --env GOPROXY=off --env GOSUMDB=off \
      "$LINUX_IMAGE" make GO_BUILD_CACHE=/src/dist/cache/linux-amd64/go verify validate-schemas compiler-probe
    ;;
  verify)
    "${docker_cmd[@]}" "${docker_args[@]}" --network none --env GOPROXY=off --env GOSUMDB=off \
      "$LINUX_IMAGE" make GO_BUILD_CACHE=/src/dist/cache/linux-amd64/go verify acceptance
    ;;
  acceptance|demo|library|package)
    case "$1" in
      acceptance) goals=(acceptance) ;;
      demo) goals=(build demo) ;;
      library) goals=(demo library) ;;
      package) goals=(package) ;;
    esac
    "${docker_cmd[@]}" "${docker_args[@]}" --network none --env GOPROXY=off --env GOSUMDB=off \
      "$LINUX_IMAGE" make GO_BUILD_CACHE=/src/dist/cache/linux-amd64/go "${goals[@]}"
    ;;
  *)
    printf '%s\n' 'Usage: bash build/linux.sh prepare|foundation|verify|acceptance|demo|library|package' >&2
    exit 2
    ;;
esac
