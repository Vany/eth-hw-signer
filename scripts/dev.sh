#!/bin/sh
# Run a command in the same environment CI uses, with the repo mounted at /work.
#   scripts/dev.sh                    # scripts/test.sh (cargo test, as CI runs it)
#   scripts/dev.sh cargo build -p signer-core --target thumbv8m.main-none-eabihf
# The image tag is the CI tag: sha256 of docker/dev.Dockerfile + rust-toolchain.toml.
set -eu
cd "$(dirname "$0")/.."
IMAGE=ghcr.io/vany/eth-hw-signer-dev
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
TAG=$(cat docker/dev.Dockerfile rust-toolchain.toml | $SHA | cut -c1-16)
if ! docker image inspect "$IMAGE:$TAG" >/dev/null 2>&1; then
  docker pull "$IMAGE:$TAG" 2>/dev/null \
    || docker build -f docker/dev.Dockerfile -t "$IMAGE:$TAG" .
fi
[ $# -gt 0 ] || set -- scripts/test.sh
exec docker run --rm -t -v "$PWD:/work" -v eth-hw-signer-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/work/target/dev-image -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$IMAGE:$TAG" "$@"
