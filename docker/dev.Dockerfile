# Dev and CI environment for eth-hw-signer, built once and reused.
# The image tag is a hash of this file and rust-toolchain.toml, so it is
# rebuilt only when one of them changes (see .github/workflows/ci.yml).
FROM rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2

LABEL org.opencontainers.image.source="https://github.com/Vany/eth-hw-signer"
LABEL org.opencontainers.image.description="eth-hw-signer dev/CI environment: Rust toolchain, Cortex-M33 target, arm-none-eabi GCC"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# git: actions/checkout inside the container; gcc-arm-none-eabi + newlib:
# blst's C code for the bare-metal Cortex-M33 target (thumbv8m.main-none-eabihf).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates zstd \
      gcc-arm-none-eabi libnewlib-arm-none-eabi \
 && rm -rf /var/lib/apt/lists/*

# Install the toolchain, components and targets named in rust-toolchain.toml.
COPY rust-toolchain.toml /opt/toolchain/rust-toolchain.toml
RUN cd /opt/toolchain && rustup toolchain install && rustup show active-toolchain \
 && rustc --version && arm-none-eabi-gcc --version | head -1

WORKDIR /work
