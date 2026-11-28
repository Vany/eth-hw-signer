# Dev and CI environment for eth-hw-signer, built once and reused.
# The image tag is a hash of this file and rust-toolchain.toml, so it is
# rebuilt only when one of them changes (see .github/workflows/ci.yml).
FROM rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2

LABEL org.opencontainers.image.source="https://github.com/Vany/eth-hw-signer"
LABEL org.opencontainers.image.description="eth-hw-signer dev/CI environment: Rust toolchain, Cortex-M33 target, arm-none-eabi GCC, Vault, OpenSSL"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# git: actions/checkout inside the container; gcc-arm-none-eabi + newlib:
# blst's C code for the bare-metal Cortex-M33 target (thumbv8m.main-none-eabihf).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates zstd \
      gcc-arm-none-eabi libnewlib-arm-none-eabi \
      openssl curl unzip \
 && rm -rf /var/lib/apt/lists/*

# vault + openssl: the real-Vault tests (router/tests/vault_real.rs) start
# throwaway dev Vaults with throwaway client certificates. Pinned by version
# and by the sha256 HashiCorp publishes for it.
ARG VAULT_VERSION=2.2.2
ARG TARGETARCH
RUN case "${TARGETARCH:-amd64}" in \
      amd64) sum=5700edf139113609962fe371af7d2a53de8ecb720d545dc39b43de204515d3c4 ;; \
      arm64) sum=78634c8672601ad1ca9b27f24e76c54224d12521c59ece957ab8d23976ddca12 ;; \
      *) echo "no vault checksum for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH:-amd64}.zip" \
 && echo "$sum  /tmp/vault.zip" | sha256sum -c - \
 && unzip -q /tmp/vault.zip -d /usr/local/bin vault \
 && rm /tmp/vault.zip && vault version

# Install the toolchain, components and targets named in rust-toolchain.toml.
COPY rust-toolchain.toml /opt/toolchain/rust-toolchain.toml
RUN cd /opt/toolchain && rustup toolchain install && rustup show active-toolchain \
 && rustc --version && arm-none-eabi-gcc --version | head -1

WORKDIR /work
