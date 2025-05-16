# syntax = docker/dockerfile:1.7.1

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.

ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.86.0
ARG CARGO_AUDITABLE_VERSION=0.6.6

########################################
## Build stage that builds the binary ##
########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder

ARG CARGO_AUDITABLE_VERSION
ARG RUSTC_VERSION

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

# Install all cross-compilation targets
# Network access: to download the targets
RUN --network=default \
  rustup target add  \
  --toolchain "${RUSTC_VERSION}" \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu

RUN --network=none \
  dpkg --add-architecture arm64 && \
  dpkg --add-architecture amd64

ARG BUILDPLATFORM

# Install cross-compilation toolchains for all supported targets
# Network access: to install apt packages
RUN --network=default \
  apt-get update && apt-get install -y \
  $(if [ "${BUILDPLATFORM}" != "linux/arm64" ]; then echo "g++-aarch64-linux-gnu"; fi) \
  $(if [ "${BUILDPLATFORM}" != "linux/amd64" ]; then echo "g++-x86-64-linux-gnu"; fi) \
  libc6-dev-amd64-cross \
  libc6-dev-arm64-cross \
  g++

# Setup the cross-compilation environment
ENV \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
  CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
  CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++

# Set the working directory
WORKDIR /app

# Copy the code
COPY ./ /app

# Network access: cargo auditable needs it
RUN --network=default \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/app/target \
  cargo auditable build \
    --locked \
    --release \
    --target x86_64-unknown-linux-gnu \
    --target aarch64-unknown-linux-gnu \
  && mv "target/x86_64-unknown-linux-gnu/release/simple-border-gateway" /usr/local/bin/simple-border-gateway-amd64 \
  && mv "target/aarch64-unknown-linux-gnu/release/simple-border-gateway" /usr/local/bin/simple-border-gateway-arm64

###################
## Runtime stage ##
###################
FROM docker.io/library/debian:${DEBIAN_VERSION_NAME}-slim

ARG TARGETARCH
COPY --from=builder /usr/local/bin/simple-border-gateway-${TARGETARCH} /usr/local/bin/simple-border-gateway

RUN mkdir -p /data

WORKDIR /data

EXPOSE 8000/tcp 3128/tcp

ENTRYPOINT ["/usr/local/bin/simple-border-gateway"]
