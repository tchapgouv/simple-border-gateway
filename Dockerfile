# syntax=docker/dockerfile:1-labs

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.87.0
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
  x86_64-unknown-linux-gnu

# Set the working directory
WORKDIR /app

ARG VERGEN_GIT_DESCRIBE
ENV VERGEN_GIT_DESCRIBE=${VERGEN_GIT_DESCRIBE}

# Build dependencies in a first layer for caching purpose
RUN mkdir -p /app/src
RUN echo "fn main() {}" > /app/src/main.rs

COPY ["Cargo.toml", "Cargo.lock",  "/app"]

# Network access: to fetch dependencies
RUN --network=default \
  cargo auditable build \
    --locked \
    --release

# Copy the code
COPY --exclude=.* --exclude=target ./ /app

RUN --network=none \
  cargo auditable build \
    --locked \
    --release \
    --target x86_64-unknown-linux-gnu \
  && mv "target/x86_64-unknown-linux-gnu/release/simple-border-gateway" /usr/local/bin/simple-border-gateway

###################
## Runtime stage ##
###################
FROM debian:${DEBIAN_VERSION}-slim
#FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

COPY --from=builder /usr/local/bin/simple-border-gateway /usr/local/bin/simple-border-gateway

WORKDIR /data

EXPOSE 8000/tcp 3128/tcp

ENTRYPOINT ["/usr/local/bin/simple-border-gateway"]
