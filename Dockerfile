# syntax=docker/dockerfile:1

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=13
ARG DEBIAN_VERSION_NAME=trixie
ARG RUSTC_VERSION=1.98.1
ARG CARGO_AUDITABLE_VERSION=0.7.6

########################################
## Build stage that builds the binary ##
########################################
FROM docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder

ARG CARGO_AUDITABLE_VERSION
ARG RUSTC_VERSION

WORKDIR /app

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
    --mount=type=cache,target=/usr/local/cargo/registry \
  cargo install --locked \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

# Build the dependencies in a dedicated layer, so that changing the application
# sources below only rebuilds the workspace crates instead of the whole
# dependency tree. The workspace crates are stubbed out for this step.
# Network access: to fetch dependencies
COPY Cargo.toml Cargo.lock .
RUN --network=default \
    --mount=type=cache,target=/usr/local/cargo/registry \
  mkdir -p src \
  && echo 'fn main() {}' > src/main.rs \
  && touch src/lib.rs \
  && cargo auditable build \
    --locked \
    --release \
  && rm -rf src

COPY . .

# BuildKit copies the files with their original timestamps, which are older than
# the artifacts produced by the stub build above. Cargo then considers the
# workspace crate up to date and silently keeps the stub binary instead of
# compiling the real sources, so let's touch the source files to force a rebuild.
# Network access: to fetch dependencies
RUN --network=default \
    --mount=type=cache,target=/usr/local/cargo/registry \
  touch src/main.rs src/lib.rs \
  && cargo auditable build \
    --locked \
    --release \
  && mv "target/release/simple-border-gateway" /usr/local/bin/simple-border-gateway

###################
## Runtime stage ##
###################
#FROM debian:${DEBIAN_VERSION}-slim
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

COPY --from=builder /usr/local/bin/simple-border-gateway /usr/local/bin/simple-border-gateway

WORKDIR /data

EXPOSE 8000/tcp 3128/tcp

ENTRYPOINT ["/usr/local/bin/simple-border-gateway"]
