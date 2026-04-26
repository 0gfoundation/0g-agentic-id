# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the three attestor binaries (api / worker / indexer).
# All three ship in one image; compose picks which to run via `command:`.
#
# Build context MUST be the repo root (0g-agentic-id/), not attestor/ —
# `crates/shared/src/chain.rs` uses alloy's `sol!` macro to load the
# contract ABI from `../../../contracts/out/AgenticID.sol/AgenticID.json`,
# so `contracts/` has to sit alongside `attestor/` inside the build.
# Requires `forge build` in contracts/ to have produced the artifact.

FROM rust:1.85-bookworm AS builder

# protoc for tonic-build (compiles crates/shared/proto/tapp_service.proto).
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

# crates.io mirror (rsproxy). Remove this block to use crates.io directly.
RUN mkdir -p /usr/local/cargo \
 && printf '[source.crates-io]\nreplace-with = "rsproxy-sparse"\n\n[source.rsproxy-sparse]\nregistry = "sparse+https://rsproxy.cn/index/"\n\n[net]\ngit-fetch-with-cli = true\nretry = 20\n' \
      > /usr/local/cargo/config.toml

WORKDIR /build
COPY attestor/Cargo.toml attestor/Cargo.lock attestor/rust-toolchain.toml ./attestor/
COPY attestor/crates ./attestor/crates
# Vendored crates patched in via `[patch.crates-io]` in the workspace
# Cargo.toml. Required: `version-meld/core2/` (yanked-on-crates.io fix).
COPY attestor/version-meld ./attestor/version-meld
# Only the one ABI JSON is actually needed — no need to ship forge sources.
COPY contracts/out/AgenticID.sol/AgenticID.json ./contracts/out/AgenticID.sol/AgenticID.json

WORKDIR /build/attestor
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/attestor/target,sharing=locked \
    cargo build --release \
        -p attestor-api \
        -p attestor-worker \
        -p attestor-indexer \
 && mkdir -p /out \
 && cp target/release/attestor-api \
       target/release/attestor-worker \
       target/release/attestor-indexer \
       /out/

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/

# Non-root, no-shell user.
RUN useradd --system --user-group --no-create-home --shell /usr/sbin/nologin attestor

# cwd so `dotenvy::dotenv()` finds the `.env` mounted at /app/.env.
WORKDIR /app
USER attestor

# Default binary; compose overrides via `command:` for worker / indexer.
CMD ["attestor-api"]
