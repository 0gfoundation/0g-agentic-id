# Sealed sandbox runtime image — prime-agent flavour.
#
# Per-framework image, and the first one that needs BOTH runtimes: Prime Agent
# is a TypeScript harness (the SDK the sealed bridge imports) driving a
# persistent Python IPython kernel (prime-agent-runtime, where the harness
# state and the agent's code execution live). images/sealed/ carries node only,
# images/hermes/ python only, so neither can host it.
#
# Contents beyond the base: node (for the SDK + the sealed bridge), uv +
# python (for the IPython kernel), ca-certificates (chain RPC + 0G storage +
# router TLS), git and procps (the adapter's orphan sweep), the warm-cached
# npm package, the sealed bootstrap binary, and 0g-storage-client.
#
# The sealed↔Prime Agent HTTP bridge is deliberately NOT baked here: it is
# go:embed'ed in the sealed binary and materialized at Start, so its
# measurement rides the sealed image hash and it can never drift out of sync
# with the adapter that spawns it (same pattern as the retired claudecode
# bridge).
#
# Build context = sealed/ (for the bootstrap COPY):
#
#   cd sealed && docker build -t 0g-sealed-prime:0.1.0 -f images/prime/Dockerfile .
#
# Release checklist reminder: a new image hash must be added to the on-chain
# validFrameworkHashes whitelist or the attestor destroys the container right
# after provision. And because framework↔image matching is not validated
# anywhere, a prime-agent deploy MUST pass sealedImage explicitly — the
# default image carries no Python kernel and the agent lands offline.

# Stage 1 — 0g-storage-client (used by bootstrap to download intelligent data).
FROM golang:1.24-alpine AS storage-builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 https://github.com/0gfoundation/0g-storage-client.git
WORKDIR /src/0g-storage-client
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/0g-storage-client .

# Stage 2 — sealed bootstrap binary (carries the embedded bridge).
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap .

# Stage 3 — runtime.
FROM debian:13-slim

# uv from the official distroless image, same rationale as the hermes image:
# the tag floats because reproducibility is anchored by the lock/pin steps at
# Start, not by the uv binary version. Record the digest when cutting a release.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git curl procps xz-utils \
 && rm -rf /var/lib/apt/lists/*

ENV HOME=/root

# Node from the official tarball rather than apt (debian's node is too old for
# the SDK, and this image has no nvm base to lean on).
ARG NODE_VERSION=24.15.0
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
 && rm /tmp/node.tar.xz \
 && node --version && npm --version

# Python for the IPython kernel. Pinned here (not by a checkout's
# .python-version like hermes) because Prime Agent ships its runtime inside the
# npm package rather than as a git checkout with its own interpreter pin.
ARG PYTHON_VERSION=3.12
RUN uv python install ${PYTHON_VERSION} \
 && uv tool install --python ${PYTHON_VERSION} ipykernel \
 && uv --version

# Warm-cache the SDK at the whitelisted version. Keep PRIME_BAKED_VERSION in
# sync with whitelistMax in sealed/internal/framework/prime/whitelist.go: when
# they match, the adapter's first-Start `npm install -g` is a cache hit; a
# binding pinned to another whitelisted version pays the install at first boot
# (same runtime-flexibility tradeoff as the openclaw and hermes images).
ARG PRIME_BAKED_VERSION=0.84.1
RUN npm install -g --no-fund --no-audit "@earendil-works/pi-coding-agent@${PRIME_BAKED_VERSION}" \
 && node -e "require.resolve('@earendil-works/pi-coding-agent')" \
 && echo "baked @earendil-works/pi-coding-agent@${PRIME_BAKED_VERSION}"

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /usr/local/bin/bootstrap

# No CMD: this image is booted by the sealed bootstrap binary, which the
# sandbox layer injects and runs as PID 1. Framework processes are children of
# sealed, never a container entrypoint.
