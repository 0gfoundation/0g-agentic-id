# Sealed sandbox runtime image — hermes flavour.
#
# Per-framework image (vs images/sealed/ which is the node/openclaw one):
# hermes is Python/uv, openclaw is Node — one image carrying both runtimes
# would couple two release cadences and double the surface. This image
# deliberately ships NO node: hermes needs it only for browser automation
# (Playwright) and the WhatsApp bridge, neither of which a sealed
# server-side agent uses.
#
# Contents beyond the base: uv, git (version pinning IS git-checkout for
# hermes — no npm/pip distribution), ca-certificates (chain RPC + 0G
# storage + router TLS), procps (adapter's orphan-gateway pkill sweep),
# the hermes checkout + synced venv (warm cache — the adapter re-pins the
# exact whitelisted tag at first Start; see hermes/whitelist.go), the
# sealed bootstrap binary, and 0g-storage-client.
#
# Build context = sealed/ (for the bootstrap COPY):
#
#   cd sealed && docker build -t 0g-sealed-hermes:0.1.0 -f images/hermes/Dockerfile .
#
# Release checklist reminder: a new image hash must be added to the
# on-chain validFrameworkHashes whitelist or the attestor destroys the
# container right after provision.

# Stage 1 — 0g-storage-client (used by bootstrap to download intelligent data).
FROM golang:1.24-alpine AS storage-builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 https://github.com/0gfoundation/0g-storage-client.git
WORKDIR /src/0g-storage-client
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/0g-storage-client .

# Stage 2 — sealed bootstrap binary.
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap .

# Stage 3 — runtime. debian:13-slim matches the base hermes's own official
# image builds on; python itself is NOT apt-installed — uv provisions the
# interpreter version pinned by the checkout's .python-version during
# `uv sync`, so python upgrades ride hermes release tags, not this image.
FROM debian:13-slim

# uv from the official distroless image. The tag floats deliberately:
# byte-level reproducibility of the venv is anchored by `uv sync --locked`
# (hash-verified against the checkout's uv.lock), not by the uv binary
# version. Record the digest from the build log when cutting a release.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git curl procps \
 && rm -rf /var/lib/apt/lists/*

ENV HOME=/root

# Warm-cache the framework at the whitelisted tag. Keep HERMES_BAKED_VERSION
# in sync with whitelistMax in sealed/internal/framework/hermes/whitelist.go —
# when they match, the adapter's first-Start `git checkout + uv sync --locked`
# is a no-op cache hit; a binding pinned to another whitelisted tag pays the
# checkout+sync cost at first boot (runtime flexibility tradeoff, same as
# openclaw's npm path). --depth 1 keeps the layer small; the adapter fetches
# tags on demand if a future whitelist entry postdates this clone.
# NB: hermes git tags are CalVer (v2026.7.20 = the release marketed as
# "v0.19.0"); the semantic names have no tags.
ARG HERMES_BAKED_VERSION=v2026.7.20
RUN git clone --depth 1 --branch ${HERMES_BAKED_VERSION} \
      https://github.com/NousResearch/hermes-agent.git /usr/local/lib/hermes-agent \
 && cd /usr/local/lib/hermes-agent \
 && uv sync --locked \
 && ln -s /usr/local/lib/hermes-agent/.venv/bin/hermes /usr/local/bin/hermes

# One CLI warm-up run: proves the venv symlink at build time and pays the
# bytecode compilation once. Verified NOT to seed ~/.hermes (bundled-skill
# seeding + .bundled_manifest happen at first gateway start, inside the
# adapter's SettleDelay window before the watcher baseline is captured).
# The rm is belt-and-braces for future hermes versions that might write a
# .env template here.
RUN hermes --version \
 && rm -f /root/.hermes/.env

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /bootstrap

# Bootstrap runs as PID 1 and spawns `hermes gateway run` itself once it
# has decrypted and restored the agent's iData — no CMD from the base.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
