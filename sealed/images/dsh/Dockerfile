# Sealed sandbox runtime image — DSH (DeepSeek Harness) flavour.
#
# Per-framework image, node-only: DSH is a TypeScript Cordis-plugin harness and
# the sealed bridge (bridge/bridge.mjs, go:embed'd in the sealed binary and
# materialized at Start) composes its plugin tree in-process. No Python runtime,
# unlike images/prime/.
#
# Contents beyond debian-slim: node (SDK + sealed bridge), ca-certificates
# (chain RPC + 0G storage + router TLS), git and procps (the adapter's orphan
# sweep), the whitelisted @deepseek-ai/dsh-* packages installed globally, the
# sealed bootstrap binary, and 0g-storage-client.
#
# The composition is authored in the bridge (embedded in the sealed binary),
# NOT in a cordis.yml / profile / bundle on disk — so it rides the sealed image
# hash and an agent editing $DSH_HOME cannot change what mounts next boot.
#
# Build context = sealed/ (for the bootstrap COPY):
#
#   cd sealed && docker build -t 0g-sealed-dsh:0.1.0 -f images/dsh/Dockerfile .
#
# Release checklist: a new image hash must be added to on-chain
# validFrameworkHashes or the attestor destroys the container right after
# provision. framework↔image matching is not validated anywhere, so a dsh
# deploy MUST pass sealedImage explicitly — the default image carries no DSH
# packages and the agent lands offline.

# Stage 1 — 0g-storage-client (used by bootstrap to download intelligent data).
FROM golang:1.24-alpine AS storage-builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 https://github.com/0gfoundation/0g-storage-client.git
WORKDIR /src/0g-storage-client
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/0g-storage-client .

# Stage 2 — sealed bootstrap binary (carries the embedded bridge + plugins).
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap .

# Stage 3 — runtime.
FROM debian:13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git curl procps \
 && rm -rf /var/lib/apt/lists/*

# Low-privilege user the framework subprocess runs as (internal/privsep):
# sealed (root, PID 1) drops the agent process to it so the agent cannot read
# sealed's memory or bootstrap env. Home stays /root — ownership of the
# framework subtrees is handed over at spawn; the paths don't move.
RUN useradd --system --no-create-home --home-dir /root --shell /usr/sbin/nologin agent

ENV HOME=/root

# Node from the official tarball (debian's node is too old for the SDK).
ARG NODE_VERSION=24.15.0
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
 && rm /tmp/node.tar.xz \
 && node --version && npm --version

# Install the whitelisted DSH packages globally. They land at the top of the
# global node_modules (/usr/local/lib/node_modules), which is a SIBLING of the
# bridge's materialize dir (/usr/local/lib/seal-dsh-bridge) — so the bridge's
# bare `@deepseek-ai/*` ESM imports resolve by Node's ancestor node_modules
# walk (the ESM loader ignores NODE_PATH). See spawn.go's bridgeScriptDir.
#
# Pin EVERY package to one coherent version. The DSH npm family's `latest`
# dist-tag is NOT consistent across packages, so a caret/`latest` install can
# assemble a mismatched plugin tree — pin exact, and keep DSH_VERSION in sync
# with whitelistMax in sealed/internal/framework/dsh/whitelist.go (a mismatch
# is a hard boot failure by design, checked in spawn.go verifyInstalled).
#
# @deepseek-ai/cordis is on its own version line (the vendored framework), so
# it takes a separate pin.
#
# node-pty (pulled in by bash-local → subprocess-local) is a native module, so
# a build toolchain is needed during install, then purged to keep the image slim.
ARG DSH_VERSION=0.1.0-rc.6
ARG CORDIS_VERSION=4.0.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && npm install -g --no-fund --no-audit \
      "@deepseek-ai/cordis@${CORDIS_VERSION}" \
      "@deepseek-ai/dsh-agent-spine-demo@${DSH_VERSION}" \
      "@deepseek-ai/dsh-llm@${DSH_VERSION}" \
      "@deepseek-ai/dsh-llm-pi-ai@${DSH_VERSION}" \
      "@deepseek-ai/dsh-session@${DSH_VERSION}" \
      "@deepseek-ai/dsh-tools@${DSH_VERSION}" \
      "@deepseek-ai/dsh-credentials@${DSH_VERSION}" \
      "@deepseek-ai/dsh-credentials-local@${DSH_VERSION}" \
      "@deepseek-ai/dsh-shell@${DSH_VERSION}" \
      "@deepseek-ai/dsh-bash-local@${DSH_VERSION}" \
      "@deepseek-ai/dsh-subprocess@${DSH_VERSION}" \
      "@deepseek-ai/dsh-subprocess-local@${DSH_VERSION}" \
      "@deepseek-ai/dsh-sandbox-policy@${DSH_VERSION}" \
      "@deepseek-ai/dsh-fs@${DSH_VERSION}" \
      "@deepseek-ai/dsh-fs-local@${DSH_VERSION}" \
      "@deepseek-ai/dsh-tool-fs@${DSH_VERSION}" \
      "@deepseek-ai/dsh-token-meter@${DSH_VERSION}" \
      "@deepseek-ai/dsh-compaction-basic@${DSH_VERSION}" \
      "@deepseek-ai/dsh-tool-call-timeout-policy@${DSH_VERSION}" \
 && ROOT="$(npm root -g)" \
 && V="$(node -p "require('$ROOT/@deepseek-ai/dsh-agent-spine-demo/package.json').version")" \
 && if [ "$V" != "${DSH_VERSION}" ]; then echo "baked spine $V != DSH_VERSION ${DSH_VERSION}" >&2; exit 1; fi \
 && echo "baked @deepseek-ai/dsh family @ $V, cordis ${CORDIS_VERSION}" \
 && apt-get purge -y python3 make g++ && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /root/.npm

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /bootstrap

# Bootstrap runs as PID 1 and spawns the bridge once it has restored the
# agent's iData. ENTRYPOINT is REQUIRED on a standalone (non-0g-sandbox-base)
# image — without it the container boots a shell, never runs sealed, and fails
# as a provision timeout.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
