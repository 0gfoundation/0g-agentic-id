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

# Stage 1 — 0g-storage-client (used by bootstrap to download intelligent data;
# uploads run inside the bootstrap binary, through the same client's Go SDK).
# The CLI is `go install`ed at the SDK version pinned in go.mod (module
# checksums verified against the Go checksum database), so the two always
# move together. A `replace` of the module in go.mod would split them (this
# would install upstream's CLI while sealed links the replacement), so the
# stage refuses to build with one.
FROM golang:1.24-alpine AS storage-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN V=$(go list -m -f '{{.Version}}' github.com/0gfoundation/0g-storage-client) \
 && test -n "$V" \
 && test -z "$(go list -m -f '{{if .Replace}}replaced{{end}}' github.com/0gfoundation/0g-storage-client)" \
 && CGO_ENABLED=0 GOBIN=/out go install -ldflags="-s -w" "github.com/0gfoundation/0g-storage-client@$V"

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
 && apt-get install -y --no-install-recommends ca-certificates git curl procps xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Low-privilege user the framework subprocess runs as (internal/privsep):
# sealed (root, PID 1) drops the agent process to it so the agent cannot
# read sealed's memory or bootstrap env. Its home is /home/agent, which
# sealed creates at boot (agent:agent 0700, privsep.PrepareAgentHome) and
# which is HOME for everything the agent runs, so its tools' caches and
# config go there. The bridge, and every tool process it runs, starts in
# the framework tree (/root/.dsh) instead, so relative paths in their
# output land there, not in /home/agent (internal/framework/dsh/spawn.go
# explains why). /root stays root's: sealed makes it root:root 0711 at
# boot (privsep.SecureHome) and hands the agent only its framework tree
# inside it (privsep.OwnTree), linked into /home/agent
# (privsep.LinkAgentHome) so the ~/.<framework> paths keep working. The
# agent cannot create, rename or replace anything directly in /root,
# including the toolchain configuration root uses from there; on a reused
# container, what an earlier sealed (which let the agent own /root) left
# there is moved into /home/agent at boot (privsep.ReclaimHome). Without a
# usable agent account sealed refuses to provision (privsep.Required).
RUN useradd --system --no-create-home --home-dir /home/agent --shell /usr/sbin/nologin agent

ENV HOME=/root

# Node from the official tarball (debian's node is too old for the SDK).
ARG NODE_VERSION=24.22.1
#
# --no-same-owner: the release tarball records its build user's uid/gid
# (1001), and GNU tar run as root restores it by default — onto
# /usr/local/bin and /usr/local/lib as well, since they are directory
# entries of the archive. sealed resolves every command it runs, as root
# (RootCommand) or as the agent (AgentCommand, Sweep), only in PATH
# directories owned by root and writable by nobody else (privsep.LookPath),
# so the toolchain must be root-owned (checked at the end of this file).
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
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
# DSH_NPM_BEFORE freezes TRANSITIVE resolution: the family's packages depend
# on each other via ranges (^rc.N), so without a cutoff every rebuild re-rolls
# nested versions against whatever upstream published since — which is exactly
# how a top-pinned rc.1 tree got rc.2 internals and broke the llm adapter
# interface. --before makes the tree a pure function of (pins, cutoff).
ARG DSH_VERSION=0.1.1-rc.2
ARG DSH_NPM_BEFORE=2026-08-21T13:00:00Z
ARG CORDIS_VERSION=4.0.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && npm install -g --no-fund --no-audit --before "${DSH_NPM_BEFORE}" \
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

# sealed resolves every command it runs by name — as root (RootCommand) and
# as the agent (AgentCommand, Sweep) alike — only through PATH directories
# whose whole resolved path is owned by root and writable by nobody else,
# and the resolved binary must be root-owned too (privsep.LookPath; the boot
# log lists PATH entries it rejected). Fail the build, rather than the first
# boot, when that does not hold for a command sealed needs here.
RUN for c in npm node pkill 0g-storage-client; do \
      w="$(command -v "$c")" || { echo "$c: not on PATH" >&2; exit 1; }; \
      for p in "$(readlink -f "$w")" "$(readlink -f "$(dirname "$w")")"; do \
        while :; do \
          o="$(stat -c '%u %a' "$p")"; \
          if [ "${o% *}" != 0 ] || [ $(( 0${o#* } & 022 )) -ne 0 ]; then \
            echo "$p (uid ${o% *}, mode ${o#* }) is not root-only: privsep.LookPath will not resolve $c" >&2; exit 1; \
          fi; \
          [ "$p" = / ] && break; p="$(dirname "$p")"; \
        done; \
      done; \
    done

# Bootstrap runs as PID 1 and spawns the bridge once it has restored the
# agent's iData. ENTRYPOINT is REQUIRED on a standalone (non-0g-sandbox-base)
# image — without it the container boots a shell, never runs sealed, and fails
# as a provision timeout.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
