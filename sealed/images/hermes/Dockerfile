# Sealed sandbox runtime image — hermes flavour.
#
# Per-framework image (vs images/sealed/ which is the node/openclaw one):
# hermes is Python/uv, openclaw is Node — one image carrying both runtimes
# would couple two release cadences and double the surface. This image
# ships NO node: hermes needs node only for browser automation (Playwright),
# the WhatsApp bridge, and the web dashboard's SPA — none of which a sealed
# server-side agent uses. The dashboard specifically is NOT exposed (it
# embeds a terminal + file browser; see the adapter's FrameworkRoutes), so
# its SPA isn't built or shipped at all. Owner interaction is the chat API.
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

# Low-privilege user the framework subprocess runs as (internal/privsep):
# sealed (root, PID 1) drops the agent process to it so the agent cannot
# read sealed's memory or bootstrap env. Its home is /home/agent, which
# sealed creates at boot (agent:agent 0700, privsep.PrepareAgentHome) and
# which is HOME for everything the agent runs (and the default working
# directory of its processes), so its tools' caches and config and its own
# files go there. /root stays root's: sealed makes it root:root 0711 at
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
# --extra sms = "core + aiohttp", which the API server's HTTP layer needs
# (upstream has no api-server extra; sms's payload is exactly aiohttp).
# MUST match uvSyncArgs in sealed/internal/framework/hermes/spawn.go —
# uv sync is an exact sync, so a mismatch strips the package at first boot.
RUN git clone --depth 1 --branch ${HERMES_BAKED_VERSION} \
      https://github.com/NousResearch/hermes-agent.git /usr/local/lib/hermes-agent \
 && cd /usr/local/lib/hermes-agent \
 && uv sync --locked --extra sms \
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

# sealed resolves every command it runs by name — as root (RootCommand) and
# as the agent (AgentCommand, Sweep) alike — only through PATH directories
# whose whole resolved path is owned by root and writable by nobody else,
# and the resolved binary must be root-owned too (privsep.LookPath; the boot
# log lists PATH entries it rejected). Fail the build, rather than the first
# boot, when that does not hold for a command sealed needs here.
RUN for c in git uv hermes pkill 0g-storage-client; do \
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

# Bootstrap runs as PID 1 and spawns `hermes gateway run` itself once it
# has decrypted and restored the agent's iData — no CMD from the base.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
