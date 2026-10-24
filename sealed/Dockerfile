# Sealed sandbox runtime image.
#
# Layers the sealed-container bootstrap binary on top of the openclaw base
# image. Bootstrap reads the agent config from encrypted i-data, decrypts
# it, generates ~/.openclaw/openclaw.json, and spawns `openclaw gateway
# run`. The same process then serves :8080 as a signed reverse-proxy in
# front of openclaw on :3284.
#
# Build context = sealed/ (this directory):
#
#   cd sealed && docker build -t openclaw-sealed:0.1.0 .
#
# The base image (eliza/0g-sealed:openclaw-1.1.1) is built separately
# from sealed/images/openclaw/ — its Dockerfile builds the local tag
# `openclaw-sandbox:1.1.1`; the eliza/0g-sealed:openclaw-1.1.1 registry
# tag is applied when pushing that image to the registry. You
# only need to rebuild the base when bumping node / openclaw versions.

# Global build arg (declared before the first FROM so the stage-3 FROM can
# reference it): the openclaw base registry. GCP by default — reachable from
# GCP build environments and replacing the aliyun VPC registry. Override with
# --build-arg OPENCLAW_BASE=<aliyun tag> to build against the aliyun mirror.
ARG OPENCLAW_BASE=us-central1-docker.pkg.dev/g-devops/zg-sandbox/0g-sandbox:openclaw-1.1.1

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

# Stage 2 — bootstrap binary.
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap .

# Stage 3 — runtime: openclaw base already has node + openclaw + nvm PATH set.
# OPENCLAW_BASE is the global arg declared at the top of this file.
FROM ${OPENCLAW_BASE}

# The node this image ships comes from OPENCLAW_BASE, which can be overridden;
# fail the build if that base carries any node other than the pinned one
# (keep in step with images/openclaw/Dockerfile's NODE_VERSION).
ARG NODE_VERSION=24.22.1
RUN test "$(node --version)" = "v${NODE_VERSION}"

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
# When the base image already ships the user (an earlier line gave it /root
# as its home), its home is pointed at /home/agent instead, so tools that
# take the home from the account database rather than HOME (ssh, git over
# ssh) look there too; sealed logs a mismatch at boot.
RUN if id -u agent >/dev/null 2>&1; then usermod --home /home/agent agent; else useradd --system --no-create-home --home-dir /home/agent --shell /usr/sbin/nologin agent; fi

# Pre-install a pinned openclaw version and warm up its "bundled runtime
# deps" (the npm packages openclaw fetches the first time `gateway run`
# starts). Without this, every fresh container spends ~30-60s of first-boot
# in npm install — visible to users as /hello returning 503 and openclaw
# answering chat requests with "Queued (1)".
#
# Bootstrap still calls `npm install -g openclaw@<cfg.Framework.Version>`
# at startup; when that version matches OPENCLAW_BAKED_VERSION below npm
# is effectively a no-op (cache hit). Users who want a different version
# still pay the full dynamic install cost on first boot — that's the
# explicit tradeoff for runtime version flexibility.
ARG OPENCLAW_BAKED_VERSION=2026.7.1
RUN npm install -g --no-audit --no-fund openclaw@${OPENCLAW_BAKED_VERSION} \
 && mkdir -p /root/.openclaw \
 && printf '%s' \
    '{"gateway":{"auth":{"mode":"token","token":"warmup-not-used-at-runtime"}},"agents":{"defaults":{"model":{"primary":"anthropic/claude-opus-4-6"}}}}' \
    > /root/.openclaw/openclaw.json \
 && (timeout 60 openclaw gateway run --allow-unconfigured --bind loopback --port 33999 \
      || true) \
 && rm -f /root/.openclaw/openclaw.json /root/.openclaw/openclaw.json.bak

# nvm unpacks node release tarballs as root, which restores the tarball's
# build uid; normalize the toolchain trees to root (entries not already
# root's only) so privsep.LookPath accepts them. Checked below.
RUN find /root/.nvm /usr/local \( ! -user 0 -o ! -group 0 \) -exec chown -h 0:0 {} +

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /bootstrap

# sealed resolves every command it runs by name — as root (RootCommand) and
# as the agent (AgentCommand, Sweep) alike — only through PATH directories
# whose whole resolved path is owned by root and writable by nobody else,
# and the resolved binary must be root-owned too (privsep.LookPath; the boot
# log lists PATH entries it rejected). Fail the build, rather than the first
# boot, when that does not hold for a command sealed needs here.
RUN for c in npm node openclaw pkill 0g-storage-client; do \
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

# Bootstrap launches openclaw itself once it has decrypted the config — no
# need for the original start.sh from the base image.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
