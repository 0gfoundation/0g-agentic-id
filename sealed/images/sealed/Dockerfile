# NOT the openclaw sealed image that ships. That one (zg-sealed/0g-sealed)
# is built by sealed/Dockerfile, FROM the openclaw base that
# sealed/images/openclaw/ builds; it was matched against the production
# image by layer digest (#130). This file copies in no bootstrap binary (see
# "No CMD" below). It is the universal-image target FRAMEWORK_ADAPTER.md
# describes, for a deployment that ships it.
#
# A universal sealed sandbox image, node flavour. Images are per
# framework runtime (this one carries node; images/hermes/ carries
# python/uv — see that Dockerfile's header for why they're split), but
# which adapter actually runs is still decided at boot by the agent's
# on-chain framework binding (see sealed/main.go resolveAdapter): the
# sealed binary registers every adapter, and each adapter installs its
# binding-pinned framework version at first Start.
#
# The npm installs below are warm-cache only — they make first boot fast
# and keep cold boots working through an npm outage. Removing one does
# not remove support for that framework; it just moves the install to
# first Start. (A CLI-framework shim, when an adapter ships one, is
# go:embed'ded in the sealed binary rather than baked here — the retired
# claudecode bridge worked this way.)
#
# Build on the billing server:
#   cd sealed && docker build -t sealed-sandbox:1.0.0 -f images/sealed/Dockerfile .
#   (sealed/ is the context: the storage-builder stage reads go.mod for the
#   0g-storage-client version)
# Requires base image from: eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22

# Stage 1 — 0g-storage-client, which sealed runs (as root, through
# privsep.RootCommand) for every iData download; uploads run in-process
# (internal/dataplane/upload.go). Built here, as in the other images, at the
# version sealed/go.mod pins, so the PATH check below covers it.
FROM golang:1.24-alpine AS storage-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN V=$(go list -m -f '{{.Version}}' github.com/0gfoundation/0g-storage-client) \
 && test -n "$V" \
 && test -z "$(go list -m -f '{{if .Replace}}replaced{{end}}' github.com/0gfoundation/0g-storage-client)" \
 && CGO_ENABLED=0 GOBIN=/out go install -ldflags="-s -w" "github.com/0gfoundation/0g-storage-client@$V"

FROM eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22

# openclaw 2026.7.1 (whitelist.go's whitelistMax) requires
# node >=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0 — the 0g-sandbox base
# ships an older node in its nvm, so install the pinned version here
# instead of relying on the base (same bump the openclaw image line took
# via base-ubuntu22-node24).
ARG NODE_VERSION=24.22.1
ENV NVM_DIR=/root/.nvm
RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION} && nvm alias default ${NODE_VERSION}

# Fix PATH for non-interactive exec (toolbox process/execute does not load .bashrc).
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin:${PATH}"

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

# Warm-cache the bundled framework (the adapter re-pins the exact version
# at first Start; see openclaw's whitelist.go for the validated set).
RUN npm install -g openclaw

# openclaw-specific pre-config: allow non-loopback Host header origin
# fallback (sandbox containers have no loopback UI access from the host).
RUN openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true

# nvm unpacks node release tarballs as root, which restores the tarball's
# build uid; normalize the toolchain trees to root (entries not already
# root's only) so privsep.LookPath accepts them.
RUN find "$NVM_DIR" /usr/local \( ! -user 0 -o ! -group 0 \) -exec chown -h 0:0 {} +

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client

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

# No CMD: this image is booted by the sealed bootstrap binary, which the
# sandbox layer injects and runs as PID 1. Framework processes are
# children of sealed, never a container entrypoint.
