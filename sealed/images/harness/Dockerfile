# Sealed sandbox runtime image — 0g-harness flavour.
#
# Per-framework image, node-only: 0g-harness
# (github.com/0gfoundation/0g-harness) composes the DeepSeek Harness (DSH)
# plugin tree in-process and serves the owner's /v1/ surface. No Python
# runtime, unlike images/prime/.
#
# Contents beyond debian-slim: node, ca-certificates (chain RPC + 0G storage +
# router TLS), git and procps (the adapter's orphan sweep), one 0g-harness
# official version package (its locked DSH dependency tree included), the
# sealed bootstrap binary, the loader that runs it (cmd/loader), and
# 0g-storage-client.
#
# The harness runs from an official version package (sealed/LAYERS.md §5): the
# gzip'd tar of an installed 0g-harness package directory, named by its
# sha256. The harness-package stage builds it; the image unpacks it into
# /opt/0g-harness/<sha256>/ (root's, read-only to the agent) and names it in
# /opt/0g-harness/base. sealed runs the harness from there, and under the
# layered flow fetches other packages by hash into the same place. To publish
# the package (the attestor's artifacts, validHarnessHashes), take it from the
# stage:
#
#   cd sealed && docker build --target harness-package --output type=local,dest=out -f images/harness/Dockerfile .
#
# The composition is authored in the harness's code — NOT in a cordis.yml /
# profile / bundle the agent can reach — so it rides the package hash and an
# agent editing $DSH_HOME cannot change what mounts next boot.
#
# Build context = sealed/ (for the bootstrap COPY):
#
#   cd sealed && docker build -t 0g-sealed-harness:0.1.0 -f images/harness/Dockerfile .
#
# Release checklist: a new image hash must be added to on-chain
# validFrameworkHashes or the attestor destroys the container right after
# provision. The container does not check that the agent's framework matches
# the image: an 0g-harness agent booted on an image without the harness fails
# at framework start. The SDK picks the image by the agent's framework from
# the attestor's GET /config frameworks[] (ATTESTOR_FRAMEWORKS).

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

# Stage 2 — sealed bootstrap binary, and the loader that verifies and runs it.
# The loader is built with the sealed binary's sha256 compiled in, so it runs
# exactly this bootstrap and nothing else (sealed/LAYERS.md, base layer).
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap . \
 && H="$(sha256sum bootstrap | cut -d' ' -f1)" \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.expectedSealedHash=$H" -o loader ./cmd/loader \
 && echo "loader pinned to bootstrap sha256 $H"

# Stage 3 — the 0g-harness official version package, built on the runtime's
# own base and node: node-pty (pulled in by bash-local → subprocess-local) is
# a native module, so the package runs only on the node it was built for.
#
# 0g-harness is installed globally, with the whole DSH plugin tree as its own
# dependencies, locked exactly, with integrity hashes, by its
# npm-shrinkwrap.json; it resolves its @deepseek-ai/* imports from its own
# node_modules. HARNESS_REF names one exact build: the source archive of one
# repository commit, over https — npm installs it as a package archive, with
# no git and no install-time scripts of its own (a git URL to GitHub makes npm
# reach for ssh, which the image does not have) — or a published version
# (@0gfoundation/0g-harness@<version>).
#
# The build then checks the one thing the package must agree on with the
# sealed binary: its 0g-harness version is the version whitelist.go records in
# every 0g-harness agent's chain-tracked framework role (its last entry,
# whitelistMax). A mismatch fails the build, not a boot.
#
# The package is the installed directory as a deterministic tar (names
# sorted, owner 0, mtime 0, hard links stored as files, gzip without a
# timestamp). It may hold only directories, regular files and links that stay
# inside it, which is all sealed unpacks (internal/layers); anything else
# fails the build.
FROM debian:13-slim AS harness-package
ARG NODE_VERSION=24.22.1
ARG HARNESS_REF=https://codeload.github.com/0gfoundation/0g-harness/tar.gz/2a5ffb38ccac7e5590463cf98fa3e6fb52a526bd
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
 && rm /tmp/node.tar.xz
COPY internal/framework/harness/whitelist.go /tmp/harness-whitelist.go
RUN npm install -g --no-fund --no-audit "${HARNESS_REF}" \
 && H=/usr/local/lib/node_modules/@0gfoundation/0g-harness \
 && test -f "$H/bin/0g-harness.mjs" \
 && GOT="$(node -p "require('$H/package.json').version")" \
 && WANT="$(sed -n '/supportedVersions = \[\]string{/,/^}/p' /tmp/harness-whitelist.go | grep -oE '"[^"]+"' | tail -1 | tr -d '"')" \
 && if [ -z "$WANT" ] || [ "$GOT" != "$WANT" ]; then echo "installed 0g-harness $GOT but whitelist.go records $WANT in the framework role" >&2; exit 1; fi \
 && echo "packaging 0g-harness $GOT with DSH $(node -p "require('$H/node_modules/@deepseek-ai/dsh-agent-spine-demo/package.json').version")" \
 && if [ -n "$(find "$H" ! -type d ! -type f ! -type l)" ]; then echo "the package holds an entry that is not a directory, file or link" >&2; exit 1; fi \
 && if [ -n "$(find "$H" -type l -lname '/*')" ]; then echo "the package holds a link with an absolute target" >&2; exit 1; fi \
 && (cd "$H" && find . -type l | while read -r l; do r="$(realpath -m --relative-to=. "$(dirname "$l")/$(readlink "$l")")"; case "$r" in ..|../*) echo "link $l leaves the package" >&2; exit 1;; esac; done) \
 && mkdir -p /out \
 && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --hard-dereference --format=gnu -C "$H" -cf - . | gzip -n -9 > /out/0g-harness.tgz \
 && echo "0g-harness package sha256 $(sha256sum /out/0g-harness.tgz | cut -d' ' -f1)"

# Stage 4 — runtime.
FROM debian:13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git curl procps xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Low-privilege user the framework subprocess runs as (internal/privsep):
# sealed (root, the loader's child) drops the agent process to it so the agent cannot
# read sealed's memory or bootstrap env. Its home is /home/agent, which
# sealed creates at boot (agent:agent 0700, privsep.PrepareAgentHome) and
# which is HOME for everything the agent runs, so its tools' caches and
# config go there. The harness, and every tool process it runs, starts in
# the framework tree (/root/.dsh, DSH's home) instead, so relative paths in
# their output land there, not in /home/agent
# (internal/framework/harness/spawn.go explains why). /root stays root's: sealed makes it root:root 0711 at
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

# The 0g-harness official version package base ships (stage 3), unpacked
# where sealed runs it from: /opt/0g-harness/<sha256 of the package>/, root's,
# directories 0755 and files 0644 (0755 when executable), named in
# /opt/0g-harness/base. The agent user can read and run it, not change it.
COPY --from=harness-package /out/0g-harness.tgz /tmp/0g-harness.tgz
RUN P="$(sha256sum /tmp/0g-harness.tgz | cut -d' ' -f1)" \
 && D="/opt/0g-harness/$P" \
 && mkdir -p "$D" \
 && tar -xzf /tmp/0g-harness.tgz -C "$D" --no-same-owner --no-same-permissions \
 && chown -R -h root:root /opt/0g-harness \
 && find "$D" -type d -exec chmod 0755 {} + \
 && find "$D" -type f -perm /111 -exec chmod 0755 {} + \
 && find "$D" -type f ! -perm /111 -exec chmod 0644 {} + \
 && chmod 0755 /opt/0g-harness \
 && test -f "$D/bin/0g-harness.mjs" \
 && printf '%s\n' "$P" > /opt/0g-harness/base \
 && chmod 0644 /opt/0g-harness/base \
 && rm /tmp/0g-harness.tgz \
 && echo "base harness package $P"

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /bootstrap
COPY --from=bootstrap-builder /app/loader /loader

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

# The loader runs as PID 1: it checks /bootstrap against the hash built into
# it, runs sealed as its child, forwards stop signals, reaps orphans, and exits
# with sealed's status; under the layered flow it also switches sealed
# versions sealed stages for it, and restarts a sealed that exits on its own
# (cmd/loader). sealed spawns the harness once it has restored the agent's
# iData. ENTRYPOINT is REQUIRED on a standalone (non-0g-sandbox-base) image —
# without it the container boots a shell, never runs sealed, and fails as a
# provision timeout.
ENTRYPOINT ["/loader"]
EXPOSE 8080
