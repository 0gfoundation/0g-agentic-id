# Sealed sandbox runtime image — 0g-harness flavour.
#
# Per-framework image, node-only: 0g-harness
# (github.com/0gfoundation/0g-harness) composes the DeepSeek Harness (DSH)
# plugin tree in-process and serves the owner's /v1/ surface. No Python
# runtime, unlike images/prime/.
#
# The image is base and the loader (cmd/loader) only: debian-slim, node,
# ca-certificates (chain RPC + 0G storage + router TLS), git and procps (the
# adapter's orphan sweep), 0g-storage-client, and /loader. It carries no
# sealed program and no harness package (sealed/LAYERS.md §2): the loader
# reads the trust registry's sealed list on chain, downloads the version to
# run from the official `artifacts` release, checks that it hashes to its
# listed name and runs it; that sealed installs the harness package the
# harness list names the same way, into /opt/0g-harness/<sha256>/ (root's,
# read-only to the agent). The image hash covers base and the loader; what
# runs on top is what the chain lists.
#
# This file builds both of them too. The sealed program (stage 2) and the
# harness package (stage 3) are exported, put on the `artifacts` release
# (each asset named by its sha256) and listed on the trust registry's sealed
# and harness lists:
#
#   cd sealed && docker buildx build --pull --target bootstrap-builder --output type=tar,dest=- -f images/harness/Dockerfile . | tar -xOf - app/bootstrap > sealed
#   cd sealed && docker buildx build --pull --target harness-package --build-arg HARNESS_REF=… --output type=tar,dest=- -f images/harness/Dockerfile . | tar -xOf - out/0g-harness.tgz > 0g-harness.tgz
#
# The builds print the sha256 of each ("sealed program sha256", "0g-harness
# package sha256"); check that the exported file hashes to it. A new sealed
# or harness version needs no new image: build it with the same command
# (HARNESS_REF naming the harness commit, whose version must pass the
# whitelist check below), publish it and list its hash. Agents take it by
# the version rule (sealed/LAYERS.md §3.1, §5.3): the owner's pick, or the
# newest listed one for a new container or once the running version is
# delisted. HARNESS_REF in this file names the version built by default.
#
# The composition is authored in the harness's code — NOT in a cordis.yml /
# profile / bundle the agent can reach — so it rides the package hash and an
# agent editing $DSH_HOME cannot change what mounts next boot.
#
# Build context = sealed/ (for the loader's COPY):
#
#   cd sealed && docker build -t 0g-sealed-harness:0.1.0 -f images/harness/Dockerfile .
#
# Release checklist:
#   1. Before any container of a new image boots, a sealed program and a
#      harness package that run on it are on the `artifacts` release and on
#      the trust registry's sealed and harness lists. A container whose loader
#      finds no listed sealed it can run, or whose sealed finds no listed
#      harness package, runs nothing and waits for a listing.
#   2. The image hash is on the trust registry's image list, or the attestor
#      destroys the container right after provision.
#   3. A base on another node version (NODE_VERSION, both stages) needs
#      harness packages built on it (stage 3): the package's native modules
#      run only on the node they were built for. List them before its image
#      boots; a listed package that does not start on a base is recorded as
#      failed in that container, and the next listed one starts.
# Hashes are listed through the registry's owner, the environment's Timelock:
# a scheduled operation that takes effect after its delay (one day on
# mainnet, none on testnet and dev); delisting is immediate, by the owner or
# the guardian. The image runs only on a chain whose AgenticID (1.4.0 or
# later) names its trust registry. The container does not check that the
# agent's framework matches the image: an 0g-harness agent booted on an image
# without the harness fails at framework start. The SDK picks the image by
# the agent's framework from the attestor's GET /config frameworks[]
# (ATTESTOR_FRAMEWORKS).

# Stage 1 — 0g-storage-client (used by sealed to download intelligent data;
# uploads run inside the sealed program, through the same client's Go SDK).
# The CLI is `go install`ed at the SDK version pinned in go.mod (module
# checksums verified against the Go checksum database), so the image's CLI
# and the sealed built from the same tree agree. The image keeps its CLI
# while sealed versions change on top of it: a sealed version that needs
# another CLI needs a new image. A `replace` of the module in go.mod would
# split them (this would install upstream's CLI while sealed links the
# replacement), so the stage refuses to build with one.
FROM golang:1.24-alpine AS storage-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN V=$(go list -m -f '{{.Version}}' github.com/0gfoundation/0g-storage-client) \
 && test -n "$V" \
 && test -z "$(go list -m -f '{{if .Replace}}replaced{{end}}' github.com/0gfoundation/0g-storage-client)" \
 && CGO_ENABLED=0 GOBIN=/out go install -ldflags="-s -w" "github.com/0gfoundation/0g-storage-client@$V"

# Stage 2 — the sealed program and the loader. Only the loader goes into the
# image; the sealed program is exported and published (see the top of this
# file), and the loader downloads it by hash. sealed is built with the
# harnessonly tag: the 0g-harness adapter is the only one in it
# (adapters_harnessonly.go); the other frameworks' images build it without
# the tag, and run it as PID 1.
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -tags harnessonly -ldflags="-s -w" -o bootstrap . \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o loader ./cmd/loader \
 && echo "sealed program sha256 $(sha256sum bootstrap | cut -d' ' -f1)"

# Stage 3 — the 0g-harness official version package, built on the runtime's
# own base and node: node-pty (pulled in by bash-local → subprocess-local) is
# a native module, so the package runs only on the node it was built for
# (NODE_VERSION here and in the runtime stage must match). The image does not
# carry it: it is exported and published (see the top of this file), and
# sealed installs it by hash.
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
ARG HARNESS_REF=https://codeload.github.com/0gfoundation/0g-harness/tar.gz/9adb411536477fb61f2a6ffef4982c6e26770649
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

# Where sealed installs the harness packages it runs:
# /opt/0g-harness/<sha256 of the package>/, root's, directories 0755 and
# files 0644 (0755 when executable). The agent user can read and run them,
# not change them. Empty in the image.
RUN install -d -o root -g root -m 0755 /opt/0g-harness

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
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

# The loader runs as PID 1: it picks the sealed version the chain lists,
# downloads it, checks it against its hash right before it runs it as its
# child, forwards stop signals, reaps orphans, switches to the versions sealed
# stages for it, and restarts a sealed that exits (cmd/loader). sealed
# installs the harness package and spawns the harness once it has restored
# the agent's iData. ENTRYPOINT is REQUIRED on a standalone
# (non-0g-sandbox-base) image — without it the container boots a shell, never
# runs sealed, and fails as a provision timeout.
ENTRYPOINT ["/loader"]
EXPOSE 8080
