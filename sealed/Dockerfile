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
# The base image (eliza/0g-sealed:openclaw-1.1.0) is built separately
# from sealed/images/openclaw/ — its Dockerfile builds the local tag
# `openclaw-sandbox:1.1.0`; the eliza/0g-sealed:openclaw-1.1.0 registry
# tag is applied when pushing that image to the registry. You
# only need to rebuild the base when bumping node / openclaw versions.

# Stage 1 — 0g-storage-client (used by bootstrap to download intelligent data).
FROM golang:1.24-alpine AS storage-builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 https://github.com/0gfoundation/0g-storage-client.git
WORKDIR /src/0g-storage-client
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/0g-storage-client .

# Stage 2 — bootstrap binary.
FROM golang:1.24-alpine AS bootstrap-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bootstrap .

# Stage 3 — runtime: openclaw base already has node + openclaw + nvm PATH set.
FROM eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sealed:openclaw-1.1.0

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

COPY --from=storage-builder /out/0g-storage-client /usr/local/bin/0g-storage-client
COPY --from=bootstrap-builder /app/bootstrap /bootstrap

# Bootstrap launches openclaw itself once it has decrypted the config — no
# need for the original start.sh from the base image.
ENTRYPOINT ["/bootstrap"]
EXPOSE 8080
