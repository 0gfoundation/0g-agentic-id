# Build as a NEW tag per node version (0g-sealed:base-ubuntu22-node<NODE_VERSION>,
# currently base-ubuntu22-node24.22.1) — do NOT overwrite an existing tag:
# images that build FROM it would silently inherit the node bump, and a cached
# copy on a build host would silently keep the old node.
#   docker build -t eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sealed:base-ubuntu22-node24.22.1 \
#     -f images/openclaw/base.Dockerfile images/openclaw/
FROM ubuntu:22.04

# openclaw 2026.7.1 requires node >=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0
ARG NODE_VERSION=24.22.1
ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl wget git ca-certificates \
    lsof procps build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── nvm + node ─────────────────────────────────────────────────────────────────
ENV NVM_DIR=/root/.nvm
RUN curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash && \
    . "$NVM_DIR/nvm.sh" && \
    nvm install ${NODE_VERSION} && \
    nvm alias default ${NODE_VERSION}

# Fix PATH for non-interactive shells
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin:${PATH}"
