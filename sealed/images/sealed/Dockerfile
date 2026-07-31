# The universal sealed sandbox image — one image for every bundled
# agent framework. Which framework actually runs is decided at boot by
# the agent's on-chain framework binding (see sealed/main.go
# resolveAdapter), not by the image: the sealed binary registers every
# adapter, and each adapter npm-installs its binding-pinned framework
# version at first Start.
#
# The npm installs below are warm-cache only — they make first boot fast
# and keep cold boots working through an npm outage. Removing one does
# not remove support for that framework; it just moves the install to
# first Start. (A CLI-framework shim, when an adapter ships one, is
# go:embed'ded in the sealed binary rather than baked here — the retired
# claudecode bridge worked this way.)
#
# Build on the billing server:
#   docker build -t sealed-sandbox:1.0.0 -f images/sealed/Dockerfile images/sealed/
# Requires base image from: eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22
FROM eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22

# openclaw 2026.7.1 (whitelist.go's whitelistMax) requires
# node >=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0 — the 0g-sandbox base
# ships an older node in its nvm, so install the pinned version here
# instead of relying on the base (same bump the openclaw image line took
# via base-ubuntu22-node24).
ARG NODE_VERSION=24.15.0
ENV NVM_DIR=/root/.nvm
RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION} && nvm alias default ${NODE_VERSION}

# Fix PATH for non-interactive exec (toolbox process/execute does not load .bashrc).
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin:${PATH}"

# Warm-cache the bundled framework (the adapter re-pins the exact version
# at first Start; see openclaw's whitelist.go for the validated set).
RUN npm install -g openclaw

# openclaw-specific pre-config: allow non-loopback Host header origin
# fallback (sandbox containers have no loopback UI access from the host).
RUN openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true

# No CMD: this image is booted by the sealed bootstrap binary, which the
# sandbox layer injects and runs as PID 1. Framework processes are
# children of sealed, never a container entrypoint.
