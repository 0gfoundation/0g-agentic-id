# Build on the billing server: docker build -t openclaw-sandbox:1.1.1 -f images/openclaw/Dockerfile images/openclaw/
# Requires base image from: eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sealed:base-ubuntu22-node24.22.1
# (rebuild the base first when NODE_VERSION changes — the ARG here only fixes PATH)
FROM eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sealed:base-ubuntu22-node24.22.1

ARG NODE_VERSION=24.22.1

# Fix PATH for non-interactive exec (toolbox process/execute does not load .bashrc).
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin:${PATH}"
# A base built with a different node leaves PATH falling through to that
# node; fail the build instead of shipping it.
RUN test "$(node --version)" = "v${NODE_VERSION}"

# Install openclaw globally, pinned: the same version sealed/Dockerfile bakes
# (OPENCLAW_BAKED_VERSION) and validates (whitelistMax in
# sealed/internal/framework/openclaw/whitelist.go). An unpinned install takes
# whatever npm calls latest when the base is rebuilt.
RUN npm install -g openclaw@2026.7.1

# Pre-configure gateway: allow non-loopback Host header origin fallback
# (sandbox containers have no loopback UI access from the host).
RUN openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true

# Startup script — starts the openclaw gateway in the foreground.
# Pass ANTHROPIC_API_KEY (and other provider keys) as env vars at sandbox creation.
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh

CMD ["/bin/bash", "/root/start.sh"]
