# Build on the billing server: docker build -t openclaw-sandbox:1.0.0 -f images/openclaw/Dockerfile images/openclaw/
# Requires base image from: eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22
FROM eliza-registry-vpc.ap-southeast-1.cr.aliyuncs.com/eliza/0g-sandbox:base-ubuntu22

ARG NODE_VERSION=22.14.0

# Fix PATH for non-interactive exec (toolbox process/execute does not load .bashrc).
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin:${PATH}"

# Install openclaw globally.
RUN npm install -g openclaw

# Pre-configure gateway: allow non-loopback Host header origin fallback
# (sandbox containers have no loopback UI access from the host).
RUN openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true

# Startup script — starts the openclaw gateway in the foreground.
# Pass ANTHROPIC_API_KEY (and other provider keys) as env vars at sandbox creation.
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh

CMD ["/bin/bash", "/root/start.sh"]
