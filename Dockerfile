# Cloudflare Sandbox with agentsh - Secure AI Agent Execution
# Includes agentsh for policy enforcement and ttyd for web terminal

FROM ubuntu:22.04

ARG AGENTSH_REPO=erans/agentsh
ARG DEB_ARCH=amd64

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        bash \
        dash \
        libseccomp2 \
        python3 \
        python3-pip \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

# Save original dash for startup (before shim might affect it)
RUN cp /bin/dash /bin/dash.orig

# Install ttyd for web terminal
RUN curl -fsSL https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

# Download and install latest agentsh release
RUN set -eux; \
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${AGENTSH_REPO}/releases/latest" | jq -r '.tag_name'); \
    version="${LATEST_TAG#v}"; \
    deb="agentsh_${version}_linux_${DEB_ARCH}.deb"; \
    url="https://github.com/${AGENTSH_REPO}/releases/download/${LATEST_TAG}/${deb}"; \
    echo "Downloading agentsh ${LATEST_TAG}: ${url}"; \
    curl -fsSL -L "${url}" -o /tmp/agentsh.deb; \
    dpkg -i /tmp/agentsh.deb; \
    rm -f /tmp/agentsh.deb; \
    agentsh --version

# Create agentsh directories
RUN mkdir -p /etc/agentsh/policies \
    /var/lib/agentsh/quarantine \
    /var/lib/agentsh/sessions \
    /var/log/agentsh && \
    chmod 755 /etc/agentsh /etc/agentsh/policies && \
    chmod 755 /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions && \
    chmod 755 /var/log/agentsh

# Copy security policy and server config
COPY policies/default.yaml /etc/agentsh/policies/default.yaml
COPY config/agentsh.yaml /etc/agentsh/config.yaml

# Create non-root user for sandbox
RUN useradd -m -s /bin/bash sandbox && \
    chown -R sandbox:sandbox /var/lib/agentsh /var/log/agentsh

# Create workspace directory (BEFORE shim install)
RUN mkdir -p /workspace && chown sandbox:sandbox /workspace

# Create startup script that runs agentsh server and ttyd (BEFORE shim install)
# Uses /bin/dash.orig (unshimmed) to start services, then ttyd spawns bash (shimmed)
COPY <<'EOF' /usr/local/bin/start.sh
#!/bin/dash.orig
set -e

echo "Starting agentsh server..."
/usr/bin/agentsh server &
AGENTSH_PID=$!

# Wait for agentsh server to be ready
echo "Waiting for agentsh server..."
sleep 3

# Verify server is running
if ! kill -0 $AGENTSH_PID 2>/dev/null; then
    echo "ERROR: agentsh server failed to start"
    exit 1
fi

echo "agentsh server ready (PID: $AGENTSH_PID)"
echo "Starting ttyd web terminal on port 7681..."

# Start ttyd web terminal on port 7681
# -W: Writable (allow input)
# -t: Terminal type
# The bash shell will be intercepted by agentsh shim
exec /usr/local/bin/ttyd -W -p 7681 -t fontSize=14 -t theme='{"background": "#1e1e1e"}' /bin/bash
EOF

RUN chmod +x /usr/local/bin/start.sh

# Install the shell shim LAST - replaces /bin/bash with agentsh interceptor
# All commands after this will go through agentsh policy enforcement
# No RUN commands should come after this!
RUN agentsh shim install-shell \
    --root / \
    --shim /usr/bin/agentsh-shell-shim \
    --bash \
    --i-understand-this-modifies-the-host

# Configure agentsh for runtime
ENV AGENTSH_SERVER=http://127.0.0.1:8080

# Expose ports
# 3000 - Sandbox SDK API (internal)
# 7681 - ttyd web terminal
EXPOSE 3000 7681

# Switch to non-root user
USER sandbox
WORKDIR /workspace

# Start services using dash.orig (unshimmed)
CMD ["/bin/dash.orig", "/usr/local/bin/start.sh"]
