# Cloudflare Sandbox with agentsh - Secure AI Agent Execution
# Extends the official Cloudflare Sandbox image with agentsh policy enforcement

# Use Cloudflare's Python sandbox image as base (includes Python 3.11, Node.js 20, Bun)
FROM docker.io/cloudflare/sandbox:0.7.0-python

# Cache buster to force rebuild
ARG CACHE_BUST=20260203-002
RUN echo "Cache bust: ${CACHE_BUST}"

ARG AGENTSH_REPO=erans/agentsh
ARG DEB_ARCH=amd64

# Switch to root for installation
USER root

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Install additional dependencies needed for agentsh
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        jq \
        libseccomp2 \
    && rm -rf /var/lib/apt/lists/*

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

# Set ownership for agentsh directories (root user in this container)
RUN chown -R root:root /var/lib/agentsh /var/log/agentsh /etc/agentsh

# Note: We do NOT install the shell shim here because it requires the agentsh server to be running
# In a production setup, you would:
# 1. Start the agentsh server before starting the shell
# 2. Or use a process supervisor (s6, tini) to manage both processes
# 3. Or integrate with the container's init system

# For this demo, agentsh is installed and can be used directly via 'agentsh run <command>'
