# Cloudflare Sandbox with agentsh - Secure AI Agent Execution
# Extends the official Cloudflare Sandbox image with agentsh policy enforcement

# Use Cloudflare's Python sandbox image as base (includes Python 3.11, Node.js 20, Bun)
FROM docker.io/cloudflare/sandbox:0.7.0-python

# Cache buster to force rebuild
ARG CACHE_BUST=20260212-v097d
RUN echo "Cache bust: ${CACHE_BUST}"

ARG AGENTSH_REPO=canyonroad/agentsh
ARG DEB_ARCH=amd64

# Switch to root for installation
USER root

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Install additional dependencies needed for agentsh
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        -o Dpkg::Options::="--force-confnew" \
        libseccomp2 \
        fuse3 \
    && rm -rf /var/lib/apt/lists/*

# Download and install agentsh release
ARG AGENTSH_VERSION=0.9.7
RUN set -eux; \
    deb="agentsh_${AGENTSH_VERSION}_linux_${DEB_ARCH}.deb"; \
    url="https://github.com/${AGENTSH_REPO}/releases/download/v${AGENTSH_VERSION}/${deb}"; \
    echo "Downloading agentsh v${AGENTSH_VERSION}: ${url}"; \
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

# Install agentsh systemd service
COPY systemd/agentsh.service /etc/systemd/system/agentsh.service
RUN mkdir -p /etc/systemd/system/multi-user.target.wants && \
    ln -sf /etc/systemd/system/agentsh.service /etc/systemd/system/multi-user.target.wants/agentsh.service

# Also add rc.local as fallback startup mechanism
COPY scripts/rc.local /etc/rc.local
RUN chmod +x /etc/rc.local

# Enable rc-local.service for systemd to run rc.local at boot
RUN mkdir -p /etc/systemd/system/rc-local.service.d && \
    echo '[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/rc-local.service.d/enable.conf && \
    ln -sf /lib/systemd/system/rc-local.service /etc/systemd/system/multi-user.target.wants/rc-local.service
