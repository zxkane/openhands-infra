# Custom runtime image with Chromium for browser automation (MCP chrome-devtools)
# Based on the official OpenHands runtime image
#
# The runtime image is used as the sandbox container where agent code executes.
# Chrome/Chromium is needed for chrome-devtools-mcp and browser automation tools.

ARG RUNTIME_VERSION=1.2-nikolaik
FROM docker.openhands.dev/openhands/runtime:${RUNTIME_VERSION}

# Install Chromium and required dependencies for headless browser operation
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    fonts-noto-color-emoji \
    fonts-freefont-ttf \
    libnss3 \
    libnspr4 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2 for sandbox AWS access
# Detect architecture and install appropriate version
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then \
        curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"; \
    else \
        curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"; \
    fi && \
    unzip -q awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

# Set environment variables for Chromium location
# Used by chrome-devtools-mcp, Playwright, Puppeteer
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

USER openhands
