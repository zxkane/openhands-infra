# Custom agent-server build with boto3 included in PyInstaller bundle
# This builds the agent-server binary from source with boto3/botocore as hidden imports
#
# Build-time patches (Patch 23-26) are applied via apply-sdk-patches.py
# These patches MUST be at build time because PyInstaller creates an immutable binary.
# Runtime patches are in docker/apply-patch.sh for the OpenHands container.

# Stage 1: Build the binary
FROM python:3.12-slim-bookworm AS builder

# Install build dependencies
# binutils provides objdump required by PyInstaller on Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast package management
RUN pip install uv

# Clone the OpenHands SDK repository
WORKDIR /build
RUN git clone --depth 1 --branch v1.8.1 https://github.com/OpenHands/software-agent-sdk.git .

# Copy and run SDK patches
# Patches 23-26: Handle invalid/masked secrets during conversation resume
# See apply-sdk-patches.py for detailed documentation
COPY apply-sdk-patches.py /build/
RUN python3 /build/apply-sdk-patches.py /build

# Install all dependencies including boto3
RUN uv sync --frozen && \
    uv pip install boto3 botocore pyinstaller

# Create custom spec file with boto3 hidden imports
RUN cat > /build/agent-server-boto3.spec << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for OpenHands Agent Server with boto3 support for AWS Bedrock.
"""

from pathlib import Path
import os
from PyInstaller.utils.hooks import (
    collect_submodules,
    collect_data_files,
    copy_metadata,
)

project_root = Path.cwd()
PATHEX = [
    project_root / "openhands-agent-server",
    project_root / "openhands-sdk",
    project_root / "openhands-tools",
    project_root / "openhands-workspace",
]

ENTRY = str(project_root / "openhands-agent-server" / "openhands" / "agent_server" / "__main__.py")

a = Analysis(
    [ENTRY],
    pathex=PATHEX,
    binaries=[],
    datas=[
        *collect_data_files("tiktoken"),
        *collect_data_files("tiktoken_ext"),
        *collect_data_files("litellm"),
        *collect_data_files("fastmcp"),
        *collect_data_files("mcp"),
        *collect_data_files("openhands.sdk.agent", includes=["prompts/*.j2"]),
        *collect_data_files("openhands.sdk.context.condenser", includes=["prompts/*.j2"]),
        *collect_data_files("openhands.sdk.context.prompts", includes=["templates/*.j2"]),
        *copy_metadata("fastmcp"),
        *copy_metadata("litellm"),
        # Add botocore data files (required for service definitions)
        *collect_data_files("botocore"),
    ],
    hiddenimports=[
        *collect_submodules("openhands.sdk"),
        *collect_submodules("openhands.tools"),
        *collect_submodules("openhands.workspace"),
        *collect_submodules("openhands.agent_server"),
        *collect_submodules("tiktoken"),
        *collect_submodules("tiktoken_ext"),
        *collect_submodules("litellm"),
        *collect_submodules("fastmcp"),
        "mcp.types",
        "mcp.client",
        "mcp.server",
        "mcp.shared",
        # AWS Bedrock support - add boto3 and botocore
        *collect_submodules("boto3"),
        *collect_submodules("botocore"),
        "urllib3",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "pandas",
        "IPython",
        "jupyter",
        "notebook",
        "mcp.cli",
        "mcp.cli.cli",
    ],
    noarchive=False,
    optimize=0,
)

a.binaries = [x for x in a.binaries if not x[0].startswith('libgcc_s.so')]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="openhands-agent-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
SPEC

# Build the binary
RUN uv run pyinstaller agent-server-boto3.spec

# Stage 2: Create the runtime image
FROM nikolaik/python-nodejs:python3.12-nodejs22

# Install runtime dependencies including Chromium for browser tool preloading
# Note: OpenHands preload service requires Chromium even if enable_browsing=false (bug in OpenHands)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux \
    git \
    curl \
    unzip \
    chromium \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libgbm1 \
    libasound2 \
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

# Set environment variables for Chromium location (used by browser tools)
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# NOTE: AWS_SHARED_CREDENTIALS_FILE is NOT set here intentionally.
# The agent-server uses EC2 instance role credentials via IMDS for Bedrock calls.
# The sandbox containers receive AWS credentials through SANDBOX_RUNTIME_STARTUP_ENV_VARS
# which is configured in compute-stack.ts to include AWS_SHARED_CREDENTIALS_FILE.
# Setting AWS_SHARED_CREDENTIALS_FILE here would override IMDS and use sandbox credentials
# (which expire) for agent-server's own Bedrock calls, causing "token expired" errors.

# Create openhands user (or use existing UID 1000 user)
# nikolaik/python-nodejs base image already has user 'pn' with UID 1000
RUN id -u openhands 2>/dev/null || useradd -m -s /bin/bash openhands

# Copy the built binary
COPY --from=builder /build/dist/openhands-agent-server /usr/local/bin/openhands-agent-server

# Copy VSCode server from official agent-server image
COPY --from=ghcr.io/openhands/agent-server:0b7ccc9-python /openhands/.openvscode-server /openhands/.openvscode-server

# Set permissions
RUN chown -R openhands:openhands /openhands && \
    chmod +x /usr/local/bin/openhands-agent-server

# Pre-create workspace/project directory with correct ownership
# This is needed because OpenHands creates containers with working_dir=/workspace/project
# and Docker creates working_dir as root before switching to USER, causing permission issues
# for git init when the openhands user tries to write to the directory
RUN mkdir -p /workspace/project && \
    chown -R openhands:openhands /workspace

USER openhands
WORKDIR /workspace

# Default command
ENTRYPOINT ["/sbin/docker-init", "--", "/usr/local/bin/openhands-agent-server"]
CMD ["--port", "8000"]
