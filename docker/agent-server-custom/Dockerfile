# Custom agent-server build with boto3 included in PyInstaller bundle
# This builds the agent-server binary from source with boto3/botocore as hidden imports

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

# Patch 23: Skip invalid/masked secrets during conversation resume
# When base_state.json has secrets with null values (masked), Pydantic validation fails.
# This patch adds error handling to skip invalid secrets instead of crashing.
RUN python3 << 'PYEOF'
import sys
import re

# Patch the agent_context.py to handle invalid secrets gracefully
agent_context_file = "/build/openhands-sdk/openhands/sdk/context/agent_context.py"

with open(agent_context_file, 'r') as f:
    content = f.read()

# Ensure model_validator is imported from pydantic
# The target file likely has: from pydantic import BaseModel, Field, field_validator, model_validator
# but we verify to be safe
if 'model_validator' not in content:
    if re.search(r'from pydantic import \(', content):
        # Multi-line import
        content = re.sub(
            r'(from pydantic import \(\s*\n)',
            r'\1    model_validator,\n',
            content,
            count=1
        )
        print("Patch 23: Added model_validator to multi-line pydantic imports")
    elif 'from pydantic import' in content:
        # Single-line import
        content = re.sub(
            r'(from pydantic import [^\n(]+)(\n)',
            r'\1, model_validator\2',
            content,
            count=1
        )
        print("Patch 23: Added model_validator to pydantic imports")
    else:
        print("WARNING: No pydantic import found, model_validator may not be available")

# Add a model_validator to filter out invalid secrets before validation
# The validator runs 'before' mode to preprocess the input data

patch_code = '''
    @model_validator(mode="before")
    @classmethod
    def _filter_invalid_secrets(cls, data):
        """Filter out invalid/masked secrets during deserialization.

        Patch 23 (openhands-infra): When resuming a conversation after EC2 replacement,
        base_state.json may contain secrets with null/masked values. These cause
        Pydantic validation errors. This validator filters them out.
        """
        import logging
        logger = logging.getLogger(__name__)

        if not isinstance(data, dict):
            return data

        secrets = data.get("secrets")
        if not secrets or not isinstance(secrets, dict):
            return data

        filtered_secrets = {}
        for key, value in secrets.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 23: Skipping None secret '{key}'")
                continue
            # Skip dict values with missing or null 'value' field (masked SecretSource)
            # After exclude_none=True serialization, 'value' key may be missing entirely
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 23: Skipping masked secret '{key}'")
                continue
            # Keep valid secrets
            filtered_secrets[key] = value

        if len(filtered_secrets) < len(secrets):
            logger.info(f"Patch 23: Filtered {len(secrets) - len(filtered_secrets)} invalid secrets")

        data["secrets"] = filtered_secrets if filtered_secrets else None
        return data

'''

# Find the class definition and insert the validator after the class docstring
# Look for the end of the Field definitions section (before the first @field_validator)
pattern = r'(class AgentContext\(BaseModel\):.*?""".*?""")'
match = re.search(pattern, content, re.DOTALL)
if not match:
    print("ERROR: Could not find AgentContext class definition")
    sys.exit(1)

# Find where to insert - after the secrets Field definition, before @field_validator
insert_pattern = r'(\s+secrets:.*?\)\n)(\n\s+@field_validator)'
insert_match = re.search(insert_pattern, content, re.DOTALL)
if insert_match:
    insert_pos = insert_match.end(1)
    content = content[:insert_pos] + patch_code + content[insert_pos:]
    print("Patch 23: Added secret filter validator to AgentContext")
else:
    # Try inserting after the last Field definition, before any validator
    insert_pattern2 = r'(load_public_skills:.*?skills repository\..*?"\n\s+\)\n)'
    insert_match2 = re.search(insert_pattern2, content, re.DOTALL)
    if insert_match2:
        insert_pos = insert_match2.end(1)
        content = content[:insert_pos] + patch_code + content[insert_pos:]
        print("Patch 23: Added secret filter validator (alternative position)")
    else:
        print("ERROR: Could not find insertion point for Patch 23")
        sys.exit(1)

with open(agent_context_file, 'w') as f:
    f.write(content)

print("Patch 23: Successfully patched agent_context.py for secret validation")
PYEOF

# Patch 24: Fix _compose_conversation_info to exclude None values when dumping state
# When the frontend polls /api/conversations endpoint, the state is dumped to dict
# and re-validated. Secrets with None values cause validation errors.
# Fix: Use exclude_none=True in model_dump() to skip these fields.
RUN python3 << 'PYEOF'
import sys
import re

conversation_service_file = "/build/openhands-agent-server/openhands/agent_server/conversation_service.py"

with open(conversation_service_file, 'r') as f:
    content = f.read()

# Find and fix the _compose_conversation_info function
# Old: **state.model_dump()
# New: **state.model_dump(exclude_none=True)
old_pattern = r'(\*\*state\.model_dump\(\))'
if re.search(old_pattern, content):
    content = re.sub(
        old_pattern,
        r'**state.model_dump(exclude_none=True)',
        content
    )
    print("Patch 24: Updated _compose_conversation_info to use exclude_none=True")
else:
    print("WARNING: Could not find state.model_dump() in _compose_conversation_info")
    # Try alternative pattern (maybe already has some args)
    alt_pattern = r'(\*\*state\.model_dump\([^)]*\))'
    if re.search(alt_pattern, content):
        print("Patch 24: model_dump() already has arguments, manual review needed")
    else:
        print("ERROR: Could not find model_dump pattern")
        sys.exit(1)

with open(conversation_service_file, 'w') as f:
    f.write(content)

print("Patch 24: Successfully patched conversation_service.py")
PYEOF

# Patch 25: Filter invalid secrets from JSON before model_validate_json
# When loading StoredConversation from stored.json, Pydantic fails if secrets have None values.
# Fix: Parse JSON, filter secrets with null values, then pass to model_validate_json
RUN python3 << 'PYEOF'
import sys
import re

conversation_service_file = "/build/openhands-agent-server/openhands/agent_server/conversation_service.py"

with open(conversation_service_file, 'r') as f:
    content = f.read()

# Find the StoredConversation.model_validate_json call and wrap it with JSON preprocessing
# Target pattern:
#   stored = StoredConversation.model_validate_json(
#       json_str,
#       context={
#           "cipher": self.cipher,
#       },
#   )

# First, add the helper function at the top of the file, after imports
helper_function = '''
import json as _json_module

def _filter_invalid_secrets_from_json(json_str: str) -> str:
    """Preprocess JSON to filter out secrets with null values.

    Patch 25 (openhands-infra): When loading StoredConversation, secrets with
    null values (masked after EC2 replacement) cause Pydantic validation errors.
    This filters them out before validation.
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        data = _json_module.loads(json_str)
    except _json_module.JSONDecodeError:
        return json_str  # Return as-is if not valid JSON

    if not isinstance(data, dict):
        return json_str

    secrets = data.get("secrets")
    if secrets and isinstance(secrets, dict):
        filtered_secrets = {}
        skipped = 0
        for key, value in secrets.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 25: Skipping None secret '{key}'")
                skipped += 1
                continue
            # Skip dict values with missing or null 'value' field (masked SecretSource)
            # After exclude_none=True serialization, 'value' key may be missing entirely
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 25: Skipping masked secret '{key}'")
                skipped += 1
                continue
            filtered_secrets[key] = value

        if skipped > 0:
            logger.info(f"Patch 25: Filtered {skipped} invalid secrets from StoredConversation")
            data["secrets"] = filtered_secrets if filtered_secrets else {}
            return _json_module.dumps(data)

    return json_str

'''

# Insert helper function after the last import statement
# Find a good insertion point - after "from" or "import" lines
import_section_end = 0
for match in re.finditer(r'^(from .+|import .+)\n', content, re.MULTILINE):
    import_section_end = match.end()

if import_section_end > 0:
    content = content[:import_section_end] + helper_function + content[import_section_end:]
    print("Patch 25: Added _filter_invalid_secrets_from_json helper function")
else:
    print("WARNING: Could not find import section end")

# Now wrap the model_validate_json call
# Find: StoredConversation.model_validate_json(\n            json_str,
# Replace with: StoredConversation.model_validate_json(\n            _filter_invalid_secrets_from_json(json_str),
old_pattern = r'(StoredConversation\.model_validate_json\(\s*\n\s+)(json_str)(,)'
new_replacement = r'\1_filter_invalid_secrets_from_json(json_str)\3'

if re.search(old_pattern, content):
    content = re.sub(old_pattern, new_replacement, content)
    print("Patch 25: Wrapped json_str with _filter_invalid_secrets_from_json()")
else:
    # Try simpler pattern
    simpler_pattern = r'(StoredConversation\.model_validate_json\()(\s*json_str)'
    if re.search(simpler_pattern, content):
        content = re.sub(simpler_pattern, r'\1\2.replace("json_str", "_filter_invalid_secrets_from_json(json_str)")', content)
        print("WARNING: Used simpler pattern replacement")
    else:
        print("WARNING: Could not find model_validate_json pattern, checking file structure...")
        # Show context around StoredConversation
        if "StoredConversation.model_validate_json" in content:
            print("Patch 25: Found model_validate_json but pattern didn't match")
        else:
            print("ERROR: StoredConversation.model_validate_json not found")
            sys.exit(1)

with open(conversation_service_file, 'w') as f:
    f.write(content)

print("Patch 25: Successfully patched conversation_service.py for JSON preprocessing")
PYEOF

# Patch 26: Filter invalid secrets from ConversationState (secret_registry)
# ConversationState loads from base_state.json which may have secrets with missing 'value' field
# The secret_registry.secret_sources structure needs similar filtering as AgentContext.secrets
RUN python3 << 'PYEOF'
import sys
import re

# Correct path: openhands-sdk/openhands/sdk/conversation/state.py
state_file = "/build/openhands-sdk/openhands/sdk/conversation/state.py"

with open(state_file, 'r') as f:
    content = f.read()

# model_validator is already imported in this file, verify
if 'model_validator' not in content:
    print("WARNING: model_validator not found, attempting to add")
    if 'from pydantic import' in content:
        content = re.sub(
            r'(from pydantic import [^\n]+)',
            r'\1, model_validator',
            content,
            count=1
        )
        print("Patch 26: Added model_validator to pydantic imports")
else:
    print("Patch 26: model_validator already imported")

# Add a model_validator to filter invalid secret_registry entries
# Insert BEFORE the existing _handle_secrets_manager_alias validator
patch_code = '''
    @model_validator(mode="before")
    @classmethod
    def _filter_invalid_secret_sources(cls, data):
        """Filter out invalid/masked secrets from secret_registry during deserialization.

        Patch 26 (openhands-infra): When resuming a conversation after EC2 replacement,
        base_state.json may contain secret_registry.secret_sources with missing 'value' fields.
        This happens because exclude_none=True removes null values during serialization.
        This validator filters them out to prevent ValidationError.
        """
        import logging
        logger = logging.getLogger(__name__)

        if not isinstance(data, dict):
            return data

        secret_registry = data.get("secret_registry")
        if not secret_registry or not isinstance(secret_registry, dict):
            return data

        secret_sources = secret_registry.get("secret_sources")
        if not secret_sources or not isinstance(secret_sources, dict):
            return data

        filtered_sources = {}
        skipped = 0
        for key, value in secret_sources.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 26: Skipping None secret_source '{key}'")
                skipped += 1
                continue
            # Skip dict values with missing or null 'value' field
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 26: Skipping masked secret_source '{key}'")
                skipped += 1
                continue
            filtered_sources[key] = value

        if skipped > 0:
            logger.info(f"Patch 26: Filtered {skipped} invalid secret_sources from ConversationState")
            secret_registry["secret_sources"] = filtered_sources
            data["secret_registry"] = secret_registry

        return data

'''

# Insert BEFORE the existing _handle_secrets_manager_alias validator
existing_validator_pattern = r'(\s+@model_validator\(mode="before"\)\s+@classmethod\s+def _handle_secrets_manager_alias)'
match = re.search(existing_validator_pattern, content)
if match:
    insert_pos = match.start()
    content = content[:insert_pos] + patch_code + content[insert_pos:]
    print("Patch 26: Added _filter_invalid_secret_sources validator before existing validator")
else:
    print("ERROR: Could not find existing _handle_secrets_manager_alias validator")
    sys.exit(1)

with open(state_file, 'w') as f:
    f.write(content)

print("Patch 26: Successfully patched conversation/state.py for secret_registry validation")
PYEOF

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
