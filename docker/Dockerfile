# Custom OpenHands image with multi-tenant patches and runtime routing
#
# Architecture:
#   1. Build-time: Download pre-patched upstream files from zxkane/openhands fork
#   2. Build-time: COPY custom modules (Cognito auth, S3 stores, etc.)
#   3. Runtime:    apply-startup.sh handles JS injection, site-packages patch, DB migration
#
# Build for ARM64 (Graviton):
#   Option A - On ARM64 machine:
#     docker build -t <ecr-repo>/openhands-custom:latest .
#
#   Option B - Cross-compile with QEMU:
#     docker run --privileged --rm tonistiigi/binfmt --install all
#     docker buildx build --platform linux/arm64 -t <ecr-repo>/openhands-custom:latest --push .

# Pin to specific version for stability
# Check https://github.com/All-Hands-AI/OpenHands/releases for latest releases
ARG OPENHANDS_VERSION=1.4.0
FROM docker.openhands.dev/openhands/openhands:${OPENHANDS_VERSION}

# Install boto3 for AWS Bedrock support (required by litellm for AWS authentication)
RUN pip install --no-cache-dir boto3

# ─── Build-time: Download patched upstream files from fork ───────────────────
# Replaces the old apply-patch.sh (2000+ line regex patching at startup).
# The fork (zxkane/openhands) has clean per-feature commits against the release tag.
# See docker/CLAUDE.md for the full list of patched files and fork branch strategy.
# Pin to commit SHA for reproducible builds (tag: custom-v1.4.0-fargate-r2)
# Fargate branch: Docker-specific patches removed, RemoteSandboxService compatible
# r2: Added resume_conversation() for agent-server registration on conversation resume
ARG FORK_REF=03f3ff7c817a521b651695be095d4c74c47f0e4c
COPY download-fork-patches.sh /opt/download-fork-patches.sh
RUN FORK_REF=${FORK_REF} sh /opt/download-fork-patches.sh

# ─── Custom modules (NEW files, not upstream modifications) ──────────────────

# Patched auth_user_context.py for webhook authentication from Docker internal network
COPY patched/ /app/patched/

# Cognito user authentication (Lambda@Edge header-based identity)
COPY cognito_user_auth.py /app/openhands/server/user_auth/

# User-scoped conversation storage (S3 path: users/{user_id}/conversations/{sid}/)
COPY cognito_file_conversation_store.py /app/openhands/storage/conversation/

# User config loader for MCP configurations from S3
COPY user_config_loader.py /app/openhands/server/user_config_loader.py

# User-scoped settings and secrets stores for multi-tenancy (CRITICAL SECURITY)
# Store data at users/{user_id}/settings.json and users/{user_id}/secrets.json
COPY s3_settings_store.py /app/openhands/storage/settings/
COPY s3_secrets_store.py /app/openhands/storage/secrets/

# Multi-tenant conversation isolation (user_id-based filtering)
COPY cognito_sql_conversation_info_service.py /app/openhands/app_server/app_conversation/

# Frontend JavaScript patches (URL rewriting, auto-close settings modal)
COPY patch-fix.js /opt/patch-fix.js

# ─── Minimal startup script ─────────────────────────────────────────────────
# Handles only runtime-dynamic operations:
#   - JS injection into index.html
#   - site-packages patching (openhands_cloud)
#   - Database migration DDL
#   - Critical patch verification
COPY apply-startup.sh /opt/apply-startup.sh
COPY patch-resume.py /opt/patch-resume.py
COPY patch-vscode-url.py /opt/patch-vscode-url.py
COPY patch-exposed-urls.py /opt/patch-exposed-urls.py

ENTRYPOINT ["/bin/sh", "/opt/apply-startup.sh"]
CMD ["uvicorn", "openhands.server.listen:app", "--host", "0.0.0.0", "--port", "3000"]
