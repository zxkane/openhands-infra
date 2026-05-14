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
# OPENHANDS_IMAGE_DIGEST pins the exact base image content (multi-arch manifest digest).
# This prevents Docker build cache from silently using a stale base image layer.
# To update: docker manifest inspect docker.openhands.dev/openhands/openhands:<version>
# and use the top-level digest (sha256:...) from the manifest list.
ARG OPENHANDS_VERSION=1.7.0
# TODO(PR #81): replace with the actual sha256 of openhands/openhands:1.7.0 once
# the image is pulled in CI / staging — see lib/compute-stack.ts for the same TODO.
ARG OPENHANDS_IMAGE_DIGEST=sha256:5c0dc26f467bf8e47a6e76308edb7a30af4084b17e23a3460b5467008b12111b
FROM docker.openhands.dev/openhands/openhands:${OPENHANDS_VERSION}@${OPENHANDS_IMAGE_DIGEST}

# Upgrade system packages to fix CVEs (openssl, gnutls28, etc.)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Install boto3 for AWS Bedrock support (required by litellm for AWS authentication)
# Upgrade openhands-tools to match agent-server-custom SDK (v1.19.1)
RUN pip install --no-cache-dir boto3 openhands-tools==1.19.1

# ─── Build-time: Download patched upstream files from fork ───────────────────
# Replaces the old apply-patch.sh (2000+ line regex patching at startup).
# The fork (zxkane/openhands) has clean per-feature commits against the release tag.
# See docker/CLAUDE.md for the full list of patched files and fork branch strategy.
# Pin to commit SHA for reproducible builds (branch: custom/v1.7.0-fargate).
# Fargate branch: RemoteSandboxService compatible, multi-tenant isolation, Bedrock enhancements.
# TODO(PR #81): bump to the final SHA once the v1.7.0 fork branch is complete
# (current value is the partial cherry-pick checkpoint, 17/20 commits ported).
ARG FORK_REF=b707ea5cc1a410e9dd26058071a260188da99fc9
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
COPY patch-vscode-url.py /opt/patch-vscode-url.py
COPY patch-exposed-urls.py /opt/patch-exposed-urls.py

ENTRYPOINT ["/bin/sh", "/opt/apply-startup.sh"]
CMD ["uvicorn", "openhands.server.listen:app", "--host", "0.0.0.0", "--port", "3000"]
