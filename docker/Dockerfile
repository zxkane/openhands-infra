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
# Multi-arch manifest list digest (linux/amd64 + linux/arm64) for openhands/openhands:1.7.0.
# Refresh: docker buildx imagetools inspect docker.openhands.dev/openhands/openhands:<version>
ARG OPENHANDS_IMAGE_DIGEST=sha256:916abcb15cc451d96853bd41c55117bb2ff3de0b9914cdcd861d338055798dc6
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
# Fargate branch: RemoteSandboxService compatible, multi-tenant isolation, V1 Cognito wiring.
ARG FORK_REF=4e480e79c47fb4c66c94c8176d130abdd6d5d2e9
COPY download-fork-patches.sh /opt/download-fork-patches.sh
RUN FORK_REF=${FORK_REF} sh /opt/download-fork-patches.sh

# ─── Custom modules (NEW files, not upstream modifications) ──────────────────
#
# v1.7.0: COPY destinations migrated to V1 paths (openhands.app_server.*).
# Upstream deleted openhands/server/user_auth/ and openhands/storage/{settings,
# secrets,conversation}/ in v1.7.0. The custom modules now extend the V1 ABCs
# (UserAuth / SettingsStore / SecretsStore) and live alongside the upstream
# defaults under openhands/app_server/{user_auth,settings,secrets}/.
# cognito_file_conversation_store.py is dropped — there is no V1 equivalent;
# multi-tenant conversation isolation runs through CognitoSQLAppConversationInfoService.

# Patched auth_user_context.py for webhook authentication from Docker internal network
COPY patched/ /app/patched/

# Cognito user authentication (Lambda@Edge header-based identity) — V1 path
COPY cognito_user_auth.py /app/openhands/app_server/user_auth/

# User config loader for MCP configurations from S3
COPY user_config_loader.py /app/openhands/server/user_config_loader.py

# User-scoped settings and secrets stores for multi-tenancy (CRITICAL SECURITY)
# Store data at users/{user_id}/settings.json and users/{user_id}/secrets.json
COPY s3_settings_store.py /app/openhands/app_server/settings/
COPY s3_secrets_store.py /app/openhands/app_server/secrets/

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
