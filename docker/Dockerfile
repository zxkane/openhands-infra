# Custom OpenHands image with localhost URL rewriting fix
# This fixes WebSocket/fetch/XHR connections that try to connect to localhost
# by rewriting them to use /runtime/{port}/... path through the reverse proxy
#
# Build for ARM64 (Graviton):
#   Option A - On ARM64 machine:
#     docker build -t <ecr-repo>/openhands-custom:latest .
#
#   Option B - Cross-compile with QEMU:
#     docker run --privileged --rm tonistiigi/binfmt --install all
#     docker buildx build --platform linux/arm64 -t <ecr-repo>/openhands-custom:latest --push .
#
# The patch is applied at container startup via custom entrypoint, avoiding
# architecture-dependent RUN commands during build.

# Pin to specific version for stability
# Check https://github.com/All-Hands-AI/OpenHands/releases for latest releases
ARG OPENHANDS_VERSION=1.2.1
FROM docker.openhands.dev/openhands/openhands:${OPENHANDS_VERSION}

# Install boto3 for AWS Bedrock support (required by litellm for AWS authentication)
# This is a pure Python package so it's architecture-agnostic
RUN pip install --no-cache-dir boto3

# Copy the patch files (no architecture-dependent commands)
COPY patch-fix.js /opt/patch-fix.js
COPY apply-patch.sh /opt/apply-patch.sh

# Copy patched Python modules
# These contain fixes for webhook authentication that can't be done with sed patches
COPY patched/ /app/patched/

# Copy custom Cognito user authentication module
# This enables user identity from Lambda@Edge headers to be used for
# conversation storage (S3 path: users/{user_id}/conversations/{sid}/)
COPY cognito_user_auth.py /app/openhands/server/user_auth/

# Copy custom Cognito file conversation store
# This stores conversations under user-specific paths in S3
COPY cognito_file_conversation_store.py /app/openhands/storage/conversation/

# Patch server_config.py to use CognitoUserAuth instead of DefaultUserAuth
# OpenHands hardcodes user_auth_class and doesn't read from environment variables,
# so we must patch the source file directly
RUN sed -i "s|openhands.server.user_auth.default_user_auth.DefaultUserAuth|openhands.server.user_auth.cognito_user_auth.CognitoUserAuth|g" /app/openhands/server/config/server_config.py

# Patch server_config.py to use CognitoFileConversationStore instead of FileConversationStore
# This ensures conversations are stored under user-specific S3 paths
RUN sed -i "s|openhands.storage.conversation.file_conversation_store.FileConversationStore|openhands.storage.conversation.cognito_file_conversation_store.CognitoFileConversationStore|g" /app/openhands/server/config/server_config.py

# Set the custom entrypoint that applies the patch at runtime
# CMD is inherited from base image but we must explicitly preserve it
ENTRYPOINT ["/bin/sh", "/opt/apply-patch.sh"]
CMD ["uvicorn", "openhands.server.listen:app", "--host", "0.0.0.0", "--port", "3000"]
