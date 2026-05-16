#!/bin/sh
# Download patched upstream files from the zxkane/openhands fork at Docker build time.
#
# These files contain clean per-feature commits applied against the upstream release tag.
# This replaces the old apply-patch.sh approach of regex/sed patching at container startup.
#
# Environment variables:
#   FORK_REPO  - GitHub org/repo (default: zxkane/openhands)
#   FORK_REF   - Branch or tag   (default: pinned commit SHA on custom/v1.7.0-fargate)
set -e

FORK_REPO="${FORK_REPO:-zxkane/openhands}"
# Pin to commit SHA for reproducible builds (branch: custom/v1.7.0-fargate).
# v1.7.0 brings the upstream V0 → V1 cleanup: openhands/llm/, openhands/utils/llm.py,
# openhands/storage/, openhands/core/config/llm_config.py are deleted upstream.
# The fork moves the deleted-V0 patches into:
#   - SDK patches (apply-sdk-patches.py: Patches 28-32 for Bedrock features)
#   - V1 custom modules COPY'd by Dockerfile (cognito_user_auth.py,
#     s3_settings_store.py, s3_secrets_store.py — these don't go through this
#     download because they live in openhands-infra/docker/, not upstream)
FORK_REF="${FORK_REF:-bb3fe51c920eec0b51bc7e118e340b582db0649f}"
BASE_URL="https://raw.githubusercontent.com/${FORK_REPO}/${FORK_REF}"

# Files modified in the v1.7.0 fork branch (verified via GitHub compare API:
# gh api repos/zxkane/openhands/compare/<upstream-1.7.0-sha>...<fork-ref>)
# Do NOT add files here that are not in the fork diff — the base image already has them.
# Adding unmodified upstream files can break compatibility when the base image updates.
#
# Files dropped from v1.6.0 (logic moved to SDK fork or removed because the
# upstream V0 surface no longer exists):
#   - openhands/storage/data_models/secrets.py     (storage package collapse;
#                                                   secret-resume validators moved
#                                                   to SDK patches 23/25/26)
#   - openhands/llm/bedrock.py                     (entire openhands/llm/ deleted;
#                                                   logic moved to SDK Patches 28/29)
#   - openhands/llm/llm.py                         (same; SDK Patch 30)
#   - openhands/core/config/llm_config.py          (deleted; AWS_DEFAULT_REGION
#                                                   moved to SDK Patch 31)
#   - openhands/utils/llm.py                       (moved upstream to
#                                                   app_server/utils/llm.py;
#                                                   env-hint detection moved
#                                                   to SDK Patch 32)
#
# Files retained for v1.7.0 (still patched on the fork):
#   - openhands/server/config/server_config.py     (V0-tagged but the
#                                                   settings/secret/user_auth
#                                                   class fields are still active
#                                                   and drive get_impl())
FILES="
openhands/app_server/sandbox/remote_sandbox_service.py
openhands/app_server/app_conversation/app_conversation_service.py
openhands/app_server/app_conversation/live_status_app_conversation_service.py
openhands/app_server/app_conversation/app_conversation_router.py
openhands/app_server/event_callback/webhook_router.py
openhands/app_server/services/db_session_injector.py
openhands/app_server/config.py
openhands/app_server/event_callback/sql_event_callback_service.py
openhands/app_server/secrets/secrets_models.py
openhands/server/config/server_config.py
"

FAILED=""
for file in $FILES; do
  echo "Downloading patched: ${file}"
  if ! curl -fsSL "${BASE_URL}/${file}" -o "/app/${file}"; then
    echo "ERROR: Failed to download ${file}" >&2
    FAILED="${FAILED} ${file}"
  fi
done

if [ -n "$FAILED" ]; then
  echo "========================================" >&2
  echo "FAILED to download patched files:" >&2
  echo "${FAILED}" >&2
  echo "========================================" >&2
  exit 1
fi

echo "All patched files applied from ${FORK_REPO}@${FORK_REF}"
