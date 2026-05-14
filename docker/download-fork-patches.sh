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
# openhands/storage/, openhands/core/config/llm_config.py and several
# openhands/server/config/server_config.py fields are deleted upstream. The fork
# moves those patches into the SDK fork (see docker/agent-server-custom/apply-sdk-patches.py)
# or onto V1 paths under openhands/app_server/.
#
# TODO(PR #81): pin to the final SHA of custom/v1.7.0-fargate once the fork branch
# is complete. The current value is the partial cherry-pick checkpoint (17/20
# commits ported from custom-v1.6.0-fargate-r1).
FORK_REF="${FORK_REF:-b707ea5cc1a410e9dd26058071a260188da99fc9}"
BASE_URL="https://raw.githubusercontent.com/${FORK_REPO}/${FORK_REF}"

# Files modified in the v1.7.0 fork branch (verified via GitHub compare API:
# gh api repos/zxkane/openhands/compare/<upstream-1.7.0-sha>...<fork-ref>)
# Do NOT add files here that are not in the fork diff — the base image already has them.
# Adding unmodified upstream files can break compatibility when the base image updates.
#
# Files dropped from v1.6.0 → v1.7.0 (logic moved to SDK fork or removed because
# the upstream V0 surface no longer exists):
#   - openhands/server/config/server_config.py     (V0 store-class fields removed upstream)
#   - openhands/storage/data_models/secrets.py     (storage package collapse — no V1 home needed)
#   - openhands/llm/bedrock.py                     (entire openhands/llm/ package deleted)
#   - openhands/llm/llm.py                         (same)
#   - openhands/core/config/llm_config.py          (deleted; AWS_DEFAULT_REGION moved to SDK Patch 31)
#   - openhands/utils/llm.py                       (moved upstream to app_server/utils/llm.py;
#                                                   env-hint detection moved to SDK Patch 32)
#
# Files added net-new for v1.7.0 (V1 ports of V0 Cognito / S3 stores; these don't
# exist upstream — the fork branch must create them under openhands/app_server/).
# They are intentionally NOT in FILES yet because the fork branch is still in
# progress (only 17/20 v1.6.0 commits cherry-picked; V1 store ports pending).
# Add the lines below once the fork branch creates them and FORK_REF is bumped:
#
#   openhands/app_server/user_auth/cognito_user_auth.py
#   openhands/app_server/settings/cognito_s3_settings_store.py
#   openhands/app_server/secrets/cognito_s3_secrets_store.py
#
# When you add them, also rewrite Patch 21 in apply-startup.sh to grep for the
# new V1 paths (V0 grep for s3_settings_store.S3SettingsStore would silently pass).
FILES="
openhands/app_server/sandbox/remote_sandbox_service.py
openhands/app_server/app_conversation/app_conversation_service.py
openhands/app_server/app_conversation/live_status_app_conversation_service.py
openhands/app_server/app_conversation/app_conversation_router.py
openhands/app_server/event_callback/webhook_router.py
openhands/app_server/services/db_session_injector.py
openhands/app_server/config.py
openhands/app_server/event_callback/sql_event_callback_service.py
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
