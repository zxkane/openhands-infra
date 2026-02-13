#!/bin/sh
# Download patched upstream files from the zxkane/openhands fork at Docker build time.
#
# These files contain clean per-feature commits applied against the upstream release tag.
# This replaces the old apply-patch.sh approach of regex/sed patching at container startup.
#
# Environment variables:
#   FORK_REPO  - GitHub org/repo (default: zxkane/openhands)
#   FORK_REF   - Branch or tag   (default: custom-v1.3.0-r1)
set -e

FORK_REPO="${FORK_REPO:-zxkane/openhands}"
# Pin to commit SHA for reproducible builds (tag: custom-v1.3.0-r1)
FORK_REF="${FORK_REF:-0dfc713e37ccecc6fda72cd4434110b744aee7ca}"
BASE_URL="https://raw.githubusercontent.com/${FORK_REPO}/${FORK_REF}"

# 9 upstream Python files modified in the fork
FILES="
openhands/app_server/sandbox/docker_sandbox_service.py
openhands/app_server/app_conversation/live_status_app_conversation_service.py
openhands/app_server/app_conversation/app_conversation_router.py
openhands/app_server/event_callback/webhook_router.py
openhands/app_server/services/db_session_injector.py
openhands/server/config/server_config.py
openhands/storage/data_models/secrets.py
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
