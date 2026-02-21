#!/bin/sh
# Minimal startup script for runtime-dynamic operations.
#
# Upstream file modifications are handled at build time via download-fork-patches.sh
# (pre-patched files from the zxkane/openhands fork). This script handles ONLY
# operations that must happen at container startup:
#
#   - Patch 1:  Inject patch-fix.js into frontend/build/index.html
#   - Patch 5:  Copy patched auth_user_context.py to site-packages
#   - Patch 6:  Swap AuthUserContextInjector import in openhands_cloud
#   - Patch 27a: Database migration DDL (add user_id column if missing)
#   - Patch 21: Verify multi-tenant store configuration
#   - Critical patch failure checks
#
# SDK patches (apply-sdk-patches.py) are handled separately in agent-server-custom/.

set -e

# Track critical patch failures for security-sensitive patches
CRITICAL_PATCH_FAILURES=""

mark_critical_failure() {
  CRITICAL_PATCH_FAILURES="${CRITICAL_PATCH_FAILURES}$1 "
  echo "CRITICAL PATCH FAILURE: $1" >&2
}

# ─── Patch 1: Inject patch-fix.js into index.html ───────────────────────────

PATCH_FILE="/opt/patch-fix.js"
INDEX_FILE="/app/frontend/build/index.html"

if [ -f "$PATCH_FILE" ] && [ -f "$INDEX_FILE" ]; then
  if grep -q "auto-close settings modal" "$INDEX_FILE"; then
    echo "Patch 1: JS patch already applied"
  else
    python3 << 'PYEOF'
import re
import sys

PATCH_PATH = "/opt/patch-fix.js"
INDEX_PATH = "/app/frontend/build/index.html"
OLD_PATCH_PATTERN = r'(<head>)<script>\s*// OpenHands localhost URL fix.*?</script>'

try:
    with open(PATCH_PATH, "r") as f:
        patch_content = f.read()
    with open(INDEX_PATH, "r") as f:
        html_content = f.read()

    # Remove old patch version if present
    html_content = re.sub(OLD_PATCH_PATTERN, r'\1', html_content, flags=re.DOTALL)

    # Insert new patch after <head>
    patched_content = html_content.replace("<head>", "<head>" + patch_content, 1)

    with open(INDEX_PATH, "w") as f:
        f.write(patched_content)

    print("Patch 1: JS patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply JS patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# ─── Patch 5: Copy patched modules to Python site-packages ──────────────────

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') || {
  echo "ERROR: Failed to detect Python version" >&2
  exit 1
}

if [ -f "/app/patched/auth_user_context.py" ]; then
  PATCHED_DIR="/app/.venv/lib/python${PYTHON_VERSION}/site-packages/patched"
  if [ ! -d "$PATCHED_DIR" ]; then
    mkdir -p "$PATCHED_DIR"
    cp -r /app/patched/* "$PATCHED_DIR/"
    echo "Patch 5: Patched modules copied to site-packages (Python ${PYTHON_VERSION})"
  else
    echo "Patch 5: Patched modules already in site-packages"
  fi
fi

# ─── Patch 6: Replace AuthUserContextInjector import with patched version ────

SITE_PACKAGES="/app/.venv/lib/python${PYTHON_VERSION}/site-packages"
if [ -f "/app/patched/auth_user_context.py" ] && [ -d "$SITE_PACKAGES/openhands_cloud" ]; then
  python3 << 'PYEOF'
import re, sys, os

py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
site_packages = f"/app/.venv/lib/python{py_ver}/site-packages"
old_pattern = r'from openhands_cloud\.app_server\.injectors\.auth_user_context import'
new_import = 'from patched.auth_user_context import'

candidates = [
    os.path.join(site_packages, 'openhands_cloud/app_server/__init__.py'),
    os.path.join(site_packages, 'openhands_cloud/app_server/config.py'),
    os.path.join(site_packages, 'openhands_cloud/app_server/injectors/__init__.py'),
]

for path in candidates:
    try:
        with open(path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        continue
    if new_import in content:
        print('Patch 6: AuthUserContextInjector patch already applied')
        sys.exit(0)
    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_import, content)
        with open(path, 'w') as f:
            f.write(content)
        print(f'Patch 6: AuthUserContextInjector patch applied to {path}')
        sys.exit(0)

print('WARNING: Could not find AuthUserContextInjector import to patch')
PYEOF
fi

# ─── Patch 27a: Database migration - add user_id column ─────────────────────

if [ -n "$DATABASE_URL" ]; then
  python3 << 'PYEOF'
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - Patch 27a - %(message)s')
logger = logging.getLogger(__name__)

try:
    import asyncio

    async def run_migration():
        database_url = os.environ['DATABASE_URL']

        import re
        if database_url.startswith('postgresql://'):
            async_url = database_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
        elif database_url.startswith('postgresql+asyncpg://'):
            async_url = database_url
        else:
            logger.warning("Unsupported DATABASE_URL scheme, skipping migration")
            return

        # asyncpg doesn't support sslmode= in URL, use ssl= in connect_args instead
        has_ssl = 'sslmode=' in async_url or os.environ.get('DB_SSL', '')
        async_url = re.sub(r'[?&]sslmode=[^&]*', '', async_url)

        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text

        connect_args = {}
        if has_ssl:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connect_args = {'ssl': ssl_ctx}

        engine = create_async_engine(async_url, connect_args=connect_args)

        async with engine.begin() as conn:
            # Add user_id column (idempotent)
            await conn.execute(text(
                "ALTER TABLE conversation_metadata ADD COLUMN IF NOT EXISTS user_id VARCHAR"
            ))
            logger.info("user_id column ensured on conversation_metadata")

            # Create index (idempotent)
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_conversation_metadata_user_id "
                "ON conversation_metadata(user_id)"
            ))
            logger.info("user_id index ensured")

            # Backfill user_id from app_conversation_start_task
            result = await conn.execute(text("""
                UPDATE conversation_metadata cm
                SET user_id = (
                    SELECT t.created_by_user_id
                    FROM app_conversation_start_task t
                    WHERE t.conversation_id::text = cm.conversation_id
                      AND t.created_by_user_id IS NOT NULL
                    ORDER BY t.created_at DESC
                    LIMIT 1
                )
                WHERE cm.user_id IS NULL
                  AND EXISTS (
                      SELECT 1
                      FROM app_conversation_start_task t
                      WHERE t.conversation_id::text = cm.conversation_id
                        AND t.created_by_user_id IS NOT NULL
                  )
            """))
            logger.info(f"Backfilled user_id for {result.rowcount} existing conversations")

        await engine.dispose()
        logger.info("Database migration completed successfully")

    asyncio.run(run_migration())

except ImportError as e:
    print(f"Patch 27a: Skipping async migration (import error: {e}), will be handled by SQLAlchemy at runtime")
except Exception as e:
    print(f"WARNING: Patch 27a database migration failed: {e}", file=sys.stderr)
    print("The user_id column may be created lazily by SQLAlchemy at runtime")
PYEOF
  echo "Patch 27a: Database migration script executed"
else
  echo "Patch 27a: DATABASE_URL not set, skipping database migration (will happen at runtime)"
fi

# ─── Patch 30: Fix resume flow for Fargate sandboxes ─────────────────────────
# 1. Remove user_id kwarg (RemoteSandboxService.start_sandbox doesn't accept it)
# 2. Replace Docker-based Patch 29 secret injection with Fargate-compatible version
# 3. Add agent-server conversation initialization after sandbox creation
#    (Without this, the agent-server is empty and WebSocket returns 502)
ROUTER_FILE="/app/openhands/app_server/app_conversation/app_conversation_router.py"
if [ -f "$ROUTER_FILE" ]; then
  # Remove user_id parameter from start_sandbox calls
  sed -i '/user_id=user_id,/d' "$ROUTER_FILE"

  # Replace the entire try/except block after start_sandbox with Fargate-compatible resume
  python3 << 'PATCH30'
import re

with open("/app/openhands/app_server/app_conversation/app_conversation_router.py", "r") as f:
    content = f.read()

# Find the return statement and replace the Patch 29 Docker-based code + return
# with Fargate-compatible agent-server initialization + return
old_pattern = r'_logger\.info\(f"Sandbox recreated for conversation.*?\n.*?# Patch 29:.*?return \{"status": "ok", "sandbox_id": sandbox\.id\}'
new_code = '''_logger.info(f"Sandbox recreated for conversation {conversation_id}: {sandbox.id}")

        # Initialize conversation in agent-server (Fargate-compatible)
        # After start_sandbox(), the agent-server is running but empty.
        # We need to POST /api/conversations to register the conversation.
        try:
            import asyncio as _asyncio

            async def _init_agent_session():
                import httpx
                _init_logger = logging.getLogger(__name__)

                # Get sandbox info for agent-server URL
                _sandbox_info = await app_conversation_service.sandbox_service.get_sandbox(sandbox.id)
                if not _sandbox_info or not _sandbox_info.url:
                    _init_logger.warning(f"Patch 30: Cannot get sandbox URL for {sandbox.id}")
                    return

                _agent_url = _sandbox_info.url
                _api_key = _sandbox_info.session_api_key

                # Wait for agent-server to be healthy
                _healthy = False
                async with httpx.AsyncClient(timeout=10) as _hc:
                    for _attempt in range(36):
                        try:
                            _resp = await _hc.get(f'{_agent_url}/alive')
                            if _resp.status_code == 200:
                                _healthy = True
                                _init_logger.info(f"Patch 30: Agent-server healthy after {(_attempt + 1) * 5}s")
                                break
                        except Exception:
                            pass
                        await _asyncio.sleep(5)

                if not _healthy:
                    _init_logger.warning("Patch 30: Agent-server not healthy after 180s")
                    return

                # Create conversation in agent-server
                _conv_hex = conversation_id.replace('-', '')
                _headers = {}
                if _api_key:
                    _headers['X-Session-API-Key'] = _api_key

                # Minimal conversation creation request
                _body = {
                    "conversation_id": _conv_hex,
                }

                async with httpx.AsyncClient(timeout=30) as _client:
                    _resp = await _client.post(
                        f'{_agent_url}/api/conversations',
                        json=_body,
                        headers=_headers,
                    )
                    if _resp.status_code in (200, 201):
                        _init_logger.info(f"Patch 30: Conversation initialized in agent-server: {_conv_hex}")
                    else:
                        _init_logger.warning(f"Patch 30: Conversation init returned {_resp.status_code}: {_resp.text[:200]}")

            _asyncio.create_task(_init_agent_session())
        except Exception as _init_err:
            _logger.warning(f"Patch 30: Agent session init failed (non-fatal): {_init_err}")

        return {"status": "ok", "sandbox_id": sandbox.id}'''

    result = re.sub(old_pattern, new_code, content, flags=re.DOTALL)

    if result != content:
        with open("/app/openhands/app_server/app_conversation/app_conversation_router.py", "w") as f:
            f.write(result)
        print("Patch 30: Replaced Docker-based resume with Fargate-compatible agent-server init")
    else:
        print("Patch 30: Pattern not matched, checking if already patched")
        if "Patch 30: Agent-server" in content:
            print("Patch 30: Already patched")
        else:
            print("WARNING: Patch 30 could not be applied - resume may not work")
PATCH30
else
  echo "Patch 30: Router file not found"
fi

# ─── Verify security-critical fork patches ───────────────────────────────────
# These patches are applied at build time via download-fork-patches.sh.
# Verify that the downloaded files actually contain the expected changes.

# Note: Docker-specific user_id label check removed — Fargate sandbox uses
# RemoteSandboxService which gets user_id from UserContext.get_user_id() internally

APP_CONFIG_FILE="/app/openhands/app_server/config.py"
if [ -f "$APP_CONFIG_FILE" ]; then
  if grep -q "CognitoSQLAppConversationInfoServiceInjector" "$APP_CONFIG_FILE"; then
    echo "Verify: CognitoSQLAppConversationInfoServiceInjector present in config.py"
  else
    mark_critical_failure "Patch27b-conversation-isolation-missing-in-fork"
  fi
fi

# ─── Patch 21: Verify multi-tenant store configuration ──────────────────────

SERVER_CONFIG_FILE="/app/openhands/server/config/server_config.py"
if [ -f "$SERVER_CONFIG_FILE" ]; then
  MISSING_STORES=""

  if grep -q "s3_settings_store.S3SettingsStore" "$SERVER_CONFIG_FILE"; then
    echo "Patch 21: S3SettingsStore configured correctly"
  else
    echo "WARNING: S3SettingsStore not configured - settings may not be user-scoped" >&2
    MISSING_STORES="${MISSING_STORES} S3SettingsStore"
  fi

  if grep -q "s3_secrets_store.S3SecretsStore" "$SERVER_CONFIG_FILE"; then
    echo "Patch 21: S3SecretsStore configured correctly"
  else
    echo "WARNING: S3SecretsStore not configured - secrets may not be user-scoped" >&2
    MISSING_STORES="${MISSING_STORES} S3SecretsStore"
  fi

  if [ -z "$MISSING_STORES" ]; then
    echo "Patch 21: Multi-tenant isolation ENABLED - settings/secrets stored at users/{user_id}/"
  else
    mark_critical_failure "Patch21-multi-tenant-isolation"
  fi
fi

# ─── Final security check ───────────────────────────────────────────────────

if [ -n "$CRITICAL_PATCH_FAILURES" ]; then
  echo "" >&2
  echo "========================================" >&2
  echo "CRITICAL SECURITY PATCHES FAILED" >&2
  echo "========================================" >&2
  echo "The following security-critical patches could not be applied:" >&2
  echo "$CRITICAL_PATCH_FAILURES" >&2
  echo "" >&2
  echo "Refusing to start. Please check the patch patterns against the current OpenHands version." >&2
  echo "========================================" >&2
  exit 1
fi

echo "Starting OpenHands..."

# Execute the original entrypoint
exec /app/entrypoint.sh "$@"
