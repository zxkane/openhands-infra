#!/bin/sh
# Apply patches at container startup
# This script runs at container startup
set -e  # Exit on error

PATCH_FILE="/opt/patch-fix.js"
INDEX_FILE="/app/frontend/build/index.html"

# Patch 1: Localhost URL fix for index.html
if [ -f "$PATCH_FILE" ] && [ -f "$INDEX_FILE" ]; then
  # Check if already patched with the LATEST patch (check for auto-close settings modal patch)
  if grep -q "auto-close settings modal" "$INDEX_FILE"; then
    echo "Localhost URL patch already applied (with auto-close settings modal)"
  elif grep -q "OpenHands localhost URL fix loaded" "$INDEX_FILE"; then
    # Old patch exists, need to re-patch with new version
    echo "Updating localhost URL patch with auto-close settings modal fix..."
    python3 << 'PYEOF'
import sys
import re

try:
    patch_file = "/opt/patch-fix.js"
    index_file = "/app/frontend/build/index.html"

    with open(patch_file, "r") as f:
        patch_content = f.read()

    with open(index_file, "r") as f:
        html_content = f.read()

    # Remove old patch (everything between <head><script> and </script> for the old patch)
    old_patch_pattern = r'(<head>)<script>\s*// OpenHands localhost URL fix.*?</script>'
    html_content = re.sub(old_patch_pattern, r'\1', html_content, flags=re.DOTALL)

    # Insert new patch after <head>
    patched_content = html_content.replace("<head>", "<head>" + patch_content, 1)

    with open(index_file, "w") as f:
        f.write(patched_content)

    print("Localhost URL patch updated successfully")
except Exception as e:
    print(f"ERROR: Failed to update localhost URL patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  else
    # Apply patch using Python (handles multiline content reliably)
    python3 << 'PYEOF'
import sys

try:
    patch_file = "/opt/patch-fix.js"
    index_file = "/app/frontend/build/index.html"

    with open(patch_file, "r") as f:
        patch_content = f.read()

    with open(index_file, "r") as f:
        html_content = f.read()

    # Insert patch after <head>
    patched_content = html_content.replace("<head>", "<head>" + patch_content, 1)

    with open(index_file, "w") as f:
        f.write(patched_content)

    print("Localhost URL patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply localhost URL patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# Patch 2: sandbox_spec_id fix for docker_sandbox_service.py
# This fixes the issue where image tags[0] returns wrong tag (boto3-v2 vs latest)
# when multiple tags exist. The fix uses container labels instead to get the
# correct sandbox_spec_id.
SANDBOX_SERVICE_FILE="/app/openhands/app_server/sandbox/docker_sandbox_service.py"
if [ -f "$SANDBOX_SERVICE_FILE" ]; then
  if grep -q 'sandbox_spec_id=container.labels.get' "$SANDBOX_SERVICE_FILE"; then
    echo "sandbox_spec_id patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/sandbox/docker_sandbox_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    old_line = "sandbox_spec_id=container.image.tags[0],"
    new_line = 'sandbox_spec_id=container.labels.get("sandbox_spec_id", container.image.tags[0] if container.image.tags else None),'

    if old_line in content:
        content = content.replace(old_line, new_line)
        with open(file_path, 'w') as f:
            f.write(content)
        print("sandbox_spec_id patch applied successfully")
    else:
        print("sandbox_spec_id patch line not found (may already be patched)")
except Exception as e:
    print(f"ERROR: Failed to apply sandbox_spec_id patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# Patch 3: Conversation creation retry logic
# This fixes the race condition where POST /api/conversations fails with 500
# when the agent-server hasn't fully initialized yet after /alive returns 200.
CONV_SERVICE_FILE="/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
if [ -f "$CONV_SERVICE_FILE" ]; then
  if grep -q 'max_retries = 5' "$CONV_SERVICE_FILE"; then
    echo "Conversation retry patch already applied"
  else
    python3 << 'PYEOF'
import re
import sys

try:
    file_path = "/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Find the conversation creation code block and add retry logic
    old_pattern = r'''            response = await self\.httpx_client\.post\(
                f'\{agent_server_url\}/api/conversations',
                json=body_json,
                headers=\{'X-Session-API-Key': sandbox\.session_api_key\},
                timeout=self\.sandbox_startup_timeout,
            \)

            response\.raise_for_status\(\)'''

    new_code = '''            # Retry logic for race condition where agent-server returns 500 before fully initialized
            max_retries = 5
            retry_delay = 2.0
            last_error = None
            for attempt in range(max_retries):
                try:
                    response = await self.httpx_client.post(
                        f'{agent_server_url}/api/conversations',
                        json=body_json,
                        headers={'X-Session-API-Key': sandbox.session_api_key},
                        timeout=self.sandbox_startup_timeout,
                    )
                    response.raise_for_status()
                    break  # Success
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        _logger.warning(f"Conversation creation failed (attempt {attempt + 1}), retrying in {retry_delay}s: {e}")
                        import asyncio
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 1.5  # Exponential backoff
                    else:
                        raise'''

    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_code, content)
        with open(file_path, 'w') as f:
            f.write(content)
        print("Conversation retry patch applied successfully")
    else:
        print("Conversation retry patch pattern not found (may already be patched or code changed)")
except Exception as e:
    print(f"ERROR: Failed to apply conversation retry patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# Patch 4: REMOVED - MCP extra_hosts fix is now in OpenHands v1.2.0 (PR #12236)
# Agent-server containers now have extra_hosts={'host.docker.internal': 'host-gateway'} by default
echo "Patch 4 (MCP extra_hosts) REMOVED - already in OpenHands v1.2.0"

# Detect Python version (3.12 or 3.13) for patching
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

# Patch 5: Copy patched modules to Python path
# This must run BEFORE Patch 6 so the imports can find the patched modules
if [ -f "/app/patched/auth_user_context.py" ]; then
  PATCHED_DIR="/app/.venv/lib/python${PYTHON_VERSION}/site-packages/patched"
  if [ ! -d "$PATCHED_DIR" ]; then
    mkdir -p "$PATCHED_DIR"
    cp -r /app/patched/* "$PATCHED_DIR/"
    echo "Patched modules copied to site-packages (Python ${PYTHON_VERSION})"
  else
    echo "Patched modules already in site-packages"
  fi
fi

# Patch 6: Replace AuthUserContextInjector import with patched version
# This fixes 401 Unauthorized errors on webhook callbacks from agent-server by
# detecting internal Docker network requests early in the auth flow.
# The patched version grants ADMIN access to requests from private IPs with
# X-Session-API-Key header, bypassing Cognito auth for internal webhooks.
APP_INIT_FILE="/app/.venv/lib/python${PYTHON_VERSION}/site-packages/openhands_cloud/app_server/__init__.py"
if [ -f "$APP_INIT_FILE" ] && [ -f "/app/patched/auth_user_context.py" ]; then
  if grep -q "from patched.auth_user_context import" "$APP_INIT_FILE"; then
    echo "AuthUserContextInjector patch already applied"
  else
    python3 << 'PYEOF'
import sys
import re

try:
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    file_path = f"/app/.venv/lib/python{py_ver}/site-packages/openhands_cloud/app_server/__init__.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Pattern to match the import of AuthUserContextInjector
    # Handle various import styles:
    # 1. from openhands_cloud.app_server.injectors.auth_user_context import AuthUserContextInjector
    # 2. from openhands_cloud.app_server.injectors.auth_user_context import (AuthUserContextInjector, ...)
    old_pattern = r'from openhands_cloud\.app_server\.injectors\.auth_user_context import'
    new_import = 'from patched.auth_user_context import'

    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_import, content)
        with open(file_path, 'w') as f:
            f.write(content)
        print("AuthUserContextInjector patch applied successfully")
    else:
        print("AuthUserContextInjector import pattern not found (checking alternative locations)")
        # Try alternative: check if the injector is referenced elsewhere
        # The import might be in config.py or another file
        alternative_found = False
        for alt_path in [
            f"/app/.venv/lib/python{py_ver}/site-packages/openhands_cloud/app_server/config.py",
            f"/app/.venv/lib/python{py_ver}/site-packages/openhands_cloud/app_server/injectors/__init__.py",
        ]:
            try:
                with open(alt_path, 'r') as f:
                    alt_content = f.read()
                if re.search(old_pattern, alt_content):
                    alt_content = re.sub(old_pattern, new_import, alt_content)
                    with open(alt_path, 'w') as f:
                        f.write(alt_content)
                    print(f"AuthUserContextInjector patch applied to {alt_path}")
                    alternative_found = True
            except FileNotFoundError:
                pass
        if not alternative_found:
            print("WARNING: Could not find AuthUserContextInjector import to patch")
except Exception as e:
    print(f"ERROR: Failed to apply AuthUserContextInjector patch: {e}", file=sys.stderr)
    # Don't exit on error - let the app try to start anyway
PYEOF
  fi
fi

# DISABLED: Patch 7 - Host network mode causes port 8000 conflicts with multiple concurrent conversations
# Each agent-server binds to port 8000. With host network mode, only ONE conversation can run at a time.
# The 401 Unauthorized error occurs when a second conversation tries to start while the first is running.
# Disabling this patch allows multiple concurrent conversations (default bridge network mode).
# NOTE: This means /runtime/{port}/ access for Flask apps won't work, but that's a lesser issue.
#
# Original patch was:
# - Set network_mode='host' on agent-server containers
# - This allowed dynamic ports to be directly accessible on host network
# - But caused port 8000 conflicts between multiple agent-servers
echo "Patch 7 (host network) DISABLED - using bridge network for multi-conversation support"

# DISABLED: Patch 8 - exposed_urls fix for host network mode
# This patch is no longer needed since Patch 7 (host network) is disabled.
# With bridge network mode (default), Docker properly populates port bindings.
echo "Patch 8 (exposed_urls) DISABLED - not needed without host network mode"

# Patch 9: Add SSL support for PostgreSQL connections
# Aurora IAM authentication requires SSL connections. The default OpenHands code
# doesn't include SSL parameters in the database connection URL.
# This patch adds connect_args={'ssl': 'require'} to the async engine creation.
DB_SESSION_FILE="/app/openhands/app_server/services/db_session_injector.py"
if [ -f "$DB_SESSION_FILE" ]; then
  if grep -q "connect_args={'ssl'" "$DB_SESSION_FILE"; then
    echo "PostgreSQL SSL patch already applied"
  else
    python3 << 'PYEOF'
import sys
import os

try:
    file_path = "/app/openhands/app_server/services/db_session_injector.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Only apply if DB_SSL environment variable is set
    db_ssl = os.getenv('DB_SSL', '')
    if not db_ssl:
        print("PostgreSQL SSL patch skipped: DB_SSL not set")
        sys.exit(0)

    # Find the create_async_engine call for PostgreSQL and add SSL connect_args
    # The pattern is:
    #   async_engine = create_async_engine(
    #       url,
    #       pool_size=self.pool_size,
    #       max_overflow=self.max_overflow,
    #       pool_recycle=self.pool_recycle,
    #       pool_pre_ping=True,
    #   )
    old_pattern = '''async_engine = create_async_engine(
                    url,
                    pool_size=self.pool_size,
                    max_overflow=self.max_overflow,
                    pool_recycle=self.pool_recycle,
                    pool_pre_ping=True,
                )'''

    new_code = '''async_engine = create_async_engine(
                    url,
                    pool_size=self.pool_size,
                    max_overflow=self.max_overflow,
                    pool_recycle=self.pool_recycle,
                    pool_pre_ping=True,
                    connect_args={'ssl': 'require'},  # Patch 9: SSL required for Aurora IAM auth
                )'''

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("PostgreSQL SSL patch applied successfully")
    else:
        print("PostgreSQL SSL patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply PostgreSQL SSL patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

echo "Starting OpenHands..."

# Execute the original entrypoint
exec /app/entrypoint.sh "$@"
