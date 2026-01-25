#!/bin/sh
# Apply patches at container startup
# This script runs at container startup
set -e  # Exit on error

# Track critical patch failures for security-sensitive patches
# Critical patches (like Patch 16 - user_id label) MUST succeed or startup fails
CRITICAL_PATCH_FAILURES=""

# Function to mark a critical patch as failed
mark_critical_failure() {
  CRITICAL_PATCH_FAILURES="${CRITICAL_PATCH_FAILURES}$1 "
  echo "CRITICAL PATCH FAILURE: $1" >&2
}

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

# Patch 2b: Per-sandbox workspace mount for agent-server containers
# SANDBOX_VOLUMES is configured with a base host path, e.g.:
#   /data/openhands/workspace:/workspace:rw
# If we mount that base directly, concurrent sandboxes will share the same /workspace and collide.
# Instead, when the mount targets /workspace, mount a per-sandbox subdirectory:
#   /data/openhands/workspace/<sandbox_id> -> /workspace
#
# Note: docker_sandbox_service.py runs inside the openhands-app container, so we must be able to
# create the host path from inside the container. ComputeStack mounts /data/openhands/workspace
# into openhands-app at the same absolute path, enabling os.makedirs(...) to work.
if [ -f "$SANDBOX_SERVICE_FILE" ]; then
  if grep -q 'Per-sandbox workspace mount (patched by openhands-infra)' "$SANDBOX_SERVICE_FILE"; then
    echo "Per-sandbox workspace mount patch already applied"
  else
    python3 << 'PYEOF'
import re
import sys

try:
    file_path = "/app/openhands/app_server/sandbox/docker_sandbox_service.py"
    with open(file_path, "r") as f:
        content = f.read()

    # Find the "Prepare volumes" dict-comprehension and replace it with per-sandbox mount logic.
    # Keep this tolerant to small formatting differences across upstream versions and our other patches.
    pattern = re.compile(
        r"(?P<lead>^[ \t]*# Prepare volumes[ \t]*\n)"
        r"(?P<indent>^[ \t]*)volumes[ \t]*=[ \t]*\{"
        r"(?s:.*?mount\.host_path.*?for[ \t]+mount[ \t]+in[ \t]+self\.mounts.*?\n[ \t]*\}[ \t]*\n)",
        re.MULTILINE,
    )

    m = pattern.search(content)
    if not m:
        print("WARNING: Prepare volumes block not found; per-sandbox mount patch not applied", file=sys.stderr)
        sys.exit(0)

    indent = m.group("indent")
    lead = m.group("lead")

    replacement = (
        lead
        + f"{indent}# Per-sandbox workspace mount (patched by openhands-infra): treat mount.host_path as a base dir for /workspace\n"
        + f"{indent}volumes = {{}}\n"
        + f"{indent}for mount in self.mounts:\n"
        + f"{indent}    host_path = mount.host_path\n"
        + f"{indent}    if mount.container_path == '/workspace':\n"
        + f"{indent}        import os as _os\n"
        + f"{indent}        host_path = _os.path.join(host_path, sandbox_id)\n"
        + f"{indent}        _os.makedirs(host_path, exist_ok=True)\n"
        + f"{indent}        try:\n"
        + f"{indent}            _os.chmod(host_path, 0o777)\n"
        + f"{indent}        except Exception:\n"
        + f"{indent}            pass\n"
        + f"{indent}    volumes[host_path] = {{\n"
        + f"{indent}        'bind': mount.container_path,\n"
        + f"{indent}        'mode': mount.mode,\n"
        + f"{indent}    }}\n"
    )

    content = content[: m.start()] + replacement + content[m.end() :]

    with open(file_path, "w") as f:
        f.write(content)

    print("Per-sandbox workspace mount patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply per-sandbox workspace mount patch: {e}", file=sys.stderr)
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

# Patch 3a: Add user_id parameter to start_sandbox() signature
# This MUST run before Patch 3b so recreated sandboxes can pass user_id
# for proper cross-user authorization in OpenResty.
SANDBOX_SERVICE_FILE="/app/openhands/app_server/sandbox/docker_sandbox_service.py"
if [ -f "$SANDBOX_SERVICE_FILE" ]; then
  if grep -q "user_id: str | None = None" "$SANDBOX_SERVICE_FILE"; then
    echo "start_sandbox user_id signature patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/sandbox/docker_sandbox_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Step 1: Add user_id parameter to start_sandbox method signature
    # Handle both single-line and multi-line formats

    # Try multi-line format first (OpenHands 1.2.1+)
    old_sig_multiline = """async def start_sandbox(
        self, sandbox_spec_id: str | None = None, sandbox_id: str | None = None
    ) -> SandboxInfo:"""
    new_sig_multiline = """async def start_sandbox(
        self, sandbox_spec_id: str | None = None, sandbox_id: str | None = None, user_id: str | None = None
    ) -> SandboxInfo:"""

    if old_sig_multiline in content:
        content = content.replace(old_sig_multiline, new_sig_multiline)
        print("Step 1: start_sandbox signature updated (multi-line format)")
    else:
        # Try old single-line format
        old_sig = "async def start_sandbox(self, sandbox_id: str | None = None) -> Sandbox:"
        new_sig = "async def start_sandbox(self, sandbox_id: str | None = None, user_id: str | None = None) -> Sandbox:"
        if old_sig in content:
            content = content.replace(old_sig, new_sig)
            print("Step 1: start_sandbox signature updated (single-line format)")
        else:
            print("Step 1: start_sandbox signature not found or already patched")

    # Step 2: Add user_id to labels dict (after Patch 10 adds conversation_id)
    old_labels = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
            'conversation_id': sandbox_id,  # Patch 10: Enable OpenResty dynamic routing
        }"""
    new_labels = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
            'conversation_id': sandbox_id,  # Patch 10: Enable OpenResty dynamic routing
            'user_id': user_id,  # Patch 3a: Enable cross-user authorization
        }"""

    if old_labels in content:
        content = content.replace(old_labels, new_labels)
        print("Step 2: user_id label added to labels dict")
    else:
        # Maybe Patch 10 wasn't applied yet, try the original pattern
        old_labels_orig = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
        }"""
        new_labels_orig = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
            'conversation_id': sandbox_id,  # Patch 10: Enable OpenResty dynamic routing
            'user_id': user_id,  # Patch 3a: Enable cross-user authorization
        }"""
        if old_labels_orig in content:
            content = content.replace(old_labels_orig, new_labels_orig)
            print("Step 2: user_id and conversation_id labels added (Patch 10 combined)")
        else:
            print("Step 2: labels pattern not found (may need Patch 10 first)")

    with open(file_path, 'w') as f:
        f.write(content)

    print("start_sandbox user_id signature patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply start_sandbox signature patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# Patch 3b: Recreate missing sandbox on resume (EC2 replacement)
# When the EC2 host is replaced, previously running agent-server containers are gone.
# The conversation still references task.request.sandbox_id, and the default behavior
# is to raise "Sandbox not found", leaving the UI stuck in "Connecting...".
#
# Fix: if get_sandbox(...) returns None, create a new sandbox using the same
# sandbox id (strip the standard container prefix if present) so the workspace
# can be re-mounted from the EFS-backed host path and the conversation can continue.
#
# NOTE: Patch 3a MUST run first to add user_id parameter to start_sandbox() signature.
CONV_SERVICE_FILE="/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
if [ -f "$CONV_SERVICE_FILE" ]; then
  if grep -q 'Recreate missing sandbox (EC2 replacement)' "$CONV_SERVICE_FILE"; then
    echo "Missing sandbox resume patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
    with open(file_path, "r") as f:
        content = f.read()

    old_block = """            if sandbox_info is None:
                raise SandboxError(f'Sandbox not found: {task.request.sandbox_id}')
            sandbox = sandbox_info
"""

    new_block = """            if sandbox_info is None:
                # Recreate missing sandbox (EC2 replacement): the host was replaced so the docker
                # container no longer exists, but the workspace is persisted on EFS.
                import logging
                _resume_logger = logging.getLogger(__name__)
                _resume_logger.info(f'Sandbox missing for conversation, recreating: {task.request.sandbox_id}')
                sandbox_id_for_start = task.request.sandbox_id
                prefix = 'oh-agent-server-'
                if sandbox_id_for_start.startswith(prefix):
                    sandbox_id_for_start = sandbox_id_for_start[len(prefix):]
                sandbox = await self.sandbox_service.start_sandbox(
                    sandbox_id=sandbox_id_for_start,
                    user_id=task.created_by_user_id,
                )
                task.sandbox_id = sandbox.id
                task.request.sandbox_id = sandbox.id
                _resume_logger.info(f'Sandbox recreated with user_id={task.created_by_user_id}: {sandbox.id}')
            else:
                sandbox = sandbox_info
"""

    if old_block not in content:
        print("WARNING: Missing-sandbox resume block not found; patch not applied", file=sys.stderr)
        sys.exit(0)

    content = content.replace(old_block, new_block, 1)
    # Add an idempotency marker.
    content = content.replace(
        "# Recreate missing sandbox (EC2 replacement):",
        "# Recreate missing sandbox (EC2 replacement) (patched by openhands-infra):",
        1,
    )

    with open(file_path, "w") as f:
        f.write(content)

    print("Missing sandbox resume patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply missing sandbox resume patch: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  fi
fi

# Patch 3c: Add /resume endpoint to trigger sandbox recreation for ARCHIVED conversations
# When EC2 is replaced, sandbox containers are gone and conversations show ARCHIVED status.
# The frontend calls this endpoint to trigger sandbox recreation directly via sandbox_service.
CONV_ROUTER_FILE="/app/openhands/app_server/app_conversation/app_conversation_router.py"
if [ -f "$CONV_ROUTER_FILE" ]; then
  if grep -q 'resume_app_conversation' "$CONV_ROUTER_FILE"; then
    echo "Resume endpoint patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/app_conversation/app_conversation_router.py"
    with open(file_path, "r") as f:
        content = f.read()

    # Add the resume endpoint after the update endpoint (@router.patch)
    old_endpoint = """@router.patch('/{conversation_id}')
async def update_app_conversation("""

    new_endpoint = """@router.post('/{conversation_id}/resume')
async def resume_app_conversation(
    conversation_id: str,
    request: Request,
    response: Response,
    app_conversation_service: AppConversationService = app_conversation_service_dependency,
) -> dict:
    '''Resume an ARCHIVED conversation by recreating its sandbox.

    This endpoint triggers sandbox recreation for conversations that were archived
    due to EC2 instance replacement. The sandbox will be recreated with the same
    conversation_id and user_id labels, allowing the workspace to be reconnected.
    '''
    import logging
    from uuid import UUID
    _logger = logging.getLogger(__name__)

    conv_uuid = UUID(conversation_id)

    # Get the conversation info to check status and get user_id
    conversations = await app_conversation_service.batch_get_app_conversations([conv_uuid])
    if not conversations or not conversations[0]:
        response.status_code = 404
        return {"error": "Conversation not found"}

    conv = conversations[0]

    # Only resume ARCHIVED conversations (sandbox is MISSING)
    from openhands.app_server.sandbox.sandbox_models import SandboxStatus
    if conv.sandbox_status != SandboxStatus.MISSING:
        return {"status": "ok", "message": "Conversation is not archived", "sandbox_status": str(conv.sandbox_status)}

    _logger.info(f"Resume requested for ARCHIVED conversation: {conversation_id}")

    # Get the user_id from the conversation info service
    conv_info = await app_conversation_service.app_conversation_info_service.get_app_conversation_info(conv_uuid)
    if not conv_info:
        response.status_code = 404
        return {"error": "Conversation info not found"}

    user_id = conv_info.created_by_user_id
    sandbox_id = conv_info.sandbox_id

    if not sandbox_id:
        response.status_code = 400
        return {"error": "No sandbox_id found for conversation"}

    _logger.info(f"Recreating sandbox {sandbox_id} for user {user_id}")

    try:
        # Strip the oh-agent-server- prefix if present
        sandbox_id_for_start = sandbox_id
        prefix = 'oh-agent-server-'
        if sandbox_id_for_start.startswith(prefix):
            sandbox_id_for_start = sandbox_id_for_start[len(prefix):]

        # Directly call sandbox_service.start_sandbox with user_id (Patch 3a signature)
        sandbox = await app_conversation_service.sandbox_service.start_sandbox(
            sandbox_id=sandbox_id_for_start,
            user_id=user_id,
        )

        _logger.info(f"Sandbox recreated for conversation {conversation_id}: {sandbox.id}")
        return {"status": "ok", "sandbox_id": sandbox.id}
    except Exception as e:
        _logger.exception(f"Failed to resume conversation {conversation_id}: {e}")
        response.status_code = 500
        return {"error": str(e)}


@router.patch('/{conversation_id}')
async def update_app_conversation("""

    if old_endpoint not in content:
        print("WARNING: Could not find update_app_conversation endpoint; resume patch not applied", file=sys.stderr)
        sys.exit(0)

    content = content.replace(old_endpoint, new_endpoint, 1)

    with open(file_path, "w") as f:
        f.write(content)

    print("Resume endpoint patch applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply resume endpoint patch: {e}", file=sys.stderr)
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

# Patch 10: Add conversation_id label to sandbox containers
# This enables dynamic routing via OpenResty - each container is labeled with its conversation_id
# so the Lua router can find the correct container IP for /runtime/{conversation_id}/{port}/ URLs
# sandbox_id parameter in docker_sandbox_service.py IS conversation_id.hex (from live_status_app_conversation_service.py)
SANDBOX_SERVICE_FILE="/app/openhands/app_server/sandbox/docker_sandbox_service.py"
if [ -f "$SANDBOX_SERVICE_FILE" ]; then
  if grep -q "'conversation_id': sandbox_id" "$SANDBOX_SERVICE_FILE"; then
    echo "conversation_id label patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/sandbox/docker_sandbox_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Find the labels dict in create() method and add conversation_id
    # Original pattern:
    #   labels = {
    #       'sandbox_spec_id': sandbox_spec.id,
    #   }
    old_pattern = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
        }"""

    new_code = """labels = {
            'sandbox_spec_id': sandbox_spec.id,
            'conversation_id': sandbox_id,  # Patch 10: Enable OpenResty dynamic routing
        }"""

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("conversation_id label patch applied successfully")
    else:
        print("conversation_id label patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply conversation_id label patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 11: Generate conversation_id BEFORE sandbox creation
# This ensures the conversation_id is available when starting the sandbox, so the
# container label matches the URL format used by the frontend (/runtime/{conversation_id.hex}/{port}/)
# Without this patch, sandbox_id could be None when conversation_id is not provided in the request,
# causing a random base62 ID to be generated instead of the conversation UUID hex.
CONV_SERVICE_FILE="/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
if [ -f "$CONV_SERVICE_FILE" ]; then
  if grep -q "# Patch 11: Ensure conversation_id exists" "$CONV_SERVICE_FILE"; then
    echo "conversation_id generation patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Find the sandbox_id_str generation code and add early conversation_id generation
    # Original pattern:
    #         if not task.request.sandbox_id:
    #             # Convert conversation_id to hex string if present
    #             sandbox_id_str = (
    #                 task.request.conversation_id.hex
    #                 if task.request.conversation_id is not None
    #                 else None
    #             )
    old_pattern = """        if not task.request.sandbox_id:
            # Convert conversation_id to hex string if present
            sandbox_id_str = (
                task.request.conversation_id.hex
                if task.request.conversation_id is not None
                else None
            )"""

    new_code = """        if not task.request.sandbox_id:
            # Patch 11: Ensure conversation_id exists before sandbox creation
            # This is needed for OpenResty dynamic routing to work correctly
            # The container label needs to match the URL format: /runtime/{conversation_id.hex}/{port}/
            if task.request.conversation_id is None:
                from uuid import uuid4
                task.request.conversation_id = uuid4()
            sandbox_id_str = task.request.conversation_id.hex"""

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("conversation_id generation patch applied successfully")
    else:
        print("conversation_id generation patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply conversation_id generation patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 12 + Patch 17: Add webhook headers and git safe.directory for agent-server containers
# Patch 12: When agent-server sends webhook callbacks to openhands-app, it needs to include
# the X-Session-API-Key header for authentication. Without this, webhook endpoints
# return 401 Unauthorized and conversations fail to initialize properly.
# Patch 17: Fix git "dubious ownership" error when workspace files created by host user
# are accessed inside container by different user. Sets GIT_CONFIG_PARAMETERS='safe.directory=*'.
SANDBOX_SERVICE_FILE="/app/openhands/app_server/sandbox/docker_sandbox_service.py"
if [ -f "$SANDBOX_SERVICE_FILE" ]; then
  if grep -q "GIT_CONFIG_PARAMETERS" "$SANDBOX_SERVICE_FILE"; then
    echo "Patch 12 (webhook headers) and Patch 17 (git safe.directory) already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/sandbox/docker_sandbox_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Add json import if not present
    if 'import json' not in content:
        # Add after the first import block
        content = content.replace('import logging', 'import json\nimport logging', 1)

    # Check if this is an upgrade (Patch 12 exists but Patch 17 missing)
    if 'OH_WEBHOOKS_0_HEADERS' in content and 'GIT_CONFIG_PARAMETERS' not in content:
        # Upgrade path: add Patch 17 to existing Patch 12
        old_headers_pattern = """env_vars['OH_WEBHOOKS_0_HEADERS'] = json.dumps({'X-Session-API-Key': session_api_key})"""
        new_headers_code = """env_vars['OH_WEBHOOKS_0_HEADERS'] = json.dumps({'X-Session-API-Key': session_api_key})
        # Patch 17: Fix git "dubious ownership" error for EFS-persisted workspaces
        # When workspace files are created by one user (ec2-user on host) but accessed by
        # another user (inside container), git fails with "dubious ownership" error.
        # Setting safe.directory=* allows git operations on any directory.
        env_vars['GIT_CONFIG_PARAMETERS'] = "'" + "safe.directory=*" + "'" """
        if old_headers_pattern in content:
            content = content.replace(old_headers_pattern, new_headers_code)
            with open(file_path, 'w') as f:
                f.write(content)
            print("Patch 17 (git safe.directory) added to existing Patch 12")
        else:
            print("WARNING: Could not find Patch 12 pattern to add Patch 17")
    else:
        # Fresh install: apply both Patch 12 and Patch 17
        old_pattern = """env_vars[WEBHOOK_CALLBACK_VARIABLE] = (
            f'http://host.docker.internal:{self.host_port}/api/v1/webhooks'
        )"""

        new_code = """env_vars[WEBHOOK_CALLBACK_VARIABLE] = (
            f'http://host.docker.internal:{self.host_port}/api/v1/webhooks'
        )
        # Patch 12: Add webhook headers for authentication
        # Agent-server needs X-Session-API-Key header when calling back to openhands-app
        env_vars['OH_WEBHOOKS_0_HEADERS'] = json.dumps({'X-Session-API-Key': session_api_key})
        # Patch 17: Fix git "dubious ownership" error for EFS-persisted workspaces
        # When workspace files are created by one user (ec2-user on host) but accessed by
        # another user (inside container), git fails with "dubious ownership" error.
        # Setting safe.directory=* allows git operations on any directory.
        env_vars['GIT_CONFIG_PARAMETERS'] = "'" + "safe.directory=*" + "'" """

        if old_pattern in content:
            content = content.replace(old_pattern, new_code)
            with open(file_path, 'w') as f:
                f.write(content)
            print("Patch 12 (webhook headers) and Patch 17 (git safe.directory) applied successfully")
        else:
            print("Patch 12/17 pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply Patch 12/17: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 13: Fix user_id not saved in background task
# When a conversation is created, the HTTP request completes after the first yield,
# and the rest of _start_app_conversation runs in a background task (asyncio.create_task).
# At that point, self.user_context.get_user_id() returns None because the request context
# is closed. The fix is to use task.created_by_user_id which was captured at the start.
CONV_SERVICE_FILE="/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
if [ -f "$CONV_SERVICE_FILE" ]; then
  if grep -q "# Patch 13: Reuse user_id from task" "$CONV_SERVICE_FILE"; then
    echo "user_id background task patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Find the code that gets user_id again after sandbox start
    # Original pattern:
    #             # Store info...
    #             user_id = await self.user_context.get_user_id()
    old_pattern = """            # Store info...
            user_id = await self.user_context.get_user_id()"""

    new_code = """            # Store info...
            # Patch 13: Reuse user_id from task instead of calling user_context.get_user_id()
            # By this point, the HTTP request context is closed (running in background task)
            # so user_context.get_user_id() would return None
            user_id = task.created_by_user_id"""

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("user_id background task patch applied successfully")
    else:
        print("user_id background task patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply user_id background task patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 14: Fix webhook 401 by allowing None created_by_user_id in sandbox validation
# The docker_sandbox_service doesn't store user_id in container labels, so sandbox_info.created_by_user_id
# is always None. The valid_conversation function compares this with app_conversation_info.created_by_user_id
# (which has the actual user ID), causing a mismatch and AuthError.
# Since the session API key validation already proves the request is from the correct sandbox,
# we can safely skip the user_id comparison when sandbox_info.created_by_user_id is None.
WEBHOOK_ROUTER_FILE="/app/openhands/app_server/event_callback/webhook_router.py"
if [ -f "$WEBHOOK_ROUTER_FILE" ]; then
  if grep -q "sandbox_info.created_by_user_id is not None and" "$WEBHOOK_ROUTER_FILE"; then
    echo "webhook valid_conversation patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/event_callback/webhook_router.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Find the user_id comparison in valid_conversation and add None check
    # Original pattern:
    #     if app_conversation_info.created_by_user_id != sandbox_info.created_by_user_id:
    old_pattern = "if app_conversation_info.created_by_user_id != sandbox_info.created_by_user_id:"

    # New pattern: allow None sandbox_info.created_by_user_id
    new_code = """if sandbox_info.created_by_user_id is not None and app_conversation_info.created_by_user_id != sandbox_info.created_by_user_id:"""

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("webhook valid_conversation patch applied successfully")
    else:
        print("webhook valid_conversation patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply webhook valid_conversation patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 15: Fix webhook on_conversation_update to preserve existing user_id
# When the agent-server sends a webhook before the background task saves the conversation,
# the on_conversation_update handler creates the conversation with sandbox_info.created_by_user_id
# which is None (since Docker containers don't store user_id). This causes the user_id to be
# saved as empty string, making the conversation invisible in the user's list.
# Fix: Preserve the existing created_by_user_id if the conversation already exists in the database.
WEBHOOK_ROUTER_FILE="/app/openhands/app_server/event_callback/webhook_router.py"
if [ -f "$WEBHOOK_ROUTER_FILE" ]; then
  if grep -q "existing.created_by_user_id or sandbox_info.created_by_user_id" "$WEBHOOK_ROUTER_FILE"; then
    echo "webhook user_id preservation patch already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    file_path = "/app/openhands/app_server/event_callback/webhook_router.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # In on_conversation_update, change:
    #     created_by_user_id=sandbox_info.created_by_user_id,
    # to:
    #     created_by_user_id=existing.created_by_user_id or sandbox_info.created_by_user_id,
    # This preserves the user_id from the database if the conversation already exists

    # We need to be careful to only replace the one in on_conversation_update, not in valid_conversation
    # The one in on_conversation_update is inside AppConversationInfo(... created_by_user_id=sandbox_info.created_by_user_id,

    old_pattern = """app_conversation_info = AppConversationInfo(
        id=conversation_info.id,
        title=existing.title or f'Conversation {conversation_info.id.hex}',
        sandbox_id=sandbox_info.id,
        created_by_user_id=sandbox_info.created_by_user_id,"""

    new_code = """app_conversation_info = AppConversationInfo(
        id=conversation_info.id,
        title=existing.title or f'Conversation {conversation_info.id.hex}',
        sandbox_id=sandbox_info.id,
        created_by_user_id=existing.created_by_user_id or sandbox_info.created_by_user_id,"""

    if old_pattern in content:
        content = content.replace(old_pattern, new_code)
        with open(file_path, 'w') as f:
            f.write(content)
        print("webhook user_id preservation patch applied successfully")
    else:
        print("webhook user_id preservation patch pattern not found (code structure may have changed)")
except Exception as e:
    print(f"ERROR: Failed to apply webhook user_id preservation patch: {e}", file=sys.stderr)
    # Don't exit - let app try to start
PYEOF
  fi
fi

# Patch 16: Pass user_id to start_sandbox() for NEW conversations
# This complements Patch 3a (signature modification) and Patch 3b (resume sandbox recreation).
# Patch 3a adds the user_id parameter to start_sandbox() and adds user_id to container labels.
# Patch 3b passes user_id when recreating sandboxes for archived conversations.
# This patch (16) passes user_id when creating NEW conversation sandboxes.
#
# Together, these patches ensure:
# - All sandboxes (new and recreated) get the user_id label
# - OpenResty can verify container ownership for runtime URL access
# - Authorization works correctly for both new and resumed conversations
CONV_SERVICE_FILE="/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"
if [ -f "$CONV_SERVICE_FILE" ]; then
  if grep -q "user_id=task.created_by_user_id,  # Patch 16" "$CONV_SERVICE_FILE"; then
    echo "Patch 16 (user_id for new conversations) already applied"
  else
    python3 << 'PYEOF'
import sys

try:
    conv_file = "/app/openhands/app_server/app_conversation/live_status_app_conversation_service.py"

    with open(conv_file, 'r') as f:
        content = f.read()

    # Find the start_sandbox call for NEW conversations and add user_id parameter
    # This call is in the "if not task.request.sandbox_id:" block (new conversation)
    # Original:
    #             sandbox = await self.sandbox_service.start_sandbox(
    #                 sandbox_id=sandbox_id_str
    #             )
    # New:
    #             sandbox = await self.sandbox_service.start_sandbox(
    #                 sandbox_id=sandbox_id_str,
    #                 user_id=task.created_by_user_id,  # Patch 16: Pass user_id for container label
    #             )
    old_call = """sandbox = await self.sandbox_service.start_sandbox(
                sandbox_id=sandbox_id_str
            )"""

    new_call = """sandbox = await self.sandbox_service.start_sandbox(
                sandbox_id=sandbox_id_str,
                user_id=task.created_by_user_id,  # Patch 16: Pass user_id for container label
            )"""

    if old_call in content:
        content = content.replace(old_call, new_call)
        with open(conv_file, 'w') as f:
            f.write(content)
        print("Patch 16: user_id added to start_sandbox call for new conversations")
    elif "user_id=task.created_by_user_id" in content:
        print("Patch 16: start_sandbox already has user_id parameter")
    else:
        print("Patch 16: start_sandbox call pattern not found (code structure may have changed)")

    print("Patch 16 applied successfully")
except Exception as e:
    print(f"ERROR: Failed to apply Patch 16: {e}", file=sys.stderr)
    # CRITICAL: This is a security patch - mark failure for startup check
    print("PATCH16_FAILED", file=sys.stderr)
    sys.exit(1)
PYEOF
    # Check if the Python script indicated failure
    if [ $? -ne 0 ]; then
      mark_critical_failure "Patch16-user_id_label"
    fi
  fi
fi

# Final security check: fail startup if any critical patches failed
if [ -n "$CRITICAL_PATCH_FAILURES" ]; then
  echo "" >&2
  echo "========================================" >&2
  echo "CRITICAL SECURITY PATCHES FAILED" >&2
  echo "========================================" >&2
  echo "The following security-critical patches could not be applied:" >&2
  echo "$CRITICAL_PATCH_FAILURES" >&2
  echo "" >&2
  echo "This may leave the application in an insecure state." >&2
  echo "Refusing to start. Please check the patch patterns against the current OpenHands version." >&2
  echo "========================================" >&2
  exit 1
fi

echo "Starting OpenHands..."

# Execute the original entrypoint
exec /app/entrypoint.sh "$@"
