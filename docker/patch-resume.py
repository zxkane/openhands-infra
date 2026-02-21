"""Patch 30: Fix resume flow for Fargate sandboxes.

Modifies app_conversation_router.py to:
1. Remove user_id parameter from start_sandbox() (RemoteSandboxService doesn't accept it)
2. Replace Docker-based Patch 29 secret injection with agent-server conversation init
3. After sandbox creation, POST /api/conversations to agent-server to register the
   conversation — enables WebSocket connections for resumed conversations.
"""
import re
import sys

ROUTER_FILE = "/app/openhands/app_server/app_conversation/app_conversation_router.py"

try:
    with open(ROUTER_FILE, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("Patch 30: Router file not found, skipping")
    sys.exit(0)

# Already patched?
if "Patch 30: Agent-server" in content:
    print("Patch 30: Already applied")
    sys.exit(0)

# Remove user_id=user_id, lines
content = content.replace("            user_id=user_id,\n", "")

# Replace the block from "Sandbox recreated" log to the return statement
# This removes Docker-based Patch 29 and adds Fargate-compatible init
old_pattern = (
    r'_logger\.info\(f"Sandbox recreated for conversation \{conversation_id\}: \{sandbox\.id\}"\)'
    r'.*?'
    r'return \{"status": "ok", "sandbox_id": sandbox\.id\}'
)

new_code = '''_logger.info(f"Sandbox recreated for conversation {conversation_id}: {sandbox.id}")

        # Patch 30: Initialize conversation in agent-server (Fargate-compatible)
        # After start_sandbox(), the agent-server container is running but empty.
        # POST /api/conversations to register the conversation and enable WebSocket.
        try:
            import asyncio as _asyncio

            async def _init_agent_session():
                import httpx
                _init_logger = logging.getLogger(__name__)
                _sandbox_info = await app_conversation_service.sandbox_service.get_sandbox(sandbox.id)
                if not _sandbox_info or not _sandbox_info.url:
                    _init_logger.warning(f"Patch 30: Cannot get sandbox URL for {sandbox.id}")
                    return
                _agent_url = _sandbox_info.url
                _api_key = _sandbox_info.session_api_key
                # Wait for agent-server healthy
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
                _conv_hex = conversation_id.replace('-', '')
                _headers = {'X-Session-API-Key': _api_key} if _api_key else {}
                async with httpx.AsyncClient(timeout=30) as _client:
                    _resp = await _client.post(
                        f'{_agent_url}/api/conversations',
                        json={"conversation_id": _conv_hex},
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
    with open(ROUTER_FILE, "w") as f:
        f.write(result)
    print("Patch 30: Replaced Docker-based resume with Fargate agent-server init")
else:
    print("WARNING: Patch 30 pattern did not match - resume may not work correctly")
