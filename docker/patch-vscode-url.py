"""Patch 31: Fix VS Code URL for Remote sandbox mode.

In RUNTIME=remote mode, conversation.runtime.vscode_url calls the action
execution server's /vscode/connection_token endpoint, but through the
agent-server port (8000) where it doesn't exist → 404.

Fix: patch get_vscode_url() in conversation.py to use the agent-server's
/api/vscode/url endpoint as fallback when runtime.vscode_url fails.
The agent-server returns {"url": "http://localhost:8001/?tkn=...&folder=workspace"}
which patch-fix.js rewrites to the correct runtime subdomain URL.
"""
import sys

CONV_FILE = "/app/openhands/server/routes/conversation.py"

try:
    with open(CONV_FILE, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("Patch 31: conversation.py not found, skipping")
    sys.exit(0)

if "Patch 31" in content:
    print("Patch 31: Already applied")
    sys.exit(0)

# Replace the get_vscode_url function to add fallback
OLD = '''    try:
        runtime: Runtime = conversation.runtime
        logger.debug(f'Runtime type: {type(runtime)}')
        logger.debug(f'Runtime VSCode URL: {runtime.vscode_url}')
        return JSONResponse(
            status_code=status.HTTP_200_OK, content={'vscode_url': runtime.vscode_url}
        )
    except Exception as e:
        logger.error(f'Error getting VSCode URL: {e}')
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                'vscode_url': None,
                'error': f'Error getting VSCode URL: {e}',
            },
        )'''

NEW = '''    try:
        runtime: Runtime = conversation.runtime
        logger.debug(f'Runtime type: {type(runtime)}')
        logger.debug(f'Runtime VSCode URL: {runtime.vscode_url}')
        return JSONResponse(
            status_code=status.HTTP_200_OK, content={'vscode_url': runtime.vscode_url}
        )
    except Exception as e:
        # Patch 31: Fallback for Remote sandbox mode — try agent-server's /api/vscode/url
        # The runtime object has the action_execution_server URL (sandbox IP:port)
        logger.warning(f'runtime.vscode_url failed ({e}), trying agent-server fallback')
        try:
            import httpx
            runtime = conversation.runtime
            # action_execution_server_url points to the sandbox IP:port
            # (same host as agent-server, which has /api/vscode/url)
            base_url = getattr(runtime, 'action_execution_server_url', None)
            logger.info(f'Patch 31: base_url={base_url}')
            if base_url:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(f'{base_url}/api/vscode/url')
                    if resp.status_code == 200:
                        data = resp.json()
                        vscode_url = data.get('url')
                        if vscode_url:
                            logger.info(f'Patch 31: Got VS Code URL from agent-server: {vscode_url}')
                            return JSONResponse(
                                status_code=status.HTTP_200_OK, content={'vscode_url': vscode_url}
                            )
        except Exception as fallback_err:
            logger.warning(f'Patch 31: Fallback also failed: {fallback_err}')
        logger.error(f'Error getting VSCode URL: {e}')
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                'vscode_url': None,
                'error': f'Error getting VSCode URL: {e}',
            },
        )'''

if OLD in content:
    content = content.replace(OLD, NEW)
    with open(CONV_FILE, "w") as f:
        f.write(content)
    print("Patch 31: Added VS Code URL fallback for Remote sandbox mode")
else:
    print("WARNING: Patch 31 pattern not found in conversation.py")
