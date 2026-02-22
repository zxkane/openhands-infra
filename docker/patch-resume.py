"""Patch 30: Fix resume flow for Fargate sandboxes.

Removes incompatible user_id parameter from start_sandbox() calls in the
resume endpoint. RemoteSandboxService.start_sandbox() only accepts
sandbox_id — user_id is obtained internally via UserContext.

NOTE: Full agent-server conversation initialization is NOT handled here.
The Fargate sandbox task starts but the agent-server doesn't have the
conversation registered, so WebSocket connections fail. This requires a
fork-level fix in app_conversation_router.py to use the full
_resume_or_start_conversation flow. See: TODO fork PR.
"""
import sys

ROUTER_FILE = "/app/openhands/app_server/app_conversation/app_conversation_router.py"

try:
    with open(ROUTER_FILE, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("Patch 30: Router file not found, skipping")
    sys.exit(0)

# Remove user_id=user_id, lines from start_sandbox() calls
if "user_id=user_id," in content:
    content = content.replace("            user_id=user_id,\n", "")
    with open(ROUTER_FILE, "w") as f:
        f.write(content)
    print("Patch 30: Removed user_id parameter from start_sandbox() in resume flow")
else:
    print("Patch 30: user_id parameter already removed (clean)")
