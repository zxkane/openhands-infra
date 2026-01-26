#!/bin/bash
# Post-push hook: Clear pr-review state after successful push
# This ensures the next push requires a fresh review

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Extract command using jq if available, fallback to grep
if command -v jq &> /dev/null; then
    COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
    if echo "$COMMAND" | grep -qE '^git\s+push'; then
        "$STATE_MANAGER" clear pr-review >/dev/null 2>&1
    fi
else
    # Fallback: simple grep match (less precise)
    if echo "$TOOL_INPUT" | grep -qE '"command":\s*"git\s+push'; then
        "$STATE_MANAGER" clear pr-review >/dev/null 2>&1
    fi
fi

exit 0  # Always allow (post-hook)
