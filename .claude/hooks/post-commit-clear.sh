#!/bin/bash
# Post-commit hook: Clear code-simplifier state after successful commit
# This ensures the next commit requires a fresh review

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Only clear for git commit commands
if echo "$TOOL_INPUT" | grep -qE 'git.commit'; then
    "$STATE_MANAGER" clear code-simplifier >/dev/null 2>&1
fi

exit 0  # Always allow (post-hook)
