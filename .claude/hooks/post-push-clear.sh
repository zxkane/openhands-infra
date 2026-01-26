#!/bin/bash
# Post-push hook: Clear pr-review state after successful push
# This ensures the next push requires a fresh review

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Only clear for git push commands
if echo "$TOOL_INPUT" | grep -qE 'git.push'; then
    "$STATE_MANAGER" clear pr-review >/dev/null 2>&1
fi

exit 0  # Always allow (post-hook)
