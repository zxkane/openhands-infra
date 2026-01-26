#!/bin/bash
# Pre-commit hook: Check if code-simplifier was run
# Exit 0 = allow, Exit 2 = block (Claude Code convention)

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, skipping code-simplifier check" >&2
    exit 0  # Allow operation to continue
fi

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Extract the actual command from JSON
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# Only check for git commit commands (not other commands)
if ! echo "$COMMAND" | grep -qE '^git\s+commit'; then
    exit 0  # Not a commit, allow
fi

# Check if code-simplifier was completed
if "$STATE_MANAGER" check code-simplifier >/dev/null 2>&1; then
    exit 0  # Allow
else
    # Output message to stderr for Claude to see
    cat >&2 << 'EOF'
**[run-code-simplifier-before-commit]**
## ⛔ BLOCKED - Run Code Simplifier First

Before committing, you must:

1. **Run code-simplifier agent:**
   ```
   Task tool with subagent_type: code-simplifier:code-simplifier
   ```

2. **Mark as completed:**
   ```bash
   .claude/hooks/state-manager.sh mark code-simplifier
   ```

3. **Retry the commit**

**Skip conditions:** For docs-only changes, run:
```bash
.claude/hooks/state-manager.sh mark code-simplifier
```
EOF
    exit 2  # Block (exit code 2 is Claude Code's blocking code)
fi
