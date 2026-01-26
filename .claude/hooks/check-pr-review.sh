#!/bin/bash
# Pre-push hook: Check if pr-review was run
# Exit 0 = allow, Exit 2 = block (Claude Code convention)

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, skipping pr-review check" >&2
    exit 0  # Allow operation to continue
fi

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Extract the actual command from JSON
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# Only check for git push commands (not commit messages containing "push")
if ! echo "$COMMAND" | grep -qE '^git\s+push'; then
    exit 0  # Not a push, allow
fi

# Check if pr-review was completed
if "$STATE_MANAGER" check pr-review >/dev/null 2>&1; then
    exit 0  # Allow
else
    # Output message to stderr for Claude to see
    cat >&2 << 'EOF'
**[require-code-review-before-push]**
## ⛔ BLOCKED - Run PR Review First

Before pushing, you must:

1. **Run PR review:**
   ```
   /pr-review-toolkit:review-pr
   ```

2. **Address all Critical/High severity findings**

3. **Mark as completed:**
   ```bash
   .claude/hooks/state-manager.sh mark pr-review
   ```

4. **Retry the push**

**Skip conditions:** For follow-up pushes after review, run:
```bash
.claude/hooks/state-manager.sh mark pr-review
```
EOF
    exit 2  # Block (exit code 2 is Claude Code's blocking code)
fi
