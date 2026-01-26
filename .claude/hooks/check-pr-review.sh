#!/bin/bash
# Pre-push hook: Check if pr-review was run
# Exit 0 = allow, Exit 2 = block (Claude Code convention)

STATE_MANAGER="$(dirname "$0")/state-manager.sh"

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Only check for git push commands
if ! echo "$TOOL_INPUT" | grep -qE 'git.push'; then
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
