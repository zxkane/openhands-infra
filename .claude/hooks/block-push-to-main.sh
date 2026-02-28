#!/bin/bash
# PreToolUse hook - blocks git push directly to main branch
# All changes must go through PR workflow
# Exit 0 = allow, Exit 2 = block (Claude Code convention)
set -e

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, skipping push-to-main check" >&2
    exit 0
fi

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Extract the actual command from JSON
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# Only check git push commands
if ! echo "$COMMAND" | grep -qE '^git\s+push'; then
    exit 0
fi

# Get current branch
current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Block pushes targeting main:
# 1. Pushing while on main (without explicit refspec)
# 2. Using refspec to push to main (e.g., git push origin feature:main)
if [[ "$COMMAND" =~ :main([[:space:]]|$) ]] || { [[ "$current_branch" == "main" ]] && ! [[ "$COMMAND" =~ : ]] ; }; then
    cat >&2 <<'EOF'
**[block-push-to-main]**
## BLOCKED - Direct Push to Main

Pushing directly to `main` is **not allowed**. All changes must go through a Pull Request.

### Required Workflow:
1. Create a worktree: `git worktree add .worktrees/feat/<name> -b feat/<name> origin/main`
2. Enter the worktree: `cd .worktrees/feat/<name>`
3. Install dependencies and make your changes
4. Commit inside the worktree
5. Push to the feature branch: `git push -u origin feat/<name>`
6. Create a PR via `gh pr create`

### See CLAUDE.md for the full development workflow.
EOF
    exit 2
fi

exit 0
