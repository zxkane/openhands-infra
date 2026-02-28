#!/bin/bash
# PreToolUse hook - blocks git commits when not in a worktree
# All development must happen in a git worktree
# Exit 0 = allow, Exit 2 = block (Claude Code convention)
set -e

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, skipping worktree check" >&2
    exit 0
fi

# Read tool input from stdin (JSON)
TOOL_INPUT=$(cat)

# Extract the actual command from JSON
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# Only check git commit commands
if ! echo "$COMMAND" | grep -qE '^git\s+commit'; then
    exit 0
fi

# Allow amends (fixing existing commits)
if [[ "$COMMAND" =~ --amend ]]; then
    exit 0
fi

# Check if we're inside a worktree (not the main working tree)
# Uses git-dir vs git-common-dir: in a worktree, git-dir points to
# .git/worktrees/<name> which differs from git-common-dir (.git)
if git rev-parse --is-inside-work-tree &>/dev/null; then
    git_dir=$(git rev-parse --git-dir 2>/dev/null || echo "")
    git_common_dir=$(git rev-parse --git-common-dir 2>/dev/null || echo "")
    if [[ "$git_dir" != "$git_common_dir" ]]; then
        exit 0
    fi
fi

# Block the commit
cat >&2 <<'EOF'
**[block-commit-outside-worktree]**
## BLOCKED - Must Use Git Worktree

Committing directly in the main workspace is **not allowed**. All development must happen in a git worktree.

### Required Workflow:
1. Create a worktree:
   ```bash
   git fetch origin main
   git worktree add .worktrees/<name> -b <type>/<name> origin/main
   cd .worktrees/<name>
   npm install
   ```

2. Do all development inside the worktree

3. Commit and push from the worktree

### Why Worktrees?
- Isolates each feature/fix in its own directory
- Prevents accidental changes to main workspace
- Enables parallel work on multiple features
- See CLAUDE.md for the full development workflow
EOF

exit 2
