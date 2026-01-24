#!/bin/bash
# Pre git push hook - reminds to run code review
set -e

# Read and parse JSON input from stdin
input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // ""')

# Only process git push commands
if [[ ! "$command" =~ git[[:space:]]+(push|pull[[:space:]]+--push) ]]; then
  exit 0
fi

# Output reminder
cat <<'EOF'
{
  "decision": "allow",
  "reason": "## Code Review Reminder\n\nBefore pushing, ensure you have completed a thorough code review:\n\n### Recommended: Run PR review command\n```\n/pr-review-toolkit:review-pr\n```\n\nThis checks:\n- Code style and patterns\n- Silent failure handling\n- Type design quality\n- Test coverage\n\n**Skip if**: You already reviewed or this is a follow-up push after review.\n\nProceeding with push..."
}
EOF

exit 0
