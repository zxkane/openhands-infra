#!/bin/bash
# Pre git commit hook - reminds to run code simplifier
set -e

# Read and parse JSON input from stdin
input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // ""')

# Only process git commit commands
if [[ ! "$command" =~ git[[:space:]]+commit ]]; then
  exit 0
fi

# Output reminder
cat <<'EOF'
{
  "decision": "allow",
  "reason": "## Code Simplifier Reminder\n\nBefore committing, consider running the code-simplifier agent:\n\n```\nTask tool with subagent_type: code-simplifier:code-simplifier\n```\n\nThe agent will:\n- Review recently modified files\n- Remove redundant code\n- Ensure changes follow existing patterns\n\n**Skip if**: This is a minor docs change, you just ran simplifier, or changes are auto-generated.\n\nProceeding with commit..."
}
EOF

exit 0
