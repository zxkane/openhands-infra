#!/bin/bash
# Post git push hook - reminds Claude to wait for CI and run E2E tests
set -e

# Read and parse JSON input from stdin
input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // ""')
exit_code=$(echo "$input" | jq -r '.tool_response.exitCode // .tool_response.exit_code // "1"')

# Only process successful git push commands
if [[ ! "$command" =~ git[[:space:]]+(push|pull[[:space:]]+--push) ]]; then
  exit 0
fi

if [[ "$exit_code" != "0" ]]; then
  exit 0
fi

# Output verification reminder
cat <<'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "## Post-Push Verification Required\n\nGit push completed. Complete these steps before declaring the task done:\n\n### Step 1: Wait for GitHub Actions CI\n```bash\ngh run list --limit 1 --json status,conclusion,name,headBranch\ngh run watch\n```\n\n### Step 2: If CI Fails\n- Analyze failure logs: `gh run view --log-failed`\n- Fix issues and push again\n- Run `/pr-review-toolkit:review-pr` before next push\n- Return to Step 1\n\n### Step 3: If CI Passes - Run E2E Tests\nUse Chrome DevTools MCP to test the deployed environment:\n1. Navigate to the site URL\n2. Execute authentication E2E tests per test/E2E_TEST_CASES.md\n3. Verify all functionality works\n\n### Step 4: After All Verifications Pass\n- Summarize verification results to the user\n- Request peer review if needed\n\n**DO NOT skip these steps or declare completion prematurely.**"
  }
}
EOF

exit 0
