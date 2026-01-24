#!/bin/bash
# Stop hook - verifies that completion criteria are met before ending
set -e

# Consume stdin (required by hook interface)
cat > /dev/null

# Get current branch
current_branch=$(git branch --show-current 2>/dev/null || echo "")
if [[ -z "$current_branch" ]]; then
  exit 0
fi

# Calculate time since last push
last_push_time=$(git log -1 --format="%ct" 2>/dev/null || echo "0")
current_time=$(date +%s)
time_diff=$((current_time - last_push_time))

# Get CI status for current branch
ci_status=$(gh run list --branch "$current_branch" --limit 1 --json status,conclusion 2>/dev/null || echo "[]")
status=$(echo "$ci_status" | jq -r '.[0].status // "unknown"')
conclusion=$(echo "$ci_status" | jq -r '.[0].conclusion // "unknown"')

# Helper function to output hook response
# Stop hooks use 'systemMessage' field, not hookSpecificOutput
output_hook_response() {
  local message="$1"
  cat <<EOF
{
  "systemMessage": "$message"
}
EOF
}

# Case 1: CI is still running
if [[ "$status" == "in_progress" || "$status" == "queued" ]]; then
  output_hook_response "## Verification Incomplete - CI Running\\n\\nGitHub Actions is still running on branch '$current_branch'. Please:\\n1. Wait for CI to complete: \`gh run watch\`\\n2. If CI passes, run E2E tests using Chrome DevTools MCP\\n3. Only then can you declare the task complete"
  exit 0
fi

# Case 2: CI failed
if [[ "$status" == "completed" && "$conclusion" == "failure" ]]; then
  output_hook_response "## CI Failed\\n\\nThe latest GitHub Actions run on branch '$current_branch' failed. Please:\\n1. Check failure logs: \`gh run view --log-failed\`\\n2. Fix the issues\\n3. Push the fix and wait for CI to pass\\n4. Run E2E tests before declaring completion"
  exit 0
fi

# Case 3: Recent push (within 15 minutes) with successful CI - remind about E2E
if [[ $time_diff -lt 900 && "$status" == "completed" && "$conclusion" == "success" ]]; then
  output_hook_response "## CI Passed - E2E Verification Required\\n\\nCI passed on branch '$current_branch'. Before declaring task complete:\\n\\n### Required Steps:\\n1. Run E2E tests using Chrome DevTools MCP (see test/E2E_TEST_CASES.md)\\n2. Verify authentication flow works\\n3. Test conversation creation and agent response\\n4. Document results\\n\\n### Verification Checklist:\\n- [ ] Navigated to deployed site\\n- [ ] Tested login/logout flows\\n- [ ] Created new conversation\\n- [ ] Verified agent responds correctly\\n- [ ] No console errors\\n\\n**Only declare completion after E2E verification!**"
  exit 0
fi

exit 0
