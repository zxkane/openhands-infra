#!/bin/bash
# Post git push hook - instructs Claude to wait for CI and run E2E tests
set -e

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, skipping post-push CI workflow" >&2
    exit 0
fi

if ! command -v gh &> /dev/null; then
    echo "Warning: gh CLI not installed, skipping post-push CI workflow" >&2
    exit 0
fi

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

# Get current branch and check if there's a PR
BRANCH=$(git branch --show-current 2>/dev/null || echo "")
if [[ -z "$BRANCH" || "$BRANCH" == "main" || "$BRANCH" == "master" ]]; then
  exit 0
fi

# Try to get PR number
PR_NUMBER=$(gh pr view --json number -q '.number' 2>/dev/null || echo "")

# Build the instruction message
if [[ -n "$PR_NUMBER" ]]; then
  PR_INFO="PR #${PR_NUMBER} on branch \`${BRANCH}\`"
  PR_CHECKS_CMD="gh pr checks ${PR_NUMBER} --watch"
  PR_VIEW_CMD="gh pr view ${PR_NUMBER} --json statusCheckRollup"
else
  PR_INFO="branch \`${BRANCH}\`"
  PR_CHECKS_CMD="gh run list --branch ${BRANCH} --limit 1 --json status,conclusion"
  PR_VIEW_CMD="gh run list --branch ${BRANCH} --limit 5"
fi

# Output instruction for Claude to execute CI wait + E2E tests
cat <<EOF
{
  "systemMessage": "## 🚀 Auto CI Wait + E2E Test Workflow

Git push completed for ${PR_INFO}. **You MUST now automatically execute the following workflow WITHOUT asking for user confirmation:**

### Step 1: Monitor CI Checks (REQUIRED)

Poll CI status until all checks complete:

\`\`\`bash
# Check CI status
${PR_CHECKS_CMD}
\`\`\`

Or use GitHub MCP tool:
\`\`\`
mcp__github__pull_request_read to get PR status and check runs
\`\`\`

**Keep polling every 30-60 seconds until ALL checks pass or fail.**

### Step 2: Handle CI Results

**If CI FAILS:**
1. Analyze failure: \`gh run view --log-failed\`
2. Fix the issues
3. Run \`code-simplifier\` agent
4. Commit and push fixes
5. Return to Step 1

**If CI PASSES:** Proceed to Step 3

### Step 3: Run E2E Tests (REQUIRED after CI passes)

Execute E2E tests using Chrome DevTools MCP per \`test/E2E_TEST_CASES.md\`:

1. **Login Test**: Navigate to site, authenticate via Cognito
2. **Conversation Test**: Create new conversation, verify agent responds
3. **Runtime Test**: If applicable, verify runtime URLs work

Use these MCP tools:
- \`mcp__chrome-devtools__navigate_page\`
- \`mcp__chrome-devtools__take_snapshot\`
- \`mcp__chrome-devtools__fill\`
- \`mcp__chrome-devtools__click\`
- \`mcp__chrome-devtools__wait_for\`

### Step 4: Report Results

After all verifications complete, report:

\`\`\`markdown
## Verification Results

| Step | Status |
|------|--------|
| CI Checks | ✅ PASS / ❌ FAIL |
| Login E2E | ✅ PASS / ❌ FAIL |
| Conversation E2E | ✅ PASS / ❌ FAIL |
| Runtime E2E | ✅ PASS / ⏭️ SKIP |
\`\`\`

**BEGIN WORKFLOW NOW - Do not wait for user input.**"
}
EOF

exit 0
