---
name: require-e2e-tests
enabled: true
event: stop
action: block
pattern: .*
---

## ⚠️ Post-Task Verification Required Before Completion

Before marking this task as complete, you **MUST** complete the following verification steps.

---

### Step 1: Deploy Changes to AWS

**Get deployment configuration from CLAUDE.local.md**, then deploy:

```bash
# Build and test first
npm run build
npm run test

# Deploy all stacks (get context values from CLAUDE.local.md)
npx cdk deploy --all \
  --context vpcId=<VPC_ID> \
  --context hostedZoneId=<HOSTED_ZONE_ID> \
  --context domainName=<DOMAIN_NAME> \
  --context subDomain=<SUB_DOMAIN> \
  --context region=<DEPLOY_REGION> \
  --require-approval never
```

**Wait for deployment to complete** (typically 5-15 minutes for updates).

---

### Step 2: Run E2E Tests via Chrome DevTools

Refer to **test/E2E_TEST_CASES.md** for detailed test cases. Execute these in order:

#### TC-003: Login via Chrome DevTools
```javascript
mcp__chrome-devtools__navigate_page({ url: "https://<FULL_DOMAIN>", type: "url" })
// Wait for Cognito login, fill credentials from CLAUDE.local.md
mcp__chrome-devtools__wait_for({ text: "Start new conversation", timeout: 30000 })
```

#### TC-004: Verify Conversation List Loads
```javascript
mcp__chrome-devtools__take_snapshot({})
mcp__chrome-devtools__list_network_requests({ resourceTypes: ["xhr", "fetch"] })
```
**Expected**: `GET /api/conversations?limit=*` returns 200

#### TC-005: Start New Conversation
```javascript
mcp__chrome-devtools__click({ uid: "<start-conversation-uid>" })
mcp__chrome-devtools__wait_for({ text: "Waiting for task", timeout: 180000 })
```
**Expected**: Agent ready within 3 minutes

#### TC-006: Execute Flask App Prompt (Full E2E)
```javascript
mcp__chrome-devtools__fill({ uid: "<chat-input-uid>", value: "Create a simple Flask todo app and run it on port 5000" })
mcp__chrome-devtools__press_key({ key: "Enter" })
mcp__chrome-devtools__wait_for({ text: "runtime", timeout: 300000 })
```

#### TC-007: Verify Runtime Application Accessible
```javascript
mcp__chrome-devtools__new_page({})
mcp__chrome-devtools__navigate_page({ url: "<runtime-url>", type: "url" })
```
**Expected**: Flask app renders correctly at `https://<port>-<convId>.runtime.<domain>/`

#### TC-008: Verify In-App Routing
- Add a todo item via the app
- Verify internal routes work correctly
- Confirm URL stays on runtime subdomain

---

### Step 3: Handle Failures

**If any test fails:**
1. Identify the root cause from console logs and network requests
2. Return to code to fix the issue
3. Re-deploy (Step 1)
4. Re-run E2E tests (Step 2)
5. Repeat until all tests pass

---

### E2E Test Summary Checklist

| TC# | Test Case | Status |
|-----|-----------|--------|
| TC-003 | Login via Chrome DevTools | ☐ |
| TC-004 | Verify Conversation List | ☐ |
| TC-005 | Start New Conversation | ☐ |
| TC-006 | Execute Flask Prompt | ☐ |
| TC-007 | Verify Runtime Accessible | ☐ |
| TC-008 | Verify In-App Routing | ☐ |

---

### Skip Conditions

You may skip E2E testing ONLY if your changes are:
- Pure documentation updates (README, comments, CLAUDE.md only)
- Local configuration changes (CLAUDE.local.md)
- Non-infrastructure code changes

**CDK infrastructure changes ALWAYS require full E2E testing.**

---

**To complete this task, explicitly state which tests were run and their results.**
