# test/CLAUDE.md - Testing Guide

This document covers unit tests, E2E tests, and post-deployment verification.

## Test Commands

```bash
npm run test        # Run all tests (TypeScript + Python)
npm run test:ts     # TypeScript CDK tests only
npm run test:py     # Python tests only

# Update snapshots after intentional changes
npm run test:ts -- -u
```

## Unit Tests

### TypeScript CDK Tests (`test/stacks.test.ts`)

Tests CDK stack synthesis and snapshots:

```typescript
// Verifies stack synthesizes without errors
// Compares against snapshots in test/__snapshots__/
```

### Python Tests (`docker/test_cognito_user_auth.py`)

Tests CognitoUserAuth class:

```python
# Test header extraction
# Test user ID and email handling
# Test authentication flow
```

## E2E Testing with Chrome DevTools

**Comprehensive test cases are in `test/E2E_TEST_CASES.md`.**

### Prerequisites

1. Chrome DevTools MCP server configured
2. Cognito user created with verified email
3. Infrastructure deployed

### Post-Deployment Verification (MANDATORY)

**⚠️ After ANY infrastructure change, you MUST run E2E tests WITHOUT waiting for user input.**

#### Step 1: Login Test

```javascript
// Navigate to application
mcp__chrome-devtools__navigate_page({ url: "https://{subdomain}.{domain}", type: "url" })
mcp__chrome-devtools__take_snapshot({})

// Fill login form (get UIDs from snapshot)
mcp__chrome-devtools__fill({ uid: "<email-field>", value: "<email>" })
mcp__chrome-devtools__fill({ uid: "<password-field>", value: "<password>" })
mcp__chrome-devtools__click({ uid: "<signin-button>" })

// Wait for redirect
mcp__chrome-devtools__wait_for({ text: "OpenHands", timeout: 10000 })
mcp__chrome-devtools__take_screenshot({})
```

#### Step 2: Conversation Test

```javascript
// Click "Start new conversation"
mcp__chrome-devtools__click({ uid: "<new-conversation-button>" })

// Wait for conversation to be ready
mcp__chrome-devtools__wait_for({ text: "What do you want to build?", timeout: 30000 })

// Send a simple request
mcp__chrome-devtools__fill({ uid: "<chat-input>", value: "What is 2+2?" })
mcp__chrome-devtools__press_key({ key: "Enter" })

// Wait for response
mcp__chrome-devtools__wait_for({ text: "4", timeout: 60000 })
```

#### Step 3: Runtime Test

```javascript
// Ask to create a Flask app
mcp__chrome-devtools__fill({ uid: "<chat-input>", value: "Create a Flask app that returns 'Hello World' on port 5000" })
mcp__chrome-devtools__press_key({ key: "Enter" })

// Wait for runtime URL to appear
mcp__chrome-devtools__wait_for({ text: "runtime", timeout: 120000 })

// Navigate to runtime URL
mcp__chrome-devtools__navigate_page({ url: "https://5000-{convId}.runtime.{subdomain}.{domain}/", type: "url" })
mcp__chrome-devtools__take_snapshot({})
```

### Verification Checklist

| # | Test | Expected Result |
|---|------|-----------------|
| 1 | Login portal | Home page loads without errors |
| 2 | Conversation list | GET /api/conversations returns 200 |
| 3 | New conversation | Status reaches "Waiting for task" |
| 4 | Agent response | Agent responds correctly |
| 5 | Runtime URL | Subdomain accessible |

### Common Test Scenarios

1. **Health Check**: Verify `/api/health` returns 200
2. **Authentication**: Test login, session persistence, logout
3. **CORS**: Verify correct CORS headers
4. **Security Headers**: Check CSP, X-Frame-Options
5. **Error Handling**: Test 401/403/500 responses

### Settings Modal Auto-Close Test

```javascript
// Logout and login fresh
mcp__chrome-devtools__navigate_page({ url: "https://{subdomain}.{domain}/_logout", type: "url" })
// Login again...

// Verify modal auto-closed (no overlay)
// Console should show: "Settings modal removed from DOM"

// Verify settings created
mcp__chrome-devtools__evaluate_script({
  function: "() => fetch('/api/settings').then(r => r.status)"
})
// Should return 200
```

## Quick Verification Commands (SSH)

```bash
# Get EC2 instance ID
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names <asg-name> \
  --region <region> \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text)

# SSH via SSM
aws ssm start-session --target $INSTANCE_ID --region <region>

# Check patches applied
docker logs openhands-app 2>&1 | grep -i patch

# Check database connection
docker logs openhands-app 2>&1 | grep -i "alembic"
# Should show: "Context impl PostgresqlImpl"

# Check API requests
docker logs openhands-app 2>&1 | grep "/api/conversations" | tail -10
```

## E2E Test Report Format

After ALL verification steps pass:

```markdown
## E2E Test Results

| Step | Test | Result |
|------|------|--------|
| 1 | Login portal | ✅ PASS |
| 2 | Conversation list | ✅ PASS |
| 3 | New conversation | ✅ PASS |
| 4 | Agent response | ✅ PASS |
| 5 | Runtime access | ✅ PASS |

All E2E tests passed. Deployment verified.
```

**The task is NOT complete until this report is provided.**
