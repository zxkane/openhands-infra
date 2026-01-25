# OpenHands Infrastructure E2E Test Cases

This document defines the end-to-end test cases for validating the OpenHands infrastructure deployment on AWS.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Chrome browser with DevTools MCP server connected
- Node.js 20+ installed
- CDK bootstrapped in deployment regions

## Test Environment Variables

```bash
# Set these before running tests
export DEPLOY_REGION="us-west-2"
export VPC_ID="<vpc-id>"
export HOSTED_ZONE_ID="<hosted-zone-id>"
export DOMAIN_NAME="<domain-name>"
export SUB_DOMAIN="openhands"
export FULL_DOMAIN="${SUB_DOMAIN}.${DOMAIN_NAME}"

# Test user credentials
export TEST_USER_EMAIL="<test-email>"
export TEST_USER_PASSWORD="<test-password>"
```

---

## TC-001: Deploy Infrastructure to AWS

### Description
Deploy all OpenHands CDK stacks to the target AWS region.

### Steps

1. Build TypeScript and run tests
   ```bash
   npm run build
   npm run test
   ```

2. Preview changes (optional)
   ```bash
   npx cdk diff --all \
     --context vpcId=$VPC_ID \
     --context hostedZoneId=$HOSTED_ZONE_ID \
     --context domainName=$DOMAIN_NAME \
     --context subDomain=$SUB_DOMAIN \
     --context region=$DEPLOY_REGION
   ```

3. Deploy all stacks
   ```bash
   npx cdk deploy --all \
     --context vpcId=$VPC_ID \
     --context hostedZoneId=$HOSTED_ZONE_ID \
     --context domainName=$DOMAIN_NAME \
     --context subDomain=$SUB_DOMAIN \
     --context region=$DEPLOY_REGION \
     --require-approval never
   ```

4. Wait for deployment to complete (typically 15-30 minutes for full deployment)

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | All 6 stacks deploy successfully | `cdk deploy` exits with code 0 |
| 2 | No CloudFormation rollbacks | Check AWS Console for stack status |
| 3 | CloudFront distribution is deployed | `aws cloudfront get-distribution --id <dist-id>` shows "Deployed" |
| 4 | ACM certificate is issued | `aws acm describe-certificate` shows status "ISSUED" |
| 5 | Route 53 records created | `dig $FULL_DOMAIN` returns CloudFront IP |
| 6 | Runtime wildcard DNS works | `dig 5000-abc123.runtime.$FULL_DOMAIN` returns CloudFront IP |

### Verification Commands

```bash
# Check CloudFront distribution status
aws cloudfront get-distribution --id <distribution-id> \
  --query 'Distribution.Status' --output text

# Check ACM certificate status (us-east-1 for CloudFront)
aws acm describe-certificate --certificate-arn <cert-arn> \
  --region us-east-1 --query 'Certificate.Status' --output text

# Verify DNS resolution
dig +short $FULL_DOMAIN
dig +short test-runtime.runtime.$FULL_DOMAIN
```

---

## TC-002: Create Test User in Cognito

### Description
Create a test user in Cognito User Pool if it doesn't already exist.

### Steps

1. Get Cognito User Pool ID from stack outputs
   ```bash
   USER_POOL_ID=$(aws cloudformation describe-stacks \
     --stack-name OpenHands-Auth \
     --region us-east-1 \
     --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
     --output text)
   ```

2. Check if user already exists
   ```bash
   aws cognito-idp admin-get-user \
     --user-pool-id $USER_POOL_ID \
     --username $TEST_USER_EMAIL \
     --region us-east-1 2>/dev/null
   ```

3. Create user if not exists
   ```bash
   # Create user with temporary password
   aws cognito-idp admin-create-user \
     --user-pool-id $USER_POOL_ID \
     --username $TEST_USER_EMAIL \
     --user-attributes Name=email,Value=$TEST_USER_EMAIL Name=email_verified,Value=true \
     --temporary-password "TempPass123!" \
     --message-action SUPPRESS \
     --region us-east-1

   # Set permanent password
   aws cognito-idp admin-set-user-password \
     --user-pool-id $USER_POOL_ID \
     --username $TEST_USER_EMAIL \
     --password "$TEST_USER_PASSWORD" \
     --permanent \
     --region us-east-1
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | User exists in Cognito | `admin-get-user` returns user details |
| 2 | User status is CONFIRMED | Status field shows "CONFIRMED" |
| 3 | Email is verified | `email_verified` attribute is "true" |

### Verification Commands

```bash
# Verify user exists and is confirmed
aws cognito-idp admin-get-user \
  --user-pool-id $USER_POOL_ID \
  --username $TEST_USER_EMAIL \
  --region us-east-1 \
  --query '{Status: UserStatus, Email: UserAttributes[?Name==`email`].Value | [0]}'
```

---

## TC-003: Login via Chrome DevTools

### Description
Login to OpenHands application using test credentials via Chrome DevTools MCP.

### Steps

1. Navigate to application URL
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<full-domain>",
     type: "url"
   })
   ```

2. Wait for Cognito login redirect and take snapshot
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Sign in",
     timeout: 15000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

3. Fill in email field (get UID from snapshot)
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<email-field-uid>",
     value: "<test-email>"
   })
   ```

4. Fill in password field
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<password-field-uid>",
     value: "<test-password>"
   })
   ```

5. Click sign-in button
   ```javascript
   mcp__chrome-devtools__click({
     uid: "<signin-button-uid>"
   })
   ```

6. Wait for redirect back to application
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Start new conversation",
     timeout: 30000
   })
   ```

7. Take screenshot to verify successful login
   ```javascript
   mcp__chrome-devtools__take_screenshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Cognito login page loads | Login form fields visible in snapshot |
| 2 | No login errors | No error messages displayed after submit |
| 3 | Redirect to application succeeds | URL changes to `https://<full-domain>/` |
| 4 | Application home page renders | "Start new conversation" text visible |
| 5 | Auth cookie is set | `id_token` cookie present (HttpOnly, Secure) |

### Verification Commands

```javascript
// Verify authentication cookie is set
mcp__chrome-devtools__evaluate_script({
  function: "() => document.cookie.includes('id_token') || 'Cookie check requires HttpOnly bypass'"
})

// Check current URL
mcp__chrome-devtools__evaluate_script({
  function: "() => window.location.href"
})
```

---

## TC-004: Verify Conversation List Loads

### Description
Verify that the conversation list API loads properly without errors.

### Steps

1. After successful login, verify home page
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   ```

2. Check network requests for conversation list
   ```javascript
   mcp__chrome-devtools__list_network_requests({
     resourceTypes: ["xhr", "fetch"]
   })
   ```

3. Check console for errors
   ```javascript
   mcp__chrome-devtools__list_console_messages({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversations API returns 200 | `GET /api/conversations?limit=*` returns 200 |
| 2 | No JavaScript errors | Console has no error-level messages |
| 3 | Home page renders correctly | "Start new conversation" or conversation list visible |
| 4 | Settings API works | `GET /api/settings` returns 200 (or 404 which triggers auto-create) |

### Expected Network Requests

| Method | URL Pattern | Expected Status |
|--------|-------------|-----------------|
| GET | `/api/conversations?limit=*` | 200 |
| GET | `/api/settings` | 200 or 404 |
| GET | `/api/options/models` | 200 |

---

## TC-005: Start New Conversation

### Description
Start a new conversation and verify it becomes ready for chatting within acceptable time.

### Steps

1. Click "Start new conversation" button
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Find and click the button
   mcp__chrome-devtools__click({ uid: "<start-conversation-uid>" })
   ```

2. Wait for conversation page to load
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "What do you want to build?",
     timeout: 30000
   })
   ```

3. Wait for agent to be ready (status: "Waiting for task")
   ```javascript
   // Poll every 15 seconds for up to 3 minutes
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   ```

4. Take snapshot to verify ready state
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   ```

5. Click "Changes" panel button to verify git integration
   ```javascript
   mcp__chrome-devtools__click({ uid: "<changes-button-uid>" })
   mcp__chrome-devtools__take_snapshot({})
   ```

6. Check network requests for git API
   ```javascript
   mcp__chrome-devtools__list_network_requests({
     resourceTypes: ["xhr", "fetch"]
   })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation page loads | URL contains `/conversations/<uuid>` |
| 2 | Chatbox is connected | "What do you want to build?" prompt visible |
| 3 | Agent is ready | "Waiting for task" status within 3 minutes |
| 4 | Changes panel loads | No 500 errors on `/api/conversations/.../git/changes` |
| 5 | Workspace files visible | Changes panel shows workspace files |
| 6 | No console errors | No error-level console messages |

### Timeout Configuration

| Stage | Maximum Wait Time |
|-------|-------------------|
| Conversation page load | 30 seconds |
| Agent ready ("Waiting for task") | 3 minutes |
| Changes panel load | 10 seconds |

---

## TC-006: Execute Flask Todo App Prompt

### Description
Submit a prompt to create and run a simple Flask application.

### Steps

1. Type prompt in chat input
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Create a simple Flask todo app with add/remove/list functionality and run it on port 5000"
   })
   ```

2. Submit the prompt
   ```javascript
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

3. Wait for agent to start processing
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Running",
     timeout: 60000
   })
   ```

4. Monitor agent progress (poll periodically)
   ```javascript
   // Take snapshots every 30 seconds to monitor progress
   mcp__chrome-devtools__take_snapshot({})
   ```

5. Wait for task completion or application URL in chat
   ```javascript
   // Wait for localhost URL to appear (will be rewritten to runtime subdomain)
   mcp__chrome-devtools__wait_for({
     text: "runtime",
     timeout: 300000  // 5 minutes max
   })
   ```

6. Take final snapshot
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   mcp__chrome-devtools__take_screenshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Agent processes prompt | Status changes to "Running" |
| 2 | No agent errors | No error messages in chat |
| 3 | Flask app code created | Agent shows file creation actions |
| 4 | Application URL displayed | Runtime URL appears in chat |
| 5 | URL is rewritten correctly | URL format: `https://<port>-<convId>.runtime.<domain>/` |

### How Arbitrary Port Routing Works

Runtime subdomains support **any port** inside sandbox containers (5000, 3000, 8080, etc.):

**Request Flow**:
```
URL: https://5000-{convId}.runtime.{domain}/
     ↓
Lambda@Edge: Extracts port=5000, convId
     ↓
OpenResty: /runtime/{convId}/{port}/
     ↓
Lua: Find container by conversation_id label
     Get container IP from NetworkSettings.Networks.bridge.IPAddress
     → container_ip = 172.17.0.X
     → Return (container_ip, 5000)
     ↓
nginx: proxy_pass http://172.17.0.X:5000/
     → 200 OK
```

**Key Point**: No Docker port mapping required. EC2 host routes directly to container IP via Docker bridge network.

### Timeout Configuration

| Stage | Maximum Wait Time |
|-------|-------------------|
| Agent starts processing | 60 seconds |
| Task completion | 5 minutes |

---

## TC-007: Verify Runtime Application Accessible

### Description
Verify the created Flask application is accessible via the runtime subdomain URL.

### Steps

1. Find the runtime URL in chat (from TC-006)
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Look for URL pattern: https://<port>-<convId>.runtime.<domain>/
   ```

2. Open runtime URL in new tab
   ```javascript
   mcp__chrome-devtools__new_page({})
   mcp__chrome-devtools__navigate_page({
     url: "<runtime-url>",
     type: "url"
   })
   ```

3. Wait for page to load
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Todo",
     timeout: 30000
   })
   ```

4. Take screenshot of the application
   ```javascript
   mcp__chrome-devtools__take_screenshot({})
   ```

5. Verify security headers
   ```javascript
   mcp__chrome-devtools__list_network_requests({})
   // Check response headers for X-Frame-Options, CSP, etc.
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Runtime URL is accessible | Page loads without SSL errors |
| 2 | Application renders | Flask app content visible |
| 3 | No authentication required | Direct access without Cognito redirect |
| 4 | Security headers present | X-Frame-Options, X-Content-Type-Options in response |
| 5 | SSL certificate valid | No certificate warnings |

### Expected Security Headers

| Header | Expected Value |
|--------|----------------|
| X-Frame-Options | SAMEORIGIN |
| X-Content-Type-Options | nosniff |
| X-XSS-Protection | 1; mode=block |
| Referrer-Policy | strict-origin-when-cross-origin |
| Content-Security-Policy | frame-ancestors 'self'; ... |

---

## TC-008: Verify In-App Routing

### Description
Verify that internal application routes work correctly with runtime subdomain routing.

### Steps

1. From the Flask app page (TC-007), find add todo form
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   ```

2. Add a new todo item
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<todo-input-uid>",
     value: "Test todo item"
   })
   mcp__chrome-devtools__click({ uid: "<add-button-uid>" })
   ```

3. Verify the todo was added (page should stay on same domain)
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Test todo item",
     timeout: 10000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

4. Check URL after form submission
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: "() => window.location.href"
   })
   ```

5. Navigate to a different route (if app has multiple pages)
   ```javascript
   // Click internal link or navigate directly
   mcp__chrome-devtools__navigate_page({
     url: "<runtime-url>/todos",
     type: "url"
   })
   ```

6. Verify internal routing works
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Form submission works | Todo item appears after adding |
| 2 | URL stays on runtime subdomain | No redirect to wrong domain |
| 3 | Internal links work | Navigation within app succeeds |
| 4 | App routes resolve correctly | `/add`, `/todos`, etc. work as expected |
| 5 | No path prefix issues | App doesn't see `/runtime/...` prefix |

### Key Verification Points

| Test | Expected Behavior |
|------|-------------------|
| Add todo | POST to `/add` → stays on `<runtime-subdomain>/add` |
| List todos | GET `/todos` → renders at `<runtime-subdomain>/todos` |
| Delete todo | DELETE/POST to `/delete/<id>` → redirects to `<runtime-subdomain>/` |
| Static files | CSS/JS loaded from `<runtime-subdomain>/static/...` |

---

## TC-009: Verify Web App Subdomain Access

### Description
Verify that web applications running in sandbox containers are accessible via runtime subdomain URLs. This test ensures the runtime subdomain routing works correctly and doesn't get incorrectly processed by other URL rewriting rules.

### Prerequisites
- TC-006 completed (Flask app created and running)
- Conversation ID from TC-006

### Steps

1. Get the runtime subdomain URL from TC-006
   ```
   Format: https://<port>-<conversationId>.runtime.<subdomain>.<domain>/
   Example: https://5000-7c15e423fbd44f8f8bf483a481daa4d9.runtime.<subdomain>.<domain>/
   ```

2. Navigate directly to the runtime subdomain URL
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://5000-<convId>.runtime.<subdomain>.<domain>/",
     type: "url"
   })
   ```

3. Wait for page to load
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Hello World",
     timeout: 30000
   })
   ```

4. Take snapshot to verify content
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   ```

5. Verify URL is not being incorrectly rewritten by checking console logs
   ```javascript
   mcp__chrome-devtools__list_console_messages({
     types: ["log"]
   })
   ```

6. Test internal routes (if app has them)
   ```javascript
   // Navigate to an internal route
   mcp__chrome-devtools__navigate_page({
     url: "https://5000-<convId>.runtime.<subdomain>.<domain>/api/health",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Runtime subdomain URL is accessible | Page loads without errors |
| 2 | SSL certificate is valid | No certificate warnings for wildcard `*.runtime.<subdomain>.<domain>` |
| 3 | App content renders correctly | "Hello World" or expected content visible |
| 4 | URL is NOT double-processed | No console logs showing runtime URLs being rewritten again |
| 5 | Internal routes work | `/api/*`, `/static/*` routes resolve correctly |
| 6 | Cookies are isolated | Cookies set only for runtime subdomain |

### Console Log Verification

Check that runtime subdomain URLs are NOT being matched by `mainDomainPortPattern`:

```javascript
// GOOD: No console logs for runtime subdomain URLs being rewritten
// BAD: Logs like "Text URL rewritten: https://5000-xxx.runtime.domain:443 -> ..."
```

The fix uses a negative lookahead `(?!\d+-[a-f0-9]+\.runtime\.)` to exclude runtime subdomains from the VS Code URL rewriter.

### Security Headers Verification

| Header | Expected Value |
|--------|----------------|
| X-Frame-Options | SAMEORIGIN |
| X-Content-Type-Options | nosniff |
| Content-Security-Policy | frame-ancestors 'self' https://<subdomain>.<domain> |
| Set-Cookie | Domain=`5000-<convId>.runtime.<subdomain>.<domain>` (isolated) |

---

## TC-010: Verify VS Code URL Rewriting

### Description
Verify that VS Code editor URLs (main domain with port) are correctly rewritten to runtime subdomain format. This test ensures the VS Code URL rewriting feature works without affecting already-correct runtime subdomain URLs.

### Prerequisites
- TC-005 completed (Conversation created)
- An agent task that triggers VS Code editor (e.g., code editing task)

### Steps

1. Start a new conversation or use existing one
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<convId>",
     type: "url"
   })
   ```

2. Wait for agent to be ready
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   ```

3. Submit a task that may trigger VS Code editor
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Open VS Code editor and create a simple Python file"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

4. Monitor console logs for URL rewriting
   ```javascript
   mcp__chrome-devtools__list_console_messages({
     types: ["log"]
   })
   ```

5. Look for VS Code URL patterns in agent output or browser behavior
   ```
   Original: http://<subdomain>.<domain>:49955/?tkn=xxx&folder=/workspace
   Rewritten: https://49955-<convId>.runtime.<subdomain>.<domain>/?tkn=xxx&folder=/workspace
   ```

6. Verify the rewritten URL works
   ```javascript
   // If VS Code URL is displayed, navigate to it
   mcp__chrome-devtools__navigate_page({
     url: "<rewritten-vscode-url>",
     type: "url"
   })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | VS Code URLs are detected | `mainDomainPortPattern` matches `<domain>:<port>` format |
| 2 | VS Code URLs are rewritten | Console shows "window.open patched (main domain:port):" |
| 3 | Rewritten URL is accessible | VS Code editor loads at runtime subdomain |
| 4 | Runtime subdomains NOT affected | No double-rewriting of `*.runtime.*` URLs |
| 5 | Query parameters preserved | Token (`tkn`), folder, and other params remain intact |

### URL Rewriting Logic

The `mainDomainPortPattern` regex with fix:
```javascript
// Pattern: https?:\/\/(?!\d+-[a-f0-9]+\.runtime\.)([a-z0-9][a-z0-9.-]*\.[a-z]{2,}):(\d+)(\/[^\s<>"')\]]*)?
//
// Matches: http://<subdomain>.<domain>:49955/?tkn=xxx
// Does NOT match: https://5000-abc123.runtime.<subdomain>.<domain>/
```

### Expected Console Logs

**For VS Code URLs:**
```
window.open patched (main domain:port): http://<subdomain>.<domain>:49955/?tkn=xxx -> https://49955-<convId>.runtime.<subdomain>.<domain>/?tkn=xxx
```

**For Runtime Subdomain URLs (should NOT appear):**
```
// These logs should NOT exist for runtime subdomain URLs:
// Text URL rewritten (main domain:port): https://5000-xxx.runtime.domain/...
```

### Test Matrix

| URL Type | Example | Should Be Rewritten | Expected Result |
|----------|---------|---------------------|-----------------|
| VS Code (main domain + port) | `http://<subdomain>.<domain>:49955/` | ✅ Yes | `https://49955-<convId>.runtime.<subdomain>.<domain>/` |
| Runtime subdomain | `https://5000-abc123.runtime.<subdomain>.<domain>/` | ❌ No | Unchanged |
| localhost | `http://localhost:5000/` | ✅ Yes | `https://5000-<convId>.runtime.<subdomain>.<domain>/` |
| External domain with port | `http://example.com:8080/` | ❌ No | Unchanged (not main domain) |

---

## TC-011: Verify Cross-User Access Denied (Runtime Authorization)

### Description
Verify that User B cannot access User A's runtime services. This tests the authorization layer that enforces container ownership.

### Prerequisites
- Two Cognito test users configured:
  - User A: Primary test user (creates the conversation)
  - User B: Secondary test user (attempts unauthorized access)
- TC-006 completed by User A (Flask app running in User A's conversation)

### Test Users

| Role | Email | Password | Purpose |
|------|-------|----------|---------|
| User A (Owner) | `<user-a-email>` | `<user-a-password>` | Creates conversation and runtime |
| User B (Attacker) | `<user-b-email>` | `<user-b-password>` | Attempts unauthorized access |

### Steps

1. **Phase 1: User A creates a conversation with running app**

   1.1. Login as User A
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Login with User A credentials
   ```

   1.2. Create conversation and start Flask app (TC-005 + TC-006)
   ```javascript
   // Follow TC-005 and TC-006 steps
   // Record the conversation ID and runtime URL
   ```

   1.3. Verify runtime is accessible for User A
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://5000-<convId>.runtime.<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__take_screenshot({ filePath: "/tmp/e2e-tc011-user-a-access.png" })
   ```

   1.4. Record runtime URL for Phase 2
   ```
   RUNTIME_URL=https://5000-<convId>.runtime.<subdomain>.<domain>/
   CONV_ID=<conversation-id>
   ```

2. **Phase 2: User B attempts to access User A's runtime**

   2.1. Logout User A
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/_logout",
     type: "url"
   })
   ```

   2.2. Login as User B
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Wait for Cognito login page
   mcp__chrome-devtools__fill({ uid: "<email-uid>", value: "<user-b-email>" })
   mcp__chrome-devtools__fill({ uid: "<password-uid>", value: "<user-b-password>" })
   mcp__chrome-devtools__click({ uid: "<submit-uid>" })
   ```

   2.3. Attempt to access User A's runtime URL
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "<RUNTIME_URL>",  // User A's runtime URL
     type: "url"
   })
   mcp__chrome-devtools__take_screenshot({ filePath: "/tmp/e2e-tc011-user-b-denied.png" })
   ```

   2.4. Verify access is denied (403 Forbidden)
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Should show "Access denied: you do not own this conversation"
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | User A can access own runtime | Page loads with Flask app content (200 OK) |
| 2 | User B cannot access User A's runtime | Returns 403 Forbidden |
| 3 | Error message is clear | Shows "Access denied: you do not own this conversation" |
| 4 | User B's user_id header is injected | Lambda@Edge extracts JWT and injects header |
| 5 | OpenResty verifies ownership | Lua script checks container's user_id label |

### Authorization Flow

```
User B → CloudFront → Lambda@Edge (verify JWT, inject X-Cognito-User-Id: <user-b-id>)
                         ↓
                    ALB → OpenResty
                         ↓
                    Lua: find_container(conv_id) → user_id = <user-a-id>
                         ↓
                    Check: request_user_id (<user-b-id>) != container_user_id (<user-a-id>)
                         ↓
                    Return 403 "Access denied: you do not own this conversation"
```

### Security Note

**Prerequisite for Full Authorization**: OpenHands core must add `user_id` label when creating sandbox containers. Without this label, containers allow access from any authenticated user (backwards compatibility).

To verify the container has the user_id label:
```bash
# SSH to EC2
docker inspect <container-name> | grep -A5 "Labels"
# Should show: "user_id": "<user-a-cognito-sub>"
```

---

## TC-012: Verify Unauthenticated Runtime Access Denied

### Description
Verify that unauthenticated requests to runtime URLs return 401 Unauthorized.

### Prerequisites
- TC-006 completed (Flask app running)
- Runtime URL from TC-006

### Steps

1. Use curl to test unauthenticated access (no cookies)
   ```bash
   # From local machine or EC2
   curl -v "https://5000-<convId>.runtime.<subdomain>.<domain>/"
   ```

2. Verify 401 response
   ```bash
   # Expected output:
   # < HTTP/2 401
   # < content-type: text/plain
   # Authentication required. Please login at the main application first.
   ```

3. Test with Chrome DevTools (in incognito/no cookies)
   ```javascript
   // Open new incognito window or clear cookies first
   mcp__chrome-devtools__navigate_page({
     url: "https://5000-<convId>.runtime.<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   mcp__chrome-devtools__take_screenshot({ filePath: "/tmp/e2e-tc012-unauth.png" })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | No id_token cookie → 401 | curl without cookies returns 401 |
| 2 | Error message is helpful | "Authentication required. Please login at the main application first." |
| 3 | No redirect to Cognito | Lambda@Edge returns 401 directly (not 302) |
| 4 | Response is fast | No backend processing for unauthenticated requests |

### Why 401 Instead of Redirect?

Runtime subdomains (`*.runtime.<subdomain>.<domain>`) are NOT registered as Cognito callback URLs. If we redirected to Cognito login, the OAuth callback would fail with `redirect_mismatch` error. Instead, we return 401 with a helpful message directing users to login at the main application.

### Verification Commands

```bash
# Test unauthenticated access
curl -s -o /dev/null -w "%{http_code}" \
  "https://5000-<convId>.runtime.<subdomain>.<domain>/"
# Expected: 401

# Test with invalid token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Cookie: id_token=invalid-token" \
  "https://5000-<convId>.runtime.<subdomain>.<domain>/"
# Expected: 401 (invalid token)

# Test with expired token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Cookie: id_token=<expired-token>" \
  "https://5000-<convId>.runtime.<subdomain>.<domain>/"
# Expected: 401 (expired token)
```

---

## TC-013: Verify Main Application Access Still Works

### Description
Verify that main application authentication still works correctly after authorization changes. This ensures the authorization layer doesn't break normal user flows.

### Prerequisites
- Valid Cognito test user
- Infrastructure deployed with authorization features

### Steps

1. Navigate to main application
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   ```

2. Verify redirect to Cognito login (if not authenticated)
   ```javascript
   mcp__chrome-devtools__wait_for({ text: "Sign in", timeout: 15000 })
   mcp__chrome-devtools__take_screenshot({ filePath: "/tmp/e2e-tc013-login.png" })
   ```

3. Login with valid credentials
   ```javascript
   // Standard login flow (TC-003)
   ```

4. Verify application loads
   ```javascript
   mcp__chrome-devtools__wait_for({ text: "Start new conversation", timeout: 30000 })
   mcp__chrome-devtools__take_screenshot({ filePath: "/tmp/e2e-tc013-home.png" })
   ```

5. Verify user headers are injected correctly
   ```javascript
   // Create a new conversation to trigger backend calls
   // Check that X-Cognito-User-Id header is present in requests
   mcp__chrome-devtools__list_network_requests({
     resourceTypes: ["xhr", "fetch"]
   })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Main app redirects to Cognito | Unauthenticated access → Cognito login |
| 2 | Login succeeds | After login, redirects back to app |
| 3 | Home page loads | "Start new conversation" visible |
| 4 | API calls succeed | `/api/conversations` returns 200 |
| 5 | User identity preserved | Conversations are user-specific |

---

## TC-014: Verify Archived Conversation Resume After EC2 Replacement

### Description
Verify that an archived (existing) conversation can be re-opened via the UI and continued after the ASG replaces the EC2 instance (e.g., due to deployment, health checks, or manual termination).

### Prerequisites
- Infrastructure deployed with persistent workspaces (EFS mounted at `/data/openhands`)
- Logged in as a valid Cognito user (see TC-003)
- At least one existing conversation with files created in the workspace

### Steps

1. Create a new conversation and write a marker file
   - In the OpenHands UI, start a new conversation (TC-005)
   - Prompt the agent to create a file, e.g.:
     - `Create /workspace/project/persist_check.txt with content: hello-from-before-replace`
     - `List files in /workspace/project and confirm persist_check.txt exists`

2. Record the conversation id (`convId`)
   - Use the URL, runtime URL, or conversation list item id to capture `<convId>` for the next steps

3. Find the current ASG instance and terminate it (forces replacement)
   ```bash
   ASG_NAME=$(aws cloudformation describe-stacks \
     --stack-name OpenHands-Compute \
     --region $DEPLOY_REGION \
     --query 'Stacks[0].Outputs[?OutputKey==`AsgName`].OutputValue' \
     --output text)

   INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
     --auto-scaling-group-names "$ASG_NAME" \
     --region $DEPLOY_REGION \
     --query 'AutoScalingGroups[0].Instances[0].InstanceId' \
     --output text)

   aws autoscaling terminate-instance-in-auto-scaling-group \
     --instance-id "$INSTANCE_ID" \
     --no-should-decrement-desired-capacity \
     --region $DEPLOY_REGION
   ```

4. Wait for the replacement instance to become healthy
   ```bash
   aws autoscaling wait group-in-service \
     --auto-scaling-group-names "$ASG_NAME" \
     --region $DEPLOY_REGION
   ```

5. Navigate to home page and click on the archived conversation
   ```javascript
   // Navigate to home page
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})

   // Find the archived conversation in "Recent Conversations" list and click it
   mcp__chrome-devtools__click({ uid: "<conversation-link-uid>" })
   ```

6. Wait for conversation to load and verify chat history appears
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

7. Send a new prompt to resume the conversation
   ```javascript
   mcp__chrome-devtools__click({ uid: "<chat-input-uid>" })
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Read persist_check.txt and print its content"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

8. Wait for agent response and verify workspace file still exists
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "hello-from-before-replace",  // File content should appear
     timeout: 120000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

9. Optional: Host-level verification (EFS-backed per-sandbox directory)
   ```bash
   # SSH to EC2 and check file directly
   cat /data/openhands/workspace/<convId>/project/persist_check.txt
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation list loads after EC2 replacement | "Recent Conversations" displays previous sessions |
| 2 | Archived conversation clickable in UI | Click navigates to conversation page |
| 3 | Chat history loads without errors | Previous messages visible; URL contains conversation ID |
| 4 | Sandbox auto-resumes | Status shows "Waiting for task" (sandbox is active) |
| 5 | Workspace contents persist | `persist_check.txt` exists with original content |
| 6 | Conversation can continue | New agent actions execute successfully after replacement |

---

## Test Summary Checklist

Use this checklist to track test execution:

| TC# | Test Case | Status | Notes |
|-----|-----------|--------|-------|
| TC-001 | Deploy Infrastructure | [ ] | |
| TC-002 | Create Test User | [ ] | |
| TC-003 | Login via Chrome DevTools | [ ] | |
| TC-004 | Verify Conversation List | [ ] | |
| TC-005 | Start New Conversation | [ ] | |
| TC-006 | Execute Flask Prompt | [ ] | |
| TC-007 | Verify Runtime Accessible | [ ] | |
| TC-008 | Verify In-App Routing | [ ] | |
| TC-009 | Verify Web App Subdomain Access | [ ] | |
| TC-010 | Verify VS Code URL Rewriting | [ ] | |
| TC-011 | Cross-User Access Denied | [ ] | Requires 2 test users |
| TC-012 | Unauthenticated Access Denied | [ ] | Runtime returns 401 |
| TC-013 | Main App Access Works | [ ] | Regression test |
| TC-014 | Resume After EC2 Replacement | [ ] | Conversation + workspace persistence |

## Troubleshooting Guide

### Common Issues

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Certificate not issued | DNS validation pending | Wait up to 30 minutes, check Route 53 CNAME records |
| 502 Bad Gateway | EC2 instance unhealthy | Check ASG, target group health |
| Login redirect loop | Cookie not setting | Check cookie domain, SameSite settings |
| Agent not starting | Container pull failed | Check EC2 logs: `docker logs openhands-app` |
| Runtime URL 503 | Container not running | Verify agent started Flask app |
| In-app routes broken | Path prefix issue | Verify runtime subdomain routing is active |

### Log Locations

```bash
# EC2 instance logs
aws ssm start-session --target <instance-id> --region $DEPLOY_REGION
docker logs openhands-app 2>&1 | tail -100

# Lambda@Edge logs (check multiple regions)
aws logs tail '/aws/lambda/us-east-1.OpenHands-Edge-AuthFunction*' \
  --region $DEPLOY_REGION --since 1h

# CloudWatch application logs
aws logs tail /openhands/application --region $DEPLOY_REGION --follow
```

### Quick Health Check Commands

```bash
# Check EC2 health
aws autoscaling describe-auto-scaling-groups \
  --region $DEPLOY_REGION \
  --query 'AutoScalingGroups[?contains(Tags[?Key==`Project`].Value, `OpenHands`)].Instances[*].[InstanceId,HealthStatus]'

# Check target group health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn> \
  --region $DEPLOY_REGION

# Test runtime subdomain DNS
dig +short 5000-test123abc.runtime.$FULL_DOMAIN
```
