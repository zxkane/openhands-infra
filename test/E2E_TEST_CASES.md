# OpenHands Infrastructure E2E Test Cases

This document defines the end-to-end test cases for validating the OpenHands infrastructure deployment on AWS.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Chrome browser with DevTools MCP server connected
- Node.js 22+ installed
- CDK bootstrapped in deployment regions

## Important: Browser Tab Cleanup

**After completing ALL E2E tests, navigate the browser away from the application:**

```javascript
mcp__chrome-devtools__navigate_page({ url: "about:blank", type: "url" })
```

**Why?** Open conversation pages send periodic API requests (WebSocket keepalive, status polling) that route through OpenResty to the sandbox orchestrator. Each request updates the sandbox's `last_activity_at` timestamp in DynamoDB, which prevents the idle monitor from stopping the sandbox. Leaving a conversation tab open indefinitely keeps the Fargate sandbox task running and incurring costs.

**Rule:** Always close or navigate away from all conversation tabs after E2E testing is complete.

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
| 1 | All 10 stacks deploy successfully | `cdk deploy` exits with code 0 |
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

5. Verify git Changes API returns 200 (workspace must be a git repo)
   ```javascript
   // Call the git changes endpoint via the runtime proxy
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
       const r = await fetch('/runtime/' + convId + '/8000/api/git/changes/');
       return { status: r.status, ok: r.ok };
     }`
   })
   // Expected: { status: 200, ok: true }
   ```

6. Ask agent to create a file and verify it appears in Changes
   ```javascript
   // Type and submit a prompt to create a file
   mcp__chrome-devtools__evaluate_script({
     function: `() => {
       const el = document.querySelector('[contenteditable], textarea');
       if (el) { el.focus(); document.execCommand('insertText', false, 'Create a file called hello.txt with content "Hello World"'); }
       return 'typed';
     }`
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   // Wait for agent to complete
   mcp__chrome-devtools__wait_for({ text: "Waiting for task", timeout: 60000 })
   ```

7. Verify the file appears in git changes
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
       const r = await fetch('/runtime/' + convId + '/8000/api/git/changes/');
       const data = await r.json();
       return { status: r.status, hasChanges: data.length > 0 };
     }`
   })
   // Expected: { status: 200, hasChanges: true }
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation page loads | URL contains `/conversations/<uuid>` |
| 2 | Chatbox is connected | "What do you want to build?" prompt visible |
| 3 | Agent is ready | "Waiting for task" status within 3 minutes |
| 4 | Git Changes API returns 200 | `GET /runtime/{convId}/8000/api/git/changes/` returns 200 (not 500) |
| 5 | Workspace is a git repo | No "Not a git repository" error |
| 6 | File creation visible in Changes | After agent creates a file, Changes API shows it |
| 7 | No conversation ID in file tree | Changes panel must NOT show conversation ID as a file/directory name |
| 8 | VS Code opens in new tab | VS Code URL resolves to runtime subdomain, workspace files visible |
| 9 | No console errors | No error-level console messages |

### VS Code URL Verification (TC-005 step 5.6)

After the sandbox is ready, verify VS Code URL and open in new tab:

```javascript
// Step 1: Verify VS Code URL API returns localhost:port format
mcp__chrome-devtools__evaluate_script({
  function: `async () => {
    const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
    const r = await fetch('/api/v1/sandboxes?id=' + convId);
    const data = await r.json();
    const vscode = data[0]?.exposed_urls?.find(u => u.name === 'VSCODE');
    return {
      status: r.status,
      url: vscode?.url?.substring(0, 60),
      isLocalhost: vscode?.url?.startsWith('http://localhost:'),
    };
  }`
})
// Expected: { status: 200, url: "http://localhost:8001/?tkn=...", isLocalhost: true }
// If url contains VPC IP (172.31.x.x) → Patch 32 not applied
// If url contains "vscode-" prefix → Patch 32 not applied

// Step 2: Open VS Code in new tab (runtime subdomain)
// patch-fix.js rewrites localhost:{port} → https://{port}-{convId}.runtime.{domain}/
mcp__chrome-devtools__evaluate_script({
  function: `() => {
    const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
    const host = window.location.host.replace(/^\\d+-[a-f0-9]+\\.runtime\\./, '');
    const parts = host.split('.');
    const subdomain = parts[0];
    const domain = parts.slice(1).join('.');
    const runtimeUrl = 'https://8001-' + convId + '.runtime.' + subdomain + '.' + domain + '/';
    return runtimeUrl;
  }`
})
// Use the returned URL to open VS Code in new tab:
mcp__chrome-devtools__new_page({ url: "<runtime-vscode-url>", timeout: 30000 })
mcp__chrome-devtools__wait_for({ text: "workspace", timeout: 30000 })
mcp__chrome-devtools__take_snapshot({})
// Expected: VS Code editor loads, shows /workspace/project files
```

### Workspace Verification (TC-005 step 5.5)

After the sandbox is ready, verify the Changes panel does not contain the conversation ID:

```javascript
mcp__chrome-devtools__evaluate_script({
  function: `async () => {
    await new Promise(r => setTimeout(r, 5000));
    const main = document.querySelector('main');
    const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
    const text = main ? main.textContent : '';
    return { hasConvIdFile: text.includes(convId), convId };
  }`
})
// Expected: { hasConvIdFile: false, convId: "<uuid>" }
```

### Timeout Configuration

| Stage | Maximum Wait Time |
|-------|-------------------|
| Conversation page load | 30 seconds |
| Agent ready ("Waiting for task") | 3 minutes |
| Changes API response | 10 seconds |
| Agent file creation | 60 seconds |

---

## TC-005a: Load Existing Conversation and Verify History

### Description
Navigate to an existing conversation (created in TC-005) and verify that chat history messages are displayed. This catches issues with stale sandbox records, event storage, and conversation resume flow.

### Prerequisites
- TC-005 completed (at least one conversation with messages exists)

### Steps

1. Navigate to the home page and identify an existing conversation
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain>/", type: "url" })
   mcp__chrome-devtools__take_snapshot({})
   // Find a conversation link in "Recent Conversations" section
   ```

2. Click on the existing conversation
   ```javascript
   mcp__chrome-devtools__click({ uid: "<conversation-link-uid>" })
   ```

3. Wait for conversation page to load and verify history
   ```javascript
   // Wait for the page to show the conversation
   mcp__chrome-devtools__wait_for({
     text: "<expected-message-text>",  // e.g., text from the original prompt or agent response
     timeout: 30000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

4. Verify the conversations API responds within acceptable time
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const start = performance.now();
       const res = await fetch('/api/conversations?limit=10');
       const elapsed = Math.round(performance.now() - start);
       return { status: res.status, elapsed_ms: elapsed };
     }`
   })
   // Expected: status 200, elapsed_ms < 5000
   ```

5. Verify the events API returns conversation history
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const convId = window.location.pathname.match(/conversations\\/([a-f0-9]+)/)?.[1];
       const res = await fetch('/api/v1/conversation/' + convId + '/events/search?limit=100');
       const data = await res.json();
       return { status: res.status, eventCount: Array.isArray(data) ? data.length : data.events?.length ?? 0 };
     }`
   })
   // Expected: status 200, eventCount > 0
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation page loads | URL contains `/conversations/<uuid>` |
| 2 | Chat history visible | Previous user messages and agent responses displayed |
| 3 | Conversations API fast | `GET /api/conversations?limit=10` returns 200 in < 5s |
| 4 | Events API returns history | `GET /api/v1/conversation/{id}/events/search` returns events |
| 5 | No console errors | No error-level console messages related to sandbox/orchestrator |

### Timeout Configuration

| Stage | Maximum Wait Time |
|-------|-------------------|
| Conversation page load | 30 seconds |
| Conversations API response | 5 seconds |
| Events API response | 10 seconds |

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

**Key Point**: In the ECS Fargate architecture, runtime requests are routed via CloudFront → Lambda@Edge → ALB → sandbox Fargate task (discovered via Cloud Map service discovery).

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
   Original: http://<subdomain>.<domain>:49955/?tkn=xxx&folder=/workspace/project
   Rewritten: https://49955-<convId>.runtime.<subdomain>.<domain>/?tkn=xxx&folder=/workspace/project
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

To verify the sandbox task has the user_id label, check CloudWatch application logs:
```bash
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "user_id.*label\|sandbox.*user"
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
   # From local machine
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

## TC-014: Verify Conversation Resume After Sandbox Stop

### Description
Verify that a conversation can be fully resumed after its sandbox Fargate task is stopped (by idle timeout, manual stop, or ECS task failure). The resumed conversation must accept new messages, retain workspace files on EFS, and the LLM must know the previous conversation history.

**Note**: At the app layer, both STOPPED and PAUSED sandbox states map to `SandboxStatus.MISSING`. The app is stateless — all sandbox state is in DynamoDB (orchestrator registry), workspace files on EFS, and conversation metadata in PostgreSQL. Stopping the sandbox task is sufficient to test the full resume path.

### Prerequisites
- Infrastructure deployed with sandbox orchestrator and EFS
- Logged in as a valid Cognito user (see TC-003)

### Steps

1. Create a new conversation and write a marker file
   ```javascript
   // Create new conversation (TC-005)
   // Send prompt:
   mcp__chrome-devtools__fill({ uid: "<chat-input>", value: "Create /workspace/project/persist_check.txt with content: hello-from-before-replace" })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   // Wait for agent to complete
   mcp__chrome-devtools__wait_for({ text: "Waiting for task", timeout: 120000 })
   ```

2. Record the conversation ID and verify sandbox is RUNNING
   ```bash
   CONV_ID="<conversation-id-from-url>"
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.{status:status.S,task_arn:task_arn.S}'
   # Expected: status=RUNNING
   ```

3. Stop the sandbox Fargate task (simulating idle timeout)
   ```bash
   TASK_ARN=$(aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.task_arn.S' --output text)

   aws ecs stop-task \
     --cluster <cluster> \
     --task "$TASK_ARN" \
     --reason "E2E test: TC-014 sandbox stop for resume" \
     --region $DEPLOY_REGION
   ```

4. Wait for DynamoDB status to become STOPPED
   ```bash
   for i in $(seq 1 12); do
     STATUS=$(aws dynamodb get-item \
       --table-name <registry-table> \
       --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
       --region $DEPLOY_REGION \
       --query 'Item.status.S' --output text)
     echo "Attempt $i: status=$STATUS"
     [ "$STATUS" = "STOPPED" ] && break
     sleep 5
   done
   # Expected: status=STOPPED
   ```

5. Navigate to the conversation (full page load to trigger resume)
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<conv-id>",
     type: "url"
   })
   ```

6. Wait for sandbox to auto-resume and conversation to become ready
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 240000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

7. Send a new prompt and verify workspace file persisted
   ```javascript
   mcp__chrome-devtools__click({ uid: "<chat-input-uid>" })
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Read persist_check.txt and print its content"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({
     text: "hello-from-before-replace",
     timeout: 120000
   })
   ```

8. Verify agent retains previous conversation context
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "What file did I ask you to create earlier in this conversation?"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({
     text: "persist_check",  // Agent should reference the previously created file
     timeout: 120000
   })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation visible after sandbox stop | Conversation appears in "Recent Conversations" list |
| 2 | Conversation page loads | Chat history visible; URL contains conversation ID |
| 3 | Sandbox auto-resumes | Status transitions to "Waiting for task" |
| 4 | Workspace files persist (EFS) | `persist_check.txt` exists with original content |
| 5 | Agent responds to new message | Agent reads file and prints `hello-from-before-replace` |
| 6 | LLM retains conversation history | Agent knows about previously created file without being told its name |

---

## TC-018: Verify Logout Functionality

### Description
Verify that the Logout button in the OpenHands UI correctly logs the user out by clearing the session cookie and redirecting to the Cognito logout endpoint.

### Prerequisites
- TC-003 completed (logged in)
- User is on the OpenHands home page or any authenticated page

### Steps

1. Verify user is logged in
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__wait_for({
     text: "Start new conversation",
     timeout: 30000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

2. Find and click the Logout button
   ```javascript
   // Look for "Logout" button in the navigation
   mcp__chrome-devtools__click({ uid: "<logout-button-uid>" })
   ```

3. Wait for redirect to Cognito logout page or back to login
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Sign in",
     timeout: 15000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

4. Verify the cookie is cleared by navigating back to the app
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Should redirect to login page since cookie is cleared
   mcp__chrome-devtools__wait_for({
     text: "Sign in",
     timeout: 15000
   })
   ```

5. Verify the logout was complete (cookie inspection)
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: "() => document.cookie.includes('id_token')"
   })
   // Should return false (cookie cleared)
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Logout button visible in UI | "Logout" button present in navigation |
| 2 | Click triggers navigation | Button click navigates to `/_logout` endpoint |
| 3 | Cookie is cleared | `id_token` cookie is removed |
| 4 | Cognito session ends | Redirected through Cognito logout endpoint |
| 5 | Subsequent access requires login | Navigating to app redirects to Cognito login |

### Expected Logout Flow

```
User clicks "Logout" button
    ↓
Frontend patch intercepts click (patch-fix.js)
    ↓
Navigate to /_logout
    ↓
Lambda@Edge clears id_token cookie and redirects to:
  https://{cognito-domain}/logout?client_id={id}&logout_uri=https://{host}/
    ↓
Cognito clears its session and redirects to logout_uri
    ↓
Lambda@Edge sees no cookie, redirects to Cognito login
    ↓
User sees Cognito login page (logout complete)
```

### Technical Details

The OpenHands frontend's native logout button may call `/api/logout` or perform client-side logout, which doesn't work with Cognito authentication. The `patch-fix.js` intercepts the logout button click and redirects to our `/_logout` endpoint which:

1. Clears the `id_token` cookie (sets expired)
2. Redirects to Cognito's `/logout` endpoint
3. Cognito clears its session and redirects back

### Verification via Network Requests

```javascript
// After clicking logout, check network requests
mcp__chrome-devtools__list_network_requests({
  resourceTypes: ["document"]
})
// Should show:
// 1. GET /_logout → 302 redirect to Cognito logout
// 2. GET {cognito-domain}/logout → 302 redirect to app
// 3. GET / → 302 redirect to Cognito login
```

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Logout button doesn't respond | patch-fix.js not applied | Check container logs for patch errors |
| Cookie not cleared | Cookie domain mismatch | Verify cookie domain in Lambda@Edge |
| Redirect loop after logout | logout_uri not in allowed list | Check Cognito app client settings |
| Still logged in after logout | Multiple id_token cookies | Clear all cookies with matching domain |

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
| TC-014 | Resume After ECS Task Recycling | [ ] | Conversation + workspace persistence |
| TC-015 | AWS Docs MCP Server | [ ] | Verify awsdocs shttp server |
| TC-016 | Chrome DevTools MCP Server | [ ] | Verify chrome-devtools stdio server |
| TC-017 | Sandbox AWS Access | [ ] | Verify sandbox can access AWS (S3) and deny IAM |
| TC-018 | Logout Functionality | [ ] | Logout button clears session |
| TC-019 | Secrets Page User Isolation | [x] | User-scoped S3 storage enabled via S3SecretsStore |
| TC-020 | Settings Pages User Isolation | [x] | User-scoped S3 storage enabled via S3SettingsStore |
| TC-022 | Conversation List User Isolation | [ ] | Multi-tenant DB isolation (Patch 27) |
| TC-021 | Secrets Re-injection After ECS Task Recycling | [ ] | Patch 22/23/28/29: secrets re-injected into resumed sandbox |
| TC-025 | Cross-Sandbox Network Isolation | [ ] | Sandbox tasks cannot reach each other (SG hardening) |
| TC-030 | Changes Tab Without GitHub Repo | [ ] | Git changes API returns 200, files listed |
| TC-031 | Changes Tab With GitHub Repo | [ ] | Nested repo: git changes visible for connected repo |

---

## TC-015: Verify AWS Documentation MCP Server

### Description
Verify that the AWS Documentation MCP server (awsdocs) is properly configured and accessible to the AI agent. This server provides access to up-to-date AWS documentation and best practices via the shttp (streamable HTTP) protocol.

### Prerequisites
- Infrastructure deployed with MCP enabled (`AGENT_ENABLE_MCP=true`)
- TC-003 completed (logged in)
- TC-005 completed (new conversation ready with "Waiting for task" status)

### MCP Server Configuration

The awsdocs server is configured in `config/config.toml`:
```toml
[mcp]
shttp_servers = [
    { url = "https://knowledge-mcp.global.api.aws" }
]
```

### Steps

1. Start a new conversation or use existing one
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Click "Start new conversation" if needed
   ```

2. Wait for agent to be ready
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   ```

3. Submit a prompt that triggers AWS documentation lookup
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Use the AWS documentation MCP tools to explain how Lambda function URLs work, including authentication options and CORS configuration"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

4. Wait for agent to start processing
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Running",
     timeout: 60000
   })
   ```

5. Monitor agent progress and look for MCP tool usage
   ```javascript
   // Take snapshots periodically to observe agent behavior
   mcp__chrome-devtools__take_snapshot({})
   ```

6. Wait for agent response with AWS documentation content
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Lambda function URL",  // Key term from AWS docs
     timeout: 300000
   })
   mcp__chrome-devtools__take_screenshot({})
   ```

7. Verify response contains accurate AWS documentation
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Look for AWS-specific terminology:
   // - "function URL"
   // - "IAM authentication" or "AWS_IAM"
   // - "CORS"
   // - URLs like "https://<url-id>.lambda-url.<region>.on.aws"
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Agent acknowledges MCP tools available | Agent mentions using AWS documentation or MCP tools |
| 2 | MCP server connection succeeds | No "MCP connection failed" errors in response |
| 3 | Response contains AWS-specific content | Mentions Lambda function URL features accurately |
| 4 | Response is up-to-date | Contains current AWS documentation (not outdated info) |
| 5 | Agent can search and retrieve docs | Response demonstrates retrieval from AWS docs |

### Expected Agent Behavior

The agent should:
1. Recognize the request requires AWS documentation
2. Use MCP tools to query the AWS documentation server
3. Retrieve relevant documentation about Lambda function URLs
4. Synthesize the information into a coherent response

### Verification via CloudWatch Logs

```bash
# Check MCP configuration loaded
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i mcp

# Check for MCP tool invocations
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "shttp\|aws.*mcp\|knowledge-mcp"
```

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| "MCP not available" | `AGENT_ENABLE_MCP=false` | Verify compute-stack has `AGENT_ENABLE_MCP=true` |
| Connection timeout | Network/DNS issue | Check sandbox can reach `knowledge-mcp.global.api.aws` |
| "No tools found" | MCP config not loaded | Verify `config.toml` has `[mcp]` section |
| Generic response | MCP not used | Agent may answer from training data instead |

---

## TC-016: Verify Chrome DevTools MCP Server

### Description
Verify that the Chrome DevTools MCP server is properly configured and the AI agent can use it for browser automation tasks. This server runs as a stdio-based MCP server inside the sandbox container, which requires Chromium installed in the custom runtime image.

### Prerequisites
- Infrastructure deployed with:
  - MCP enabled (`AGENT_ENABLE_MCP=true`)
  - Custom runtime image with Chromium (`SANDBOX_RUNTIME_CONTAINER_IMAGE` pointing to custom ECR image)
- TC-003 completed (logged in)
- TC-005 completed (new conversation ready with "Waiting for task" status)

### MCP Server Configuration

The chrome-devtools server is configured in `config/config.toml`:
```toml
[mcp]
stdio_servers = [
    { name = "chrome-devtools", command = "npx", args = ["-y", "chrome-devtools-mcp@latest", "--isolated", "--headless", "-e", "/usr/bin/chromium"] }
]
```

### Custom Runtime Image

The custom runtime image (`docker/runtime-custom/Dockerfile`) includes:
- Chromium browser (`/usr/bin/chromium`)
- Required dependencies for headless operation
- Environment variables for browser detection

### Steps

1. Start a new conversation or use existing one
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Click "Start new conversation" if needed
   ```

2. Wait for agent to be ready
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   ```

3. Submit a prompt that triggers Chrome DevTools MCP usage
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Use the chrome-devtools MCP server to navigate to https://example.com and take a screenshot. Save the screenshot to /workspace/example-screenshot.png"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

4. Wait for agent to start processing
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Running",
     timeout: 60000
   })
   ```

5. Monitor agent progress
   ```javascript
   // Take snapshots periodically to observe agent behavior
   mcp__chrome-devtools__take_snapshot({})
   ```

6. Wait for agent to complete the browser task
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "screenshot",  // Agent should mention screenshot
     timeout: 300000
   })
   mcp__chrome-devtools__take_screenshot({})
   ```

7. Verify the screenshot was saved
   ```javascript
   // Ask agent to confirm the file exists
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "List files in /workspace and confirm example-screenshot.png exists"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

8. Wait for file confirmation
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "example-screenshot.png",
     timeout: 60000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Agent acknowledges chrome-devtools MCP | Agent mentions using browser automation or MCP tools |
| 2 | Chromium starts successfully | No "chromium not found" errors |
| 3 | Navigation succeeds | Agent confirms navigating to example.com |
| 4 | Screenshot captured | Agent reports screenshot taken |
| 5 | File saved to workspace | `/workspace/example-screenshot.png` exists |
| 6 | No browser crashes | Agent completes task without errors |

### Expected Agent Behavior

The agent should:
1. Recognize the request requires browser automation
2. Use chrome-devtools MCP tools to launch headless Chromium
3. Navigate to the specified URL
4. Capture a screenshot
5. Save the screenshot to the workspace

### Alternative Test Prompt

If the screenshot test fails, try a simpler test:
```javascript
mcp__chrome-devtools__fill({
  uid: "<chat-input-uid>",
  value: "Use the chrome-devtools MCP to get the page title of https://example.com"
})
```

Expected response should mention "Example Domain" (the title of example.com).

### Verification via CloudWatch Logs

```bash
# Check custom runtime image is being used
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "runtime.*image\|sandbox.*image"

# Check for Chromium-related logs
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "chromium\|chrome\|browser"

# Check MCP stdio server logs
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "chrome-devtools\|stdio.*mcp"
```

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| "chromium not found" | Standard runtime image used | Verify `SANDBOX_RUNTIME_CONTAINER_IMAGE` points to custom ECR image |
| "MCP server failed to start" | npx/npm not available | Check sandbox has Node.js installed |
| Browser crash | Missing dependencies | Verify runtime image has all Chromium deps |
| "No display" error | Missing `--headless` flag | Verify MCP config has `--headless` argument |
| Screenshot empty/corrupt | Rendering issue | Try simpler tasks like `get_page_title` |
| Timeout waiting for browser | Slow container startup | Increase timeout, check container resources |

### Custom Runtime Image Verification

To verify the custom runtime image is correctly built and deployed:

```bash
# Check the deployed runtime image URI via CloudWatch
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep SANDBOX_RUNTIME
```

---

## TC-017: Verify Sandbox AWS Access

### Description
Verify that sandbox containers can access AWS services using scoped IAM credentials when `sandboxAwsAccess=true` is configured. The agent should be able to perform AWS operations (like listing S3 buckets) while sensitive operations (like creating IAM users) are denied.

### Prerequisites
- Infrastructure deployed with `--context sandboxAwsAccess=true`
- TC-003 completed (logged in)
- TC-005 completed (new conversation ready with "Waiting for task" status)
### Configuration Requirements

The following must be configured for sandbox AWS access:

1. **CDK Context**: `sandboxAwsAccess=true`
2. **Sandbox Role**: `OpenHandsSandboxRole` created with allow-all policy + explicit deny
3. **Sandbox Task Role**: ECS Fargate sandbox tasks assume the sandbox IAM role
4. **Environment Variables**:
   - `AWS_DEFAULT_REGION` set on sandbox task definition
   - `SANDBOX_RUNTIME_STARTUP_ENV_VARS` passes AWS config to sandbox containers

### Deployment Command

```bash
npx cdk deploy \
  OpenHands-Network OpenHands-Monitoring OpenHands-Security \
  OpenHands-Database OpenHands-UserConfig OpenHands-Compute OpenHands-Edge \
  --context vpcId=$VPC_ID \
  --context hostedZoneId=$HOSTED_ZONE_ID \
  --context domainName=$DOMAIN_NAME \
  --context subDomain=$SUB_DOMAIN \
  --context region=$DEPLOY_REGION \
  --context sandboxAwsAccess=true \
  --require-approval never
```

### Steps

1. Verify infrastructure is deployed with sandbox AWS access
   ```bash
   # Check sandbox role exists
   aws iam get-role --role-name $(aws iam list-roles \
     --query 'Roles[?contains(RoleName, `SandboxRole`)].RoleName' \
     --output text | head -1) --region $DEPLOY_REGION

   # Check sandbox task definition has the sandbox role
   aws ecs describe-task-definition \
     --task-definition openhands-sandbox \
     --region $DEPLOY_REGION \
     --query 'taskDefinition.taskRoleArn'
   ```

2. Start a new conversation
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Click "Start new conversation"
   ```

3. Wait for agent to be ready
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Waiting for task",
     timeout: 180000
   })
   ```

4. Submit a prompt to list S3 buckets
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Use boto3 to list all S3 buckets in this AWS account and show me the bucket names"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

5. Wait for agent to start processing
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "Running",
     timeout: 60000
   })
   ```

6. Wait for S3 bucket list response
   ```javascript
   // The response should contain bucket names
   mcp__chrome-devtools__wait_for({
     text: "bucket",  // or specific bucket name if known
     timeout: 120000
   })
   mcp__chrome-devtools__take_snapshot({})
   mcp__chrome-devtools__take_screenshot({})
   ```

7. Verify agent successfully listed buckets
   ```javascript
   // Look for AWS S3 bucket names in the response
   // Example: "openhands-monitoring-databucket...", "cdk-hnb659fds-..."
   mcp__chrome-devtools__take_snapshot({})
   ```

8. Test explicit deny by attempting IAM user creation
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Try to create an IAM user named 'test-sandbox-user' using boto3 and report the result"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   ```

9. Verify IAM operation is denied
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "AccessDenied",  // or "denied" or "not authorized"
     timeout: 120000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Sandbox credentials file exists | `/data/openhands/config/sandbox-credentials` present |
| 2 | Credentials are refreshed | systemd timer running every 10 minutes |
| 3 | Agent can list S3 buckets | Agent returns bucket names without errors |
| 4 | Agent cannot create IAM users | Returns AccessDenied error |
| 5 | Credentials have correct region | `AWS_DEFAULT_REGION` set to deployment region |
| 6 | Agent-server has environment vars | `SANDBOX_DOCKER_RUNTIME_KWARGS` includes `environment` |

### Expected Allowed Operations

| Service | Operation | Expected Result |
|---------|-----------|-----------------|
| S3 | ListBuckets | ✅ Allowed |
| S3 | GetObject | ✅ Allowed |
| S3 | PutObject | ✅ Allowed |
| EC2 | DescribeInstances | ✅ Allowed |
| Lambda | ListFunctions | ✅ Allowed |
| Bedrock | InvokeModel | ✅ Allowed |

### Expected Denied Operations (Explicit Deny)

| Service | Operation | Expected Result |
|---------|-----------|-----------------|
| IAM | CreateUser | ❌ AccessDenied |
| IAM | CreateRole | ❌ AccessDenied |
| IAM | CreateAccessKey | ❌ AccessDenied |
| IAM | AttachRolePolicy | ❌ AccessDenied |
| STS | AssumeRole | ❌ AccessDenied |
| Organizations | * | ❌ AccessDenied |
| Billing | * | ❌ AccessDenied |

### Verification via CloudWatch Logs

```bash
# Check sandbox task role configuration
aws ecs describe-task-definition \
  --task-definition openhands-sandbox \
  --region $DEPLOY_REGION \
  --query 'taskDefinition.{taskRole:taskRoleArn,containers:containerDefinitions[*].{name:name,env:environment[?name==`AWS_DEFAULT_REGION`]}}'

# Check application logs for sandbox AWS access
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep -i "sandbox.*credential\|aws.*access"
```

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| "AccessDenied" on S3 | Sandbox role policy issue | Check role policy in IAM console |
| "Region not configured" | `AWS_DEFAULT_REGION` missing | Verify sandbox task definition has region env var |
| Credentials expired | ECS task role issue | Check sandbox task role trust policy |
| Agent can't find AWS CLI | AWS CLI not in runtime image | Verify custom runtime image has `awscli` installed |

### AWS CLI Verification

If the custom runtime image includes AWS CLI, the agent can also use CLI commands:

```javascript
mcp__chrome-devtools__fill({
  uid: "<chat-input-uid>",
  value: "Run 'aws s3 ls' command and show me the output"
})
```

Expected: List of S3 buckets from the AWS CLI.

---

## TC-019: Verify User Secrets Page Isolation

### Description
Verify that the /settings/secrets page correctly displays only the current user's secrets and does not show secrets from other users. This test ensures user data isolation for the secrets management feature.

### Prerequisites
- Infrastructure deployed with user-config API
- Two Cognito test users configured:
  - User A: Primary test user
  - User B: Secondary test user with different secrets
- TC-003 completed (login process verified)

### Test Users

| Role | Email | Password | Purpose |
|------|-------|----------|---------|
| User A | `e2e+userA-<timestamp>@<domain>` | `E2EPass@123456` | Creates secrets, verifies isolation |
| User B | `e2e+userB-<timestamp>@<domain>` | `E2EPass@123456` | Creates different secrets |

### Steps

1. **Phase 1: Create User A and add secrets**

   1.1. Create test user A
   ```bash
   E2E_USER_A="e2e+userA-$(date +%Y%m%d-%H%M%S)@<domain>"
   E2E_PASS="E2EPass@123456"

   aws cognito-idp admin-create-user \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_A" \
     --user-attributes Name=email,Value="$E2E_USER_A" Name=email_verified,Value=true \
     --temporary-password "$E2E_PASS" \
     --message-action SUPPRESS \
     --region us-east-1

   aws cognito-idp admin-set-user-password \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_A" \
     --password "$E2E_PASS" \
     --permanent \
     --region us-east-1
   ```

   1.2. Login as User A
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/_logout",
     type: "url"
   })
   // Wait for redirect to login
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Login with User A credentials
   mcp__chrome-devtools__fill({ uid: "<email-field>", value: "<user-a-email>" })
   mcp__chrome-devtools__fill({ uid: "<password-field>", value: "<user-a-password>" })
   mcp__chrome-devtools__click({ uid: "<signin-button>" })
   ```

   1.3. Navigate to Secrets page
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/secrets",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   1.4. Verify page loads with empty secrets (new user)
   ```javascript
   // Should show "Secrets" heading with no existing secrets
   // or "Add a new secret" button
   mcp__chrome-devtools__take_snapshot({})
   ```

   1.5. Add a secret for User A
   ```javascript
   mcp__chrome-devtools__click({ uid: "<add-secret-button>" })
   mcp__chrome-devtools__fill({ uid: "<secret-name-field>", value: "USER_A_SECRET" })
   mcp__chrome-devtools__fill({ uid: "<secret-description-field>", value: "User A test secret" })
   mcp__chrome-devtools__fill({ uid: "<secret-value-field>", value: "user-a-secret-value" })
   mcp__chrome-devtools__click({ uid: "<save-button>" })
   ```

   1.6. Verify secret is displayed
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "USER_A_SECRET",
     timeout: 10000
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

2. **Phase 2: Create User B and verify isolation**

   2.1. Create test user B
   ```bash
   E2E_USER_B="e2e+userB-$(date +%Y%m%d-%H%M%S)@<domain>"

   aws cognito-idp admin-create-user \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_B" \
     --user-attributes Name=email,Value="$E2E_USER_B" Name=email_verified,Value=true \
     --temporary-password "$E2E_PASS" \
     --message-action SUPPRESS \
     --region us-east-1

   aws cognito-idp admin-set-user-password \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_B" \
     --password "$E2E_PASS" \
     --permanent \
     --region us-east-1
   ```

   2.2. Logout User A and login as User B
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/_logout",
     type: "url"
   })
   // Wait for redirect to login
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   // Login with User B credentials
   mcp__chrome-devtools__fill({ uid: "<email-field>", value: "<user-b-email>" })
   mcp__chrome-devtools__fill({ uid: "<password-field>", value: "<user-b-password>" })
   mcp__chrome-devtools__click({ uid: "<signin-button>" })
   ```

   2.3. Navigate to Secrets page as User B
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/secrets",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   2.4. Verify User A's secret is NOT visible
   ```javascript
   // The page should NOT show "USER_A_SECRET"
   // Should show empty secrets list for new user
   mcp__chrome-devtools__take_snapshot({})
   ```

   2.5. Add a different secret for User B
   ```javascript
   mcp__chrome-devtools__click({ uid: "<add-secret-button>" })
   mcp__chrome-devtools__fill({ uid: "<secret-name-field>", value: "USER_B_SECRET" })
   mcp__chrome-devtools__fill({ uid: "<secret-description-field>", value: "User B test secret" })
   mcp__chrome-devtools__fill({ uid: "<secret-value-field>", value: "user-b-secret-value" })
   mcp__chrome-devtools__click({ uid: "<save-button>" })
   ```

   2.6. Verify only User B's secret is displayed
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "USER_B_SECRET",
     timeout: 10000
   })
   mcp__chrome-devtools__take_snapshot({})
   // Should NOT contain "USER_A_SECRET"
   ```

3. **Phase 3: Verify User A still sees only their secrets**

   3.1. Logout User B and login as User A again
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/_logout",
     type: "url"
   })
   // Login with User A credentials
   ```

   3.2. Navigate to Secrets page
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/secrets",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   3.3. Verify only User A's secret is displayed
   ```javascript
   // Should show "USER_A_SECRET"
   // Should NOT show "USER_B_SECRET"
   mcp__chrome-devtools__take_snapshot({})
   ```

4. **Phase 4: Verify API isolation**

   4.1. Check network request to /api/secrets
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/secrets",
     type: "url"
   })
   mcp__chrome-devtools__list_network_requests({
     resourceTypes: ["xhr", "fetch"]
   })
   // Find GET /api/secrets request
   mcp__chrome-devtools__get_network_request({ reqid: <secrets-request-id> })
   ```

   4.2. Verify response contains only current user's secrets
   ```javascript
   // Response body should contain only USER_A_SECRET (for User A session)
   // NOT USER_B_SECRET
   ```

5. **Phase 5: Cleanup**

   ```bash
   # Delete test users
   aws cognito-idp admin-delete-user \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_A" \
     --region us-east-1

   aws cognito-idp admin-delete-user \
     --user-pool-id <user-pool-id> \
     --username "$E2E_USER_B" \
     --region us-east-1
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Secrets page loads | /settings/secrets renders without errors |
| 2 | New user sees empty secrets | Fresh user has no secrets |
| 3 | User can add secret | Secret creation succeeds |
| 4 | Secret is displayed | User's own secret visible in list |
| 5 | User isolation works | User A cannot see User B's secrets |
| 6 | API isolation works | GET /api/secrets returns only current user's data |
| 7 | Secret values never exposed | Only names/descriptions shown, not values |
| 8 | Logout clears session | After logout, secrets page requires re-auth |

### Security Verification

| Check | Expected |
|-------|----------|
| JWT token in cookie | User ID from token matches secrets returned |
| X-Cognito-User-Id header | Injected by Lambda@Edge, used for data scoping |
| No cross-user leakage | User B's request never returns User A's data |
| Secret values hidden | API returns metadata only, not actual secret values |

### Network Request Verification

| Request | Expected Response |
|---------|-------------------|
| `GET /api/secrets` | `{"custom_secrets": [{"name": "...", "description": "..."}]}` |
| Response body | Must NOT contain secrets from other users |
| Response headers | `X-Cognito-User-Id` matches current user |

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Seeing other user's secrets | Old cookie with different user ID | Clear cookies, re-login |
| Secrets persist after logout | Cookie not properly cleared | Navigate to /_logout endpoint |
| Empty secrets for existing user | User ID mismatch | Verify JWT contains correct `sub` claim |
| API returns 401 | Session expired | Re-authenticate |
| API returns 403 | User ID spoofing detected | Lambda@Edge blocks spoofed headers |

---

## TC-020: Verify Settings Pages User Isolation (MCP, Integrations, Secrets)

### Description
Verify that all settings pages (/settings/mcp, /settings/integrations, /settings/secrets) correctly isolate user data and do not leak configurations between users.

### Prerequisites
- Infrastructure deployed with user-config API
- Two Cognito test users
- TC-003 completed (login process verified)

### Steps

1. **Verify MCP Settings Isolation**

   1.1. Login as User A, navigate to MCP settings
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/mcp",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   1.2. Add a custom MCP server for User A
   ```javascript
   // Click "Add MCP Server" button
   // Fill in custom server URL
   // Save
   ```

   1.3. Logout and login as User B
   ```javascript
   // Verify User B does NOT see User A's custom MCP server
   ```

2. **Verify Integrations Settings Isolation**

   2.1. Login as User A, navigate to Integrations
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/integrations",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   2.2. Configure GitHub integration for User A
   ```javascript
   // Enable GitHub integration
   // Add token reference
   ```

   2.3. Verify User B doesn't see User A's integrations
   ```javascript
   // Logout User A, login User B
   // Navigate to integrations
   // Should NOT show User A's GitHub integration
   ```

3. **Verify Application Settings Isolation**

   3.1. Login as User A, navigate to Application settings
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/app",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   3.2. Change LLM settings for User A
   3.3. Verify User B has independent settings

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | MCP settings isolated | Users have independent MCP configurations |
| 2 | Integrations isolated | Users have independent integration configs |
| 3 | Application settings isolated | Users have independent app preferences |
| 4 | Secrets isolated | Verified in TC-019 |
| 5 | No cross-user data leakage | All settings pages scoped to current user |

### API Endpoints to Verify

| Endpoint | Isolation Check |
|----------|-----------------|
| `GET /api/settings` | Returns only current user's settings |
| `GET /api/secrets` | Returns only current user's secrets |
| `GET /api/v1/user-config/mcp` | Returns only current user's MCP config |
| `GET /api/v1/user-config/integrations` | Returns only current user's integrations |

---

## TC-022: Verify Conversation List User Isolation (Database)

### Description
Verify that the conversation list is scoped per-user via the CognitoSQLAppConversationInfoService (Patch 27). User A should only see their own conversations and User B should not see User A's conversations.

### Prerequisites
- Infrastructure deployed with Patch 27 (CognitoSQLAppConversationInfoServiceInjector)
- Two Cognito test users
- TC-003 completed (login process verified)

### Steps

1. **Phase 1: User A creates a conversation**

   1.1. Login as User A (TC-003)

   1.2. Start a new conversation (TC-005)

   1.3. Send a prompt to create conversation history
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "What is 2+2?"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({
     text: "4",
     timeout: 120000
   })
   ```

   1.4. Note the conversation ID from the URL

   1.5. Navigate to home page and verify conversation visible in list
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   // Should show User A's conversation in "Recent Conversations"
   ```

2. **Phase 2: User B sees only their own conversations**

   2.1. Logout User A
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/_logout",
     type: "url"
   })
   ```

   2.2. Login as User B

   2.3. Navigate to home page
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__take_snapshot({})
   ```

   2.4. Verify User A's conversation is NOT visible
   ```javascript
   // The conversation list should NOT contain User A's conversation
   // For a new user, should show empty or "Start new conversation" only
   ```

   2.5. Start a new conversation as User B and verify it appears
   ```javascript
   // Create conversation as User B
   // Navigate home and verify it appears in their list
   ```

3. **Phase 3: Verify User A still sees only their conversations**

   3.1. Logout User B, login as User A

   3.2. Verify User A's conversation is visible, User B's is NOT

4. **Phase 4: Database verification**

   ```bash
   # ECS exec into app container to check database
   CLUSTER_NAME="<cluster-name>"
   TASK_ARN=$(aws ecs list-tasks --cluster "$CLUSTER_NAME" \
     --service-name openhands-app --region $DEPLOY_REGION \
     --query 'taskArns[0]' --output text)

   aws ecs execute-command --cluster "$CLUSTER_NAME" --task "$TASK_ARN" \
     --container openhands-app --interactive --region $DEPLOY_REGION \
     --command "python3 -c \"
   import asyncio, os
   from sqlalchemy.ext.asyncio import create_async_engine
   from sqlalchemy import text
   url = os.environ['DATABASE_URL'].replace('postgresql://', 'postgresql+asyncpg://')
   async def check():
       engine = create_async_engine(url, connect_args={'ssl': 'require'})
       async with engine.begin() as conn:
           result = await conn.execute(text('SELECT conversation_id, user_id FROM conversation_metadata WHERE user_id IS NOT NULL LIMIT 5'))
           for row in result:
               print(f'  conv={row[0][:8]}... user_id={row[1]}')
       await engine.dispose()
   asyncio.run(check())
   \""
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | User A sees own conversation | Conversation visible in list after creation |
| 2 | User B cannot see User A's conversation | User B's home page does not show User A's conversations |
| 3 | User B sees own conversations | User B's newly created conversation is visible |
| 4 | User A cannot see User B's conversation | User A's home page does not show User B's conversations |
| 5 | Database has user_id | `SELECT user_id FROM conversation_metadata` returns non-null values |
| 6 | Event paths work correctly | Conversations have correct event storage paths |
| 7 | Resume works with user_id | After ECS task recycling, sandbox recreated with correct user_id label |

### API Verification

| Request | Expected |
|---------|----------|
| `GET /api/conversations` (User A) | Only User A's conversations |
| `GET /api/conversations` (User B) | Only User B's conversations |
| `DELETE /api/conversations/{id}` (User B on User A's conv) | 404 or no effect |

### Technical Details

**Implementation**: CognitoSQLAppConversationInfoService (Patch 27) extends SQLAppConversationInfoService to:
1. Add `WHERE user_id = ?` to all SELECT queries via `_secure_select()`
2. Persist `user_id` in `save_app_conversation_info()`
3. Return real `created_by_user_id` in `_to_info()`
4. Scope count and delete operations to user

**Database**: `conversation_metadata` table has a `user_id` VARCHAR column with index, added via idempotent DDL at container startup.

**Rollback**: Revert Dockerfile and apply-patch.sh changes. The `user_id` column is harmless (unused by upstream code).

---

## Troubleshooting Guide

### Common Issues

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Certificate not issued | DNS validation pending | Wait up to 30 minutes, check Route 53 CNAME records |
| 502 Bad Gateway | ECS task unhealthy | Check ECS service events, target group health |
| Login redirect loop | Cookie not setting | Check cookie domain, SameSite settings |
| Agent not starting | Container pull failed | Check CloudWatch logs: `/openhands/application` |
| Runtime URL 503 | Sandbox task not running | Verify agent started Flask app, check sandbox orchestrator |
| In-app routes broken | Path prefix issue | Verify runtime subdomain routing is active |
| Service not starting | No Fargate capacity | Check ECS service events in AWS Console |

### Log Locations

```bash
# Application logs (ECS Fargate → CloudWatch)
aws logs tail /openhands/application --region $DEPLOY_REGION --follow

# Lambda@Edge logs (check multiple regions)
aws logs tail '/aws/lambda/us-east-1.OpenHands-Edge-AuthFunction*' \
  --region $DEPLOY_REGION --since 1h
```

### Quick Health Check Commands

```bash
# Check ECS service health
aws ecs describe-services \
  --cluster <cluster-name> \
  --services openhands-app openhands-openresty \
  --region $DEPLOY_REGION \
  --query 'services[].{name:serviceName,status:status,running:runningCount,desired:desiredCount}'

# Check target group health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn> \
  --region $DEPLOY_REGION

# Test runtime subdomain DNS
dig +short 5000-test123abc.runtime.$FULL_DOMAIN
```

---

## Known Limitations

### OpenHands Core Multi-Tenancy Issue (FIXED)

**Status**: ✅ FIXED - User-scoped data isolation implemented via custom S3 stores

**Previous Issue**: OpenHands stored user data (secrets, settings) in **global files** at the S3 bucket root, not in user-scoped paths.

**Solution Implemented**: Custom `S3SettingsStore` and `S3SecretsStore` classes replace the default `FileSettingsStore` and `FileSecretsStore` to enable user-scoped storage.

**Current Data Isolation**:

| Data Type | Path | Status |
|-----------|------|--------|
| Secrets | `users/{user_id}/secrets.json` | ✅ Scoped |
| Settings | `users/{user_id}/settings.json` | ✅ Scoped |
| Conversations | `users/{user_id}/conversations/` | ✅ Scoped |

**Implementation Details**:
- `docker/s3_settings_store.py` - User-scoped settings store
- `docker/s3_secrets_store.py` - User-scoped secrets store
- Dockerfile patches `server_config.py` to use custom stores
- `apply-patch.sh` verifies multi-tenant isolation at startup (critical security check)

**Technical Verification**:
```bash
# Check S3 for user-scoped files
aws s3 ls s3://<bucket>/users/ --recursive | grep -E "(settings|secrets)\.json"
# Expected: users/{user_id}/settings.json, users/{user_id}/secrets.json

# Check CloudWatch logs for isolation verification
aws logs tail /openhands/application --since 30m --region $DEPLOY_REGION \
  --format short | grep "Patch 21"
# Expected: "Patch 21: Multi-tenant isolation ENABLED"
```

**E2E Test Expectations (TC-019)**:

| # | Test Step | Expected Result |
|---|-----------|-----------------|
| 1 | User A creates secret | Stored at `users/{user_a_id}/secrets.json` |
| 2 | User A sees own secret | USER_A_SECRET displayed |
| 3 | User B logs in | Different user_id session |
| 4 | User B sees empty secrets | No USER_A_SECRET visible |
| 5 | User B creates secret | Stored at `users/{user_b_id}/secrets.json` |
| 6 | User A re-login | Only sees USER_A_SECRET |

**Residual Risks**:
1. If Dockerfile build fails, fallback to `FileSettingsStore`/`FileSecretsStore` could expose global storage
2. `apply-patch.sh` Patch 21 is marked as CRITICAL and will block startup if stores not configured properly

---

## TC-021: Verify Secrets Re-injection After ECS Task Recycling

### Description
Verify that user secrets are re-injected and usable in resumed conversations after ECS Fargate app task recycling. This tests the full secret lifecycle across sandbox recreation:

- **Patch 22**: Injects `OH_SECRET_KEY` into sandbox for secret decryption
- **Patch 23/25/26**: Skip masked secrets during resume (prevents crash)
- **Patch 28**: Fix `event_callback_result.id` NULL (enables webhook callbacks)
- **Patch 29**: Re-inject fresh secrets into sandbox via `/api/conversations/{id}/secrets`

### Prerequisites
- Infrastructure deployed with persistent storage (EFS) and user config enabled
- TC-003 completed (logged in)

### Test Flow

```
Phase 1: Create secret → Start conversation → Verify secret accessible
     ↓
Phase 2: Stop ECS app task → Wait for replacement task → Verify healthy
     ↓
Phase 3: Navigate to conversation → Sandbox resumes → Verify secret re-injected
     ↓
Phase 4: Verify via CloudWatch logs (Patches 22/23/28/29 applied)
```

### Steps

1. **Phase 1: Create secret and verify in conversation**

   1.1. Navigate to Secrets page and create a test secret
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/settings/secrets",
     type: "url"
   })
   mcp__chrome-devtools__wait_for({ text: "Secrets", timeout: 15000 })
   mcp__chrome-devtools__take_snapshot({})

   // Add secret: name=TEST_E2E_SECRET, value=e2e-secret-12345
   mcp__chrome-devtools__click({ uid: "<add-secret-button>" })
   mcp__chrome-devtools__fill({ uid: "<secret-name-field>", value: "TEST_E2E_SECRET" })
   mcp__chrome-devtools__fill({ uid: "<secret-value-field>", value: "e2e-secret-12345" })
   mcp__chrome-devtools__click({ uid: "<save-button>" })
   mcp__chrome-devtools__wait_for({ text: "TEST_E2E_SECRET", timeout: 10000 })
   ```

   1.2. Start a new conversation and verify secret access
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain>/", type: "url" })
   mcp__chrome-devtools__click({ uid: "<start-conversation-button>" })
   mcp__chrome-devtools__wait_for({ text: "Waiting for task", timeout: 180000 })

   // Ask agent to read the secret
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Read the TEST_E2E_SECRET secret and print its first 5 characters"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({
     text: "e2e-s",  // First 5 chars of "e2e-secret-12345"
     timeout: 120000
   })
   ```

   1.3. Record conversation ID from URL (`/conversations/<uuid>`)

2. **Phase 2: Stop ECS app task and wait for replacement**

   ```bash
   CLUSTER_NAME="<cluster-name>"  # e.g., openhands-test-kane-mx
   DEPLOY_REGION="<region>"

   # Find the running app task
   TASK_ARN=$(aws ecs list-tasks \
     --cluster "$CLUSTER_NAME" \
     --service-name openhands-app \
     --region $DEPLOY_REGION \
     --query 'taskArns[0]' --output text)

   echo "Stopping task: $TASK_ARN"
   aws ecs stop-task \
     --cluster "$CLUSTER_NAME" \
     --task "$TASK_ARN" \
     --reason "E2E test: TC-021 task recycling for secrets re-injection" \
     --region $DEPLOY_REGION

   # Wait for replacement task to become healthy
   aws ecs wait services-stable \
     --cluster "$CLUSTER_NAME" \
     --services openhands-app \
     --region $DEPLOY_REGION

   # Verify new task is running
   NEW_TASK_ARN=$(aws ecs list-tasks \
     --cluster "$CLUSTER_NAME" \
     --service-name openhands-app \
     --region $DEPLOY_REGION \
     --query 'taskArns[0]' --output text)
   echo "New task: $NEW_TASK_ARN (was: $TASK_ARN)"
   ```

3. **Phase 3: Resume conversation and verify secret re-injection**

   3.1. Navigate to the archived conversation
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<conversation-id>",
     type: "url"
   })
   ```

   3.2. Wait for sandbox resume (Patch 23 skips masked secrets, Patch 29 re-injects fresh ones)
   ```javascript
   mcp__chrome-devtools__wait_for({ text: "Waiting for task", timeout: 180000 })
   ```

   3.3. Verify chat history loaded
   ```javascript
   mcp__chrome-devtools__wait_for({ text: "TEST_E2E_SECRET", timeout: 30000 })
   ```

   3.4. Ask agent to read the secret again — this verifies Patch 29 re-injected it
   ```javascript
   mcp__chrome-devtools__fill({
     uid: "<chat-input-uid>",
     value: "Read the TEST_E2E_SECRET secret again and print its first 5 characters"
   })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({
     text: "e2e-s",  // Must match - proves Patch 29 re-injected the secret
     timeout: 120000
   })
   mcp__chrome-devtools__take_screenshot({})
   ```

4. **Phase 4: Verify patches via CloudWatch logs**

   ```bash
   # Check patch application in CloudWatch logs
   aws logs tail /openhands/application --since 10m --region $DEPLOY_REGION \
     --format short | grep -E "Patch (22|23|28|29)" | head -10
   ```

   Expected output:
   ```
   Patch 22: runtime_startup_env_vars injection applied successfully
   Patch 23: Invalid secrets skip applied successfully
   Patch 28: Added default=uuid4 to StoredEventCallbackResult.id
   Patch 29: Secret re-injection on resume applied successfully
   ```

   Also verify re-injection happened:
   ```bash
   aws logs tail /openhands/application --since 10m --region $DEPLOY_REGION \
     --format short | grep "Patch 29: Re-injected"
   # Expected: "Patch 29: Re-injected N secrets into resumed sandbox <conversation-id>"
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Secret created successfully | Visible on /settings/secrets page |
| 2 | Secret accessible in new conversation | Agent prints "e2e-s" |
| 3 | ECS task recycled successfully | New task ARN differs from original |
| 4 | Conversation resumes without crash | No Pydantic ValidationError in logs |
| 5 | Chat history loads | Previous messages visible |
| 6 | **Secret accessible after resume** | **Agent prints "e2e-s" (Patch 29 re-injection)** |
| 7 | Patches 22/23/28/29 applied | CloudWatch log output matches expected |
| 8 | Re-injection logged | "Patch 29: Re-injected N secrets" in logs |

### Technical Details

**Why secrets break on resume without Patch 29**:

```
New Conversation:                          Resumed Conversation (without Patch 29):
─────────────────                          ──────────────────────────────────────
_setup_secrets_for_git_providers()         base_state.json loaded
  → LookupSecret(url=webhook, jwt=...)       → secrets: {"KEY": "**********"}
  → StaticSecret(value=real_value)         Patch 23/25/26 filter masked values
Secrets passed to StartConversationReq       → secrets: {} (empty!)
Sandbox stores in agent_context            Agent has NO secrets
Agent can read/use secrets                 ❌ "Secret not found"
```

**With Patch 29**:

```
Resumed Conversation (with Patch 29):
──────────────────────────────────────
1. Sandbox recreated (resume endpoint)
2. base_state.json loaded → masked secrets filtered by Patch 23/25/26
3. Resume endpoint fires background task:
   a. Wait for sandbox RUNNING
   b. _setup_secrets_for_git_providers() → fresh LookupSecret/StaticSecret
   c. POST /api/conversations/{id}/secrets → inject into sandbox
4. Agent has fresh secrets ✅
```

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| "ValidationError" on resume | Patch 23 not applied | Check CloudWatch logs for "Patch 23" |
| Secret not found after resume | Patch 29 not applied | Check CloudWatch logs for "Patch 29" |
| "Patch 29: Sandbox not running" | Sandbox slow to start | Increase wait time or retry |
| "Patch 29: Secret injection returned 4xx" | API endpoint changed | Check sandbox OpenAPI schema |
| IntegrityError in webhook logs | Patch 28 not applied | Check `docker logs` for "Patch 28" |

### Cleanup

```bash
# Delete test secret via /settings/secrets page
# Delete test conversation if needed
```

---

## TC-023: Verify Mobile Historical Conversation Messages Display

### Description

Verify that historical conversation messages display correctly on mobile/narrow viewports.
This test covers the upstream bug (All-Hands-AI/OpenHands#12704) where conversation history
skeleton gets stuck on viewports narrower than ~1200px due to WebSocket provider remounting.
The bug is fixed by Patch 8 in `docker/patch-fix.js` (temporary React fiber fix).

### Prerequisites

- A conversation with 10+ messages already exists (create on desktop if needed)
- Chrome DevTools MCP server connected
- Cognito user logged in

### Steps

1. **Create test conversation on desktop** (skip if existing conversation has 10+ messages)

   a. Navigate to the application at desktop viewport
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   ```

   b. Start a new conversation and generate multiple exchanges
   ```javascript
   // Send a prompt, wait for response, repeat 5+ times to build history
   mcp__chrome-devtools__fill({ uid: "<chat-input>", value: "List 5 programming languages and their creators" })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({ text: "Python", timeout: 60000 })
   ```

   c. Note the conversation URL path (e.g., `/conversations/{uuid}`)

2. **Switch to mobile viewport (iPhone 14 Pro Max emulation)**

   ```javascript
   mcp__chrome-devtools__emulate({
     viewport: {
       width: 430,
       height: 932,
       deviceScaleFactor: 3,
       isMobile: true,
       hasTouch: true
     },
     userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
   })
   ```

3. **Navigate to the historical conversation**

   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}/conversations/<conv-uuid>", type: "url" })
   ```

4. **Wait for messages to load** (Patch 8 should activate within 3-5 seconds if skeleton is stuck)

   ```javascript
   // Wait for actual message content - not the skeleton
   mcp__chrome-devtools__wait_for({ text: "Python", timeout: 15000 })
   ```

5. **Take screenshot for verification**

   ```javascript
   mcp__chrome-devtools__take_screenshot({})
   ```

6. **Verify no stuck skeleton**

   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: "() => { var s = document.querySelector('[data-testid=\"chat-messages-skeleton\"]'); return { skeletonVisible: !!s, messageCount: document.querySelectorAll('[data-testid^=\"message-\"]').length }; }"
   })
   ```

7. **Verify Patch 8 log output** (check console for activation)

   ```javascript
   mcp__chrome-devtools__list_console_messages({ types: ["log", "warn"] })
   // Look for "[Patch 8]" messages
   ```

8. **Test at additional narrow widths** (768px tablet, 375px iPhone SE)

   ```javascript
   mcp__chrome-devtools__emulate({
     viewport: { width: 768, height: 1024, deviceScaleFactor: 2, isMobile: true, hasTouch: true }
   })
   mcp__chrome-devtools__navigate_page({ type: "reload" })
   mcp__chrome-devtools__wait_for({ text: "Python", timeout: 15000 })
   ```

9. **Reset to desktop viewport**

   ```javascript
   mcp__chrome-devtools__emulate({ viewport: null, userAgent: null })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Messages visible at 430px width within 5s | `wait_for` succeeds for message content |
| 2 | No stuck skeleton after page load | `evaluate_script` returns `skeletonVisible: false` |
| 3 | Message count matches conversation history | `messageCount > 0` in evaluate_script result |
| 4 | Patch 8 log visible if skeleton was stuck | Console shows `[Patch 8]` messages |
| 5 | Messages visible at 768px width | Reload at tablet width shows messages |
| 6 | Messages visible at 375px width | Reload at narrow phone width shows messages |
| 7 | Desktop viewport still works after reset | Messages display at full width |

### Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| Skeleton stuck > 15s | Patch 8 not injected | Check CloudWatch `/openhands/application` for "Patch 8" |
| Messages load on desktop but not mobile | Upstream bug not patched | Verify `patch-fix.js` includes skeleton fix IIFE |
| "[Patch 8] Could not find React fiber" | React DOM structure changed | Upstream version may have changed component tree |
| "[Patch 8] Max retries reached" | Fiber hook search failing | May need to adjust hook detection logic |
| API returns HTML on mobile | iOS ITP blocking cookies | Check console for "[Auth redirect detected]" |

### Cleanup

```bash
# Reset viewport to desktop in Chrome DevTools
# No infrastructure cleanup needed
```

---

## TC-024: Verify Sandbox Idle Timeout

### Description
Verify that sandbox Fargate tasks are automatically stopped after the configured idle timeout (staging: 10 minutes, production: 30 minutes). This tests the idle monitor Lambda, EventBridge schedule, and task-state Lambda event-driven cleanup.

### Prerequisites
- Infrastructure deployed with sandbox orchestrator
- Idle monitor Lambda deployed and working (check `/aws/lambda/openhands-sandbox-idle-monitor` logs)
- At least one conversation sandbox running

### Steps

1. Start a new conversation and verify sandbox is running
   ```javascript
   // Create new conversation (TC-005)
   // Verify "Waiting for task" status
   ```

2. Record the conversation ID and check DynamoDB status
   ```bash
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key '{"conversation_id":{"S":"<conv-id>"}}' \
     --region $DEPLOY_REGION \
     --query 'Item.{status:status.S,task_arn:task_arn.S,last_activity:last_activity_at.N}'
   # Expected: status=RUNNING
   ```

3. Wait for idle timeout to elapse (staging: 10min, production: 30min)
   - Do NOT interact with the conversation during this period
   - The idle monitor Lambda runs every 5 minutes

4. Verify the sandbox was stopped
   ```bash
   # Check DynamoDB - should be PAUSED (stopped by idle monitor)
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key '{"conversation_id":{"S":"<conv-id>"}}' \
     --region $DEPLOY_REGION \
     --query 'Item.status.S'
   # Expected: PAUSED

   # Check ECS task - should be STOPPED
   aws ecs describe-tasks \
     --cluster <cluster> \
     --tasks <task-arn> \
     --region $DEPLOY_REGION \
     --query 'tasks[0].lastStatus'
   # Expected: STOPPED
   ```

5. Verify idle monitor Lambda logs
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/openhands-sandbox-idle-monitor \
     --start-time $(($(date +%s) - 900))000 \
     --region $DEPLOY_REGION \
     --query 'events[*].message' | grep -i "stopping\|idle"
   ```

6. Verify task-state Lambda processed the stop event
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/openhands-sandbox-task-state \
     --start-time $(($(date +%s) - 900))000 \
     --region $DEPLOY_REGION \
     --query 'events[*].message' | grep "<conv-id>"
   ```

7. Verify conversation still appears in UI conversation list
   ```javascript
   // Navigate to home page
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__take_snapshot({})
   // The PAUSED conversation should still appear in "Recent Conversations"
   // Note: OpenHands app may display PAUSED/STOPPED conversations as "archived" in the UI
   // — this is the app's own label for idle conversations, NOT the infrastructure ARCHIVED state
   ```

8. Verify conversation can be resumed after idle timeout
   ```javascript
   // Click the PAUSED conversation in the conversation list
   // Expected: App loads conversation history from S3 and starts resuming the sandbox
   // The sandbox should start (orchestrator /start succeeds for PAUSED status)
   mcp__chrome-devtools__wait_for({ text: ["Starting", "Connecting", "What do you want to build?"], timeout: 30000 })
   ```

9. Verify sandbox resumes to RUNNING
   ```bash
   # After resume, DynamoDB should show RUNNING again
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key '{"conversation_id":{"S":"<conv-id>"}}' \
     --region $DEPLOY_REGION \
     --query 'Item.status.S'
   # Expected: RUNNING (or STARTING during provisioning)
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Sandbox created and running | DynamoDB status=RUNNING |
| 2 | Idle monitor Lambda functional | No errors in Lambda logs |
| 3 | Sandbox stopped after timeout | DynamoDB status=PAUSED after idle period |
| 4 | ECS task stopped | `lastStatus=STOPPED` in ECS |
| 5 | Task-state Lambda triggered | EventBridge → Lambda → DynamoDB update logged |
| 6 | Configurable timeout | staging=10min, production=30min (via `idleTimeoutMinutes` context) |
| 7 | Conversation visible in UI after idle stop | Appears in conversation list (may show as "archived" label in app UI) |
| 8 | **Conversation resumable after idle stop** | Clicking PAUSED conversation starts sandbox successfully |
| 9 | Sandbox reaches RUNNING after resume | DynamoDB status=RUNNING |

### Configuration

| Environment | Idle Timeout | Override |
|-------------|-------------|----------|
| Staging (`test.*`) | 10 minutes | `--context idleTimeoutMinutes=<N>` |
| Production | 30 minutes | `--context idleTimeoutMinutes=<N>` |

### Important: App UI vs Infrastructure State

The OpenHands app UI may display PAUSED/STOPPED conversations with an "archived" label.
This is the **app's own terminology** for idle conversations — it does NOT mean the infrastructure
`ARCHIVED` state. The distinction:

| State | DynamoDB Status | Resumable? | UI Display |
|-------|----------------|------------|------------|
| Idle-stopped | `PAUSED` or `STOPPED` | Yes | May show "archived" (app label) |
| Truly archived | `ARCHIVED` | **No** (409) | Should show non-resumable state |

---

## TC-025: Verify Cross-Sandbox Network Isolation

### Description
Verify that sandbox Fargate tasks are network-isolated from each other. Sandbox A must not be able to reach Sandbox B on any port (agent-server 8000, user apps 5000, etc.). Only the app service (via `appServiceSg`) should be able to reach sandbox tasks.

This validates the security hardening that removed the self-referencing `sandboxTaskSg` ingress rule, preventing cross-sandbox attacks such as reading other users' code or conversations.

### Prerequisites
- Infrastructure deployed with sandbox orchestrator
- Two Cognito user accounts (or one account creating two conversations)
- `jq` installed for JSON parsing

### Steps

1. Start Conversation A and record its sandbox task IP
   ```javascript
   // Create new conversation via UI (TC-005 flow)
   // Wait for "Waiting for task" status
   ```

   ```bash
   # Get Conversation A's task IP from DynamoDB
   CONV_A="<conversation-id-A>"
   TASK_A_ARN=$(aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_A\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.task_arn.S' --output text)

   TASK_A_IP=$(aws ecs describe-tasks \
     --cluster <cluster> \
     --tasks "$TASK_A_ARN" \
     --region $DEPLOY_REGION \
     --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' --output text)
   echo "Sandbox A IP: $TASK_A_IP"
   ```

2. Start Conversation B and record its sandbox task IP
   ```javascript
   // Create another new conversation via UI
   // Wait for "Waiting for task" status
   ```

   ```bash
   # Get Conversation B's task IP from DynamoDB
   CONV_B="<conversation-id-B>"
   TASK_B_ARN=$(aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_B\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.task_arn.S' --output text)

   TASK_B_IP=$(aws ecs describe-tasks \
     --cluster <cluster> \
     --tasks "$TASK_B_ARN" \
     --region $DEPLOY_REGION \
     --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' --output text)
   echo "Sandbox B IP: $TASK_B_IP"
   ```

3. From Conversation A, attempt to reach Sandbox B's agent-server (port 8000)
   ```javascript
   // In Conversation A's chat, ask the agent:
   // "Run this command: curl -s --connect-timeout 5 http://<Sandbox-B-IP>:8000/alive"
   // Expected: connection timeout or refused (NOT a successful response)
   ```

4. From Conversation A, attempt to reach Sandbox B on other ports
   ```javascript
   // "Run: curl -s --connect-timeout 5 http://<Sandbox-B-IP>:5000/"
   // Expected: connection timeout or refused

   // "Run: curl -s --connect-timeout 5 http://<Sandbox-B-IP>:3000/"
   // Expected: connection timeout or refused
   ```

5. Verify both sandboxes still work normally via app service
   ```javascript
   // In Conversation A, send a normal task: "echo hello"
   // Expected: agent responds successfully

   // In Conversation B, send a normal task: "echo world"
   // Expected: agent responds successfully
   ```

6. Verify security group rules (infrastructure validation)
   ```bash
   SG_ID=$(aws cloudformation describe-stacks \
     --stack-name OpenHands-Sandbox \
     --region $DEPLOY_REGION \
     --query 'Stacks[0].Outputs[?OutputKey==`SandboxTaskSecurityGroupId`].OutputValue' --output text)

   # Verify NO self-referencing rule exists
   aws ec2 describe-security-groups \
     --group-ids "$SG_ID" \
     --region $DEPLOY_REGION \
     --query 'SecurityGroups[0].IpPermissions[?UserIdGroupPairs[?GroupId==`'"$SG_ID"'`]]'
   # Expected: empty array [] — no self-referencing inbound rule
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Sandbox A cannot reach Sandbox B:8000 | `curl` times out or connection refused |
| 2 | Sandbox A cannot reach Sandbox B:5000 | `curl` times out or connection refused |
| 3 | Sandbox A cannot reach Sandbox B:3000 | `curl` times out or connection refused |
| 4 | Both sandboxes work via app service | Normal agent tasks succeed |
| 5 | No self-referencing SG rule | `describe-security-groups` returns empty for self-ref |
| 6 | Internet access still works | Sandbox can `curl https://httpbin.org/ip` |

---

## TC-026: Verify Cross-Sandbox EFS Isolation

### Description
Verify that per-conversation EFS access points prevent sandboxes from accessing each other's workspace data. Each sandbox should only see its own files — attempting to traverse to parent directories must be physically blocked by the EFS access point root boundary.

### Prerequisites
- Infrastructure deployed with per-conversation EFS isolation (access points)
- Two active conversations (can be same or different users)

### Steps

1. **Create conversation A** and write a marker file:
   ```
   Ask the agent: "Create a file at /mnt/efs/project/marker-a.txt with content 'conversation-a-secret'"
   ```

2. **Create conversation B** and attempt to read conversation A's data:
   ```
   Ask the agent: "Run these commands and show me the output:
   ls -la /mnt/efs/
   ls -la /mnt/efs/project/
   cat /mnt/efs/project/marker-a.txt 2>&1 || echo 'NOT FOUND'
   ls -la /mnt/efs/../ 2>&1 || echo 'CANNOT ESCAPE'"
   ```

3. **Verify conversation B's own workspace works**:
   ```
   Ask the agent: "Create a file at /mnt/efs/project/marker-b.txt with content 'conversation-b-data' and then read it back"
   ```

4. **Verify access point cleanup after stop**:
   ```bash
   # Get the EFS file system ID from the deployment
   EFS_ID=$(aws efs describe-file-systems --query 'FileSystems[?Tags[?Key==`Component` && Value==`sandbox-workspace`]].FileSystemId' --output text --region $DEPLOY_REGION)

   # List access points before stop
   aws efs describe-access-points --file-system-id $EFS_ID --region $DEPLOY_REGION \
     --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,State:LifeCycleState}'

   # Stop conversation B (via UI or API)

   # Wait 30 seconds, then verify access point was cleaned up
   sleep 30
   aws efs describe-access-points --file-system-id $EFS_ID --region $DEPLOY_REGION \
     --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,State:LifeCycleState}'
   # Conversation B's access point should be gone
   ```

5. **Verify resume preserves data**:
   ```
   Resume conversation A and ask: "Read /mnt/efs/project/marker-a.txt"
   # Should still contain 'conversation-a-secret'
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Conversation B cannot see conversation A's files | `ls /mnt/efs/` shows only conversation B's own data |
| 2 | Parent directory traversal is blocked | `ls /mnt/efs/../` shows same content as `/mnt/efs/` (access point root) |
| 3 | Both sandboxes work independently | Each can create and read their own files |
| 4 | Access point cleaned up on stop | `describe-access-points` no longer shows stopped conversation's AP |
| 5 | Resume preserves workspace data | Previously created files are accessible after resume |

---

## TC-027: Verify SPA Navigation Starts Sandbox (Regression)

### Description
Verify that navigating to an existing conversation via client-side SPA routing (clicking in home page or left nav bar) properly starts the sandbox in the backend. This is a regression test for the bug where only a hard page refresh would trigger sandbox start — client-side navigation left the sandbox stopped.

### Prerequisites
- TC-003 completed (logged in)
- TC-005 completed (at least one conversation with messages exists)

### Steps

1. Navigate to a conversation via full page load first, to ensure it has a running sandbox
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<conversation-uuid>",
     type: "url"
   })
   mcp__chrome-devtools__wait_for({
     text: "<expected-message-text>",
     timeout: 30000
   })
   ```

2. Navigate to the home page via full page load
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/",
     type: "url"
   })
   mcp__chrome-devtools__wait_for({ text: "Recent Conversations", timeout: 10000 })
   mcp__chrome-devtools__take_snapshot({})
   ```

3. Click on the existing conversation (SPA navigation — no full page reload)
   ```javascript
   mcp__chrome-devtools__click({ uid: "<conversation-link-uid>" })
   ```

4. Wait for conversation page to load history
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: "<expected-message-text>",
     timeout: 30000
   })
   ```

5. Verify the auto-resume patch triggers sandbox start (check console logs)
   ```javascript
   mcp__chrome-devtools__list_console_messages({ types: ["log"] })
   // Look for: "Auto-resume: SPA navigation detected" or "Auto-resume: initialized"
   // And: "Auto-resume: sandbox resume triggered successfully" or "sandbox is RUNNING"
   ```

6. Verify sandbox reaches RUNNING status via API
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const convId = window.location.pathname.match(/conversations\\/([a-f0-9-]+)/)?.[1]?.replace(/-/g, '');
       if (!convId) return { error: 'no conversation id' };
       // Poll up to 60 seconds for sandbox to reach RUNNING
       for (let i = 0; i < 12; i++) {
         const res = await fetch('/api/v1/app-conversations?ids=' + convId);
         const data = await res.json();
         const status = data?.[0]?.sandbox_status;
         if (status === 'RUNNING') return { status, attempts: i + 1 };
         await new Promise(r => setTimeout(r, 5000));
       }
       const finalRes = await fetch('/api/v1/app-conversations?ids=' + convId);
       const finalData = await finalRes.json();
       return { status: finalData?.[0]?.sandbox_status, timedOut: true };
     }`
   })
   // Expected: status === 'RUNNING'
   ```

7. Verify agent can respond (sandbox is functional)
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Find chat input and send a message
   mcp__chrome-devtools__fill({ uid: "<chat-input-uid>", value: "What is 1+1?" })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({ text: "2", timeout: 60000 })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | SPA navigation loads conversation page | URL contains `/conversations/<uuid>` after click |
| 2 | Chat history visible | Previous messages displayed without hard refresh |
| 3 | Sandbox starts automatically | `sandbox_status` reaches `RUNNING` within 60s |
| 4 | Agent is functional | Agent responds to a simple prompt |
| 5 | No page reload needed | `performance.navigation.type` is 0 (navigate), not 1 (reload) |

### Timeout Configuration

| Stage | Maximum Wait Time |
|-------|-------------------|
| Conversation page load | 30 seconds |
| Sandbox start after SPA navigation | 60 seconds |
| Agent response | 60 seconds |

---

## TC-023: LLM Model Selection

### Description
Verify that users can see and select from available Bedrock models in the settings UI.

### Prerequisites
- TC-003 passed (user is logged in)
- Deployment includes `HIDE_LLM_SETTINGS=false` and `BedrockModelDiscovery` IAM permissions

### Category
Compute/Docker changes (triggered by `compute-stack.ts`, `security-stack.ts`, `docker/patch-fix.js` changes)

### Steps

1. Navigate to settings
   ```javascript
   mcp__chrome-devtools__take_snapshot({})
   // Find and click the settings/gear icon
   mcp__chrome-devtools__click({ uid: "<settings-button-uid>" })
   mcp__chrome-devtools__wait_for({ text: "Model", timeout: 10000 })
   mcp__chrome-devtools__take_snapshot({})
   ```

2. Verify model dropdown shows Bedrock models
   ```javascript
   // The AI Configuration modal should be visible with a model selector
   // Look for model names like "claude-sonnet", "claude-opus", "nova", etc.
   mcp__chrome-devtools__take_screenshot({})
   ```

3. Verify the default model is Claude Sonnet 4.6
   ```javascript
   // Check the currently selected model contains "sonnet-4-6"
   mcp__chrome-devtools__evaluate_script({
     function: `() => {
       const modelInput = document.querySelector('[data-testid="ai-config-modal"] input[type="text"]');
       return modelInput ? modelInput.value : 'not found';
     }`
   })
   // Expected: contains "claude-sonnet-4-6"
   ```

4. Select a different model (e.g., Claude Haiku)
   ```javascript
   // Find the model input/dropdown and change to Haiku
   mcp__chrome-devtools__take_snapshot({})
   // Clear existing value and type new model
   mcp__chrome-devtools__fill({ uid: "<model-input-uid>", value: "global.anthropic.claude-haiku-4-5-20251001-v1:0" })
   // Save settings
   mcp__chrome-devtools__click({ uid: "<save-button-uid>" })
   mcp__chrome-devtools__wait_for({ text: "saved", timeout: 5000 })
   ```

5. Start a new conversation and verify agent responds
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__wait_for({ text: "Start new", timeout: 10000 })
   mcp__chrome-devtools__click({ uid: "<new-conversation-button>" })
   mcp__chrome-devtools__wait_for({ text: "What do you want", timeout: 30000 })
   mcp__chrome-devtools__fill({ uid: "<chat-input>", value: "What is 2+2? Reply with just the number." })
   mcp__chrome-devtools__press_key({ key: "Enter" })
   mcp__chrome-devtools__wait_for({ text: "4", timeout: 60000 })
   ```

6. Verify first-time user gets auto-created default settings
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: `() => fetch('/api/settings').then(r => r.json()).then(s => s.llm_model || 'no model')`
   })
   // Expected: contains "bedrock/" prefix and "sonnet-4-6"
   ```

7. **Regression: Verify user model selection is passed to conversation (not overridden by env var)**
   ```javascript
   // Save a non-default model via API
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       await fetch('/api/settings', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ llm_model: 'bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0' })
       });
       return (await fetch('/api/settings').then(r => r.json())).llm_model;
     }`
   })
   // Expected: "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"

   // Start a new conversation
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__wait_for({ text: "New Conversation", timeout: 10000 })
   mcp__chrome-devtools__click({ uid: "<new-conversation-button>" })
   mcp__chrome-devtools__wait_for({ text: "What do you want", timeout: 120000 })

   // Ask the agent to check LLM_MODEL env var in sandbox
   mcp__chrome-devtools__type_text({ text: "Run: echo $LLM_MODEL", submitKey: "Enter" })
   // Wait for response
   mcp__chrome-devtools__wait_for({ text: "no output", timeout: 120000 })
   // Expected: LLM_MODEL env var is empty (not hardcoded to sonnet)
   // The model should be passed via StartConversationRequest, not env var

   // Restore default model
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       await fetch('/api/settings', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ llm_model: 'bedrock/global.anthropic.claude-sonnet-4-6' })
       });
       return 'restored';
     }`
   })
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Settings UI visible | Settings modal opens with model selector |
| 2 | Model list populated | Dropdown shows Bedrock models (not empty) |
| 3 | Default model correct | Default is `bedrock/global.anthropic.claude-sonnet-4-6` |
| 4 | Model change persists | Selected model saved and used for new conversations |
| 5 | Agent responds with changed model | New conversation works with non-default model |
| 6 | First-time auto-settings | `/api/settings` returns 200 with Bedrock model for new users |
| 7 | **Model not overridden by env var** | `LLM_MODEL` env var is empty in sandbox; model comes from user settings via StartConversationRequest |

---

## TC-028: Verify Conversation Archival (Full Lifecycle)

### Description
End-to-end test of the conversation archival lifecycle: create a conversation, interact with it, let it idle-stop, archive it via Lambda, then verify the UI correctly distinguishes PAUSED (resumable) from ARCHIVED (not resumable).

### Prerequisites
- Infrastructure deployed with `conversationRetentionDays=1` (short retention for testing)
- Archival Lambda deployed (`openhands-conversation-archival`)
- Chrome DevTools MCP server connected
- Logged in as a valid Cognito user

### Steps

#### Phase 1: Create a conversation and let it become PAUSED

1. Create a new conversation via UI
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__wait_for({ text: ["New Conversation"], timeout: 10000 })
   mcp__chrome-devtools__click({ uid: "<new-conversation-button>" })
   mcp__chrome-devtools__wait_for({ text: ["What do you want to build?"], timeout: 30000 })
   // Record conversation ID from URL: /conversations/<CONV_ID>
   ```

2. Record the conversation ID and verify sandbox is RUNNING
   ```bash
   CONV_ID="<conversation-id-from-url>"
   REGISTRY_TABLE="<registry-table>"
   aws dynamodb get-item \
     --table-name $REGISTRY_TABLE \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.status.S' --output text
   # Expected: RUNNING or STARTING
   ```

3. Navigate away and wait for idle timeout (or manually stop the sandbox)
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "about:blank", type: "url" })
   ```
   ```bash
   # Option A: Wait for idle timeout (staging: 10 minutes)
   # Option B: Manually force to PAUSED for faster testing
   aws dynamodb update-item \
     --table-name $REGISTRY_TABLE \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --update-expression "SET #st = :st" \
     --expression-attribute-names '{"#st":"status"}' \
     --expression-attribute-values '{":st":{"S":"PAUSED"}}' \
     --region $DEPLOY_REGION
   ```

#### Phase 2: Verify PAUSED conversation is resumable

4. Open the PAUSED conversation in UI — sandbox should resume
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}/conversations/<CONV_ID>", type: "url" })
   mcp__chrome-devtools__wait_for({ text: ["Starting", "Connecting", "What do you want to build?"], timeout: 30000 })
   // PASS if sandbox starts resuming — PAUSED conversations are resumable
   mcp__chrome-devtools__navigate_page({ url: "about:blank", type: "url" })
   ```

5. Verify conversation does NOT show "Archived" label in conversation list
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__wait_for({ text: ["Recent Conversations"], timeout: 10000 })
   mcp__chrome-devtools__take_snapshot({})
   // The conversation should appear WITHOUT an "Archived" badge
   ```

#### Phase 3: Archive the conversation

6. Set conversation timestamps to simulate old data, then run archival
   ```bash
   # Force back to PAUSED with old timestamp (2 days ago)
   OLD_TS=$(($(date +%s) - 2 * 86400))
   aws dynamodb update-item \
     --table-name $REGISTRY_TABLE \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --update-expression "SET #st = :st, last_activity_at = :ts, created_at = :ts" \
     --expression-attribute-names '{"#st":"status"}' \
     --expression-attribute-values "{\":st\":{\"S\":\"PAUSED\"},\":ts\":{\"N\":\"$OLD_TS\"}}" \
     --region $DEPLOY_REGION

   # Invoke archival Lambda
   aws lambda invoke \
     --function-name openhands-conversation-archival \
     --region $DEPLOY_REGION \
     /tmp/archival-output.json
   cat /tmp/archival-output.json
   # Expected: archived count >= 1
   ```

7. Verify conversation is now ARCHIVED in DynamoDB
   ```bash
   aws dynamodb get-item \
     --table-name $REGISTRY_TABLE \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.{status:status.S,ttl:ttl.N}'
   # Expected: status=ARCHIVED, ttl=null (removed)
   ```

#### Phase 4: Verify ARCHIVED conversation UI behavior

8. Check conversation list — ARCHIVED conversation should show "Archived" label
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}", type: "url" })
   mcp__chrome-devtools__wait_for({ text: ["Recent Conversations"], timeout: 10000 })
   mcp__chrome-devtools__take_snapshot({})
   // The conversation should now show with an "Archived" badge/label
   // Compare with step 5: same conversation, different label after archival
   ```

9. Open the ARCHIVED conversation — verify banner + history + no sandbox
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://${FULL_DOMAIN}/conversations/<CONV_ID>", type: "url" })
   // Wait for archived detection and banner
   // (patch-fix.js checks /api/conversations/{id} for status=ARCHIVED)
   mcp__chrome-devtools__wait_for({ text: ["archived and is read-only"], timeout: 15000 })
   mcp__chrome-devtools__take_snapshot({})
   // Key verifications:
   //   a. Purple "archived" banner at top with close button (X)
   //   b. Conversation history loaded from S3 (user/assistant messages visible)
   //   c. Sandbox NOT starting — no "Connecting..." status
   //   d. Status shows "Archived" instead of "Starting"
   //   e. Contrast with step 4: same conversation WAS resumable when PAUSED
   ```

10. Verify archived banner has close button
    ```javascript
    // Click the X button on the banner
    mcp__chrome-devtools__click({ uid: "<close-button-uid>" })
    // Banner should disappear
    mcp__chrome-devtools__take_snapshot({})
    // Verify: banner element removed from DOM
    ```

11. Verify API-level blocking
    ```bash
    # Both /start and /resume should return 409
    # (requires access from within VPC or via SSM session)
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST http://orchestrator.openhands.local:8081/start \
      -H 'Content-Type: application/json' \
      -d "{\"session_id\":\"$CONV_ID\"}"
    # Expected: 409

    curl -s -o /dev/null -w "%{http_code}" \
      -X POST http://orchestrator.openhands.local:8081/resume \
      -H 'Content-Type: application/json' \
      -d "{\"runtime_id\":\"$CONV_ID\"}"
    # Expected: 409
    ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | New conversation creates successfully | Step 1: sandbox starts |
| 2 | PAUSED conversation resumable | Step 4: sandbox resumes |
| 3 | PAUSED conversation has NO "Archived" label | Step 5: snapshot shows no badge |
| 4 | Archival Lambda succeeds | Step 6: archived count >= 1 |
| 5 | DynamoDB status = ARCHIVED, TTL removed | Step 7: status=ARCHIVED, ttl=null |
| 6 | ARCHIVED conversation shows "Archived" label in sidebar | Step 8: snapshot shows badge |
| 7 | **Archived banner displayed** | Step 9a: purple banner with "archived and is read-only" text |
| 8 | **Conversation history attempted** | Step 9b: patch calls trajectory API; messages shown if events exist in S3 |
| 9 | **Sandbox NOT starting** | Step 9c: auto-resume skipped, no /resume call triggered |
| 10 | Banner close button works | Step 10: clicking X removes banner |
| 11 | `/start` returns 409 for ARCHIVED | Step 11: HTTP 409 |
| 12 | `/resume` returns 409 for ARCHIVED | Step 11: HTTP 409 |
| 13 | **Same conversation: resumable when PAUSED, blocked when ARCHIVED** | Steps 4 vs 9 |

### Limitations

- **V1 event persistence**: The V1 app-server uses `FilesystemEventService` which writes events
  to `{persistence_dir}/{user_id}/v1_conversations/`. On Fargate, `persistence_dir` defaults to
  the container's ephemeral filesystem (`/data/openhands`), NOT the EFS mount. Events are lost
  when the Fargate task restarts. This means conversation history is not available after archival
  (or any task restart). Fix: configure `OH_PERSISTENCE_DIR` to point to the app's EFS mount path
  so V1 events survive Fargate task replacements. This is a separate configuration issue tracked
  independently from this lifecycle PR.

---

## TC-029: Verify Conversation Deletion

### Description
Verify that the orchestrator `/delete` endpoint fully deletes conversation data across all storage layers (DynamoDB, S3, EFS, Aurora).

### Prerequisites
- Infrastructure deployed with sandbox orchestrator
- At least one conversation with data in S3 and DynamoDB

### Steps

1. Create a conversation and interact with it (TC-005)
   - Record the conversation ID from the URL

2. Stop the sandbox (navigate away or wait for idle timeout)

3. Verify data exists before deletion
   ```bash
   CONV_ID="<conversation-id>"

   # DynamoDB record exists
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION \
     --query 'Item.status.S'
   # Expected: PAUSED or STOPPED

   # S3 objects exist
   aws s3 ls s3://<data-bucket>/conversations/$CONV_ID/ --region $DEPLOY_REGION
   # Expected: Objects present
   ```

4. Call the orchestrator `/delete` endpoint
   ```bash
   # Via the internal orchestrator URL (requires access from within VPC)
   curl -X POST http://orchestrator.openhands.local:8081/delete \
     -H 'Content-Type: application/json' \
     -d "{\"runtime_id\":\"$CONV_ID\"}"
   # Expected: {"status":"deleted","session_id":"<conv-id>"}
   ```

5. Verify data is deleted
   ```bash
   # DynamoDB record gone
   aws dynamodb get-item \
     --table-name <registry-table> \
     --key "{\"conversation_id\":{\"S\":\"$CONV_ID\"}}" \
     --region $DEPLOY_REGION
   # Expected: empty (no Item)

   # S3 objects gone (after deletion Lambda completes)
   sleep 30  # Allow async Lambda to finish
   aws s3 ls s3://<data-bucket>/conversations/$CONV_ID/ --region $DEPLOY_REGION
   # Expected: empty or no output

   # Aurora record gone
   # (verify via app API - conversation should not appear in list)
   ```

6. Verify conversation no longer appears in UI
   - Refresh the home page
   - Conversation should not be in "Recent Conversations" list

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | `/delete` returns success | `{"status":"deleted"}` response |
| 2 | DynamoDB record removed | `get-item` returns empty |
| 3 | S3 objects removed | No objects under conversation prefix |
| 4 | EFS workspace removed | Directory no longer exists |
| 5 | Conversation gone from UI | Not in conversation list |
| 6 | Deletion Lambda logged | Check CloudWatch logs for `openhands-conversation-delete` |

---

## TC-030: Verify Changes Tab Without GitHub Repo

### Description
Verify that the "Changes" tab works correctly for a conversation that is **not** connected to a GitHub repository. The git changes API should return successfully and the Changes panel should display modified files.

### Prerequisites
- TC-003 completed (logged in)
- TC-005 completed (new conversation created without a GitHub repo)
- Agent has created or modified files (e.g., TC-006 Flask app)

### Steps

1. Navigate to an existing conversation where the agent has modified files
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<convId>",
     type: "url"
   })
   ```

2. Wait for conversation to load
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: ["What do you want to build?", "Waiting for task"],
     timeout: 15000
   })
   ```

3. Click the "Changes" button in the toolbar (the `<>` icon)
   ```javascript
   // Take snapshot to find the Changes button
   mcp__chrome-devtools__take_snapshot({})
   // Click the Changes button
   mcp__chrome-devtools__click({ uid: "<changes-button-uid>" })
   ```

4. Verify the Changes panel loads with file list
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: ["app.py", ".gitignore", "No changes"],
     timeout: 10000
   })
   ```

5. Verify the git changes API returned 200 (not 500)
   ```javascript
   mcp__chrome-devtools__list_network_requests({
     resourceTypes: ["fetch", "xhr"]
   })
   // Look for: GET /runtime/<convId>/8000/api/git/changes/ → 200
   // Previously this could return 500 if the path was not normalized
   ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Changes button clickable | Button exists in toolbar |
| 2 | Git changes API returns 200 | Network request `/api/git/changes/` or `/api/git/changes/.` returns 200 |
| 3 | Changed files listed | Files modified by agent appear in Changes panel |
| 4 | No 500 errors | No server errors in network requests |

---

## TC-031: Verify Changes Tab With GitHub Repo (Regression)

### Description
Verify that the "Changes" tab works correctly for a conversation that opened a **GitHub repository** and that file modifications inside the connected repo are visible. This is a regression test for the bug where git changes/diff queries couldn't find the correct nested git repo.

**Bug scenario**: The repo is cloned to `/workspace/project/<repo>/` which is a nested git repo. Previously, paths were normalized to `.` (workspace root) which only showed the outer `/workspace` repo — modifications inside the cloned repo were invisible.

**Fix**: `patch-fix.js` normalizes paths to `project/<repo>` so the agent-server resolves to the correct nested git repository. Additionally, `git init /workspace/project` was removed from the sandbox entrypoint to avoid creating an unnecessary intermediate git repo.

### Prerequisites
- TC-003 completed (logged in)
- TC-005 completed (conversation with running sandbox)

### Steps

The `normalizeGitUrl()` function in `patch-fix.js` intercepts `fetch()` and `XMLHttpRequest.open()`
calls matching localhost/private-IP patterns and rewrites them. We verify that bare repo names and
URL-encoded workspace paths are normalized to `project/<repo>` so the agent-server resolves to the
correct nested git repository.

1. Navigate to an existing conversation with a running sandbox (connected to a GitHub repo)
   ```javascript
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<convId>",
     type: "url"
   })
   ```

2. Wait for conversation to load
   ```javascript
   mcp__chrome-devtools__wait_for({
     text: ["Waiting for task"],
     timeout: 60000
   })
   ```

3. Simulate the frontend's git changes API call with a bare repo name
   ```javascript
   // This is exactly what the frontend does when a GitHub repo is connected:
   // fetch('http://localhost:8000/api/git/changes/<repo-name>')
   // The patch-fix.js interceptor will:
   //   1. Match httpPattern (localhost:8000)
   //   2. buildRuntimeUrl() -> /runtime/<convId>/8000/api/git/changes/<repo-name>
   //   3. normalizeGitUrl() -> rewrites bare repo name to "project/<repo>"
   //   4. Final URL: /runtime/<convId>/8000/api/git/changes/project/<repo>
   mcp__chrome-devtools__evaluate_script({
     function: `async () => {
       const resp = await fetch('http://localhost:8000/api/git/changes/openhands-infra');
       return { status: resp.status, finalUrl: resp.url };
     }`
   })
   ```

4. Verify the URL was rewritten (bare repo name → `project/<repo>`)
   ```javascript
   // The finalUrl should end with /api/git/changes/project/openhands-infra
   // (NOT /api/git/changes/openhands-infra or /api/git/changes/.)
   // Status may be 200 (if auth cookies present) or 401 (path-based routing auth)
   // The key verification is the URL rewrite, not the response status
   ```

5. Verify via console logs that the rewrite happened
   ```javascript
   mcp__chrome-devtools__list_console_messages({ types: ["log"] })
   // Look for:
   // "Fetch patched: http://localhost:8000/api/git/changes/openhands-infra
   //             -> https://<host>/runtime/<convId>/8000/api/git/changes/project/openhands-infra"
   ```

6. Click the "Changes" tab/button to view file changes in the connected repo
   ```javascript
   // Navigate to the conversation that has zxkane/openhands-infra connected
   mcp__chrome-devtools__navigate_page({
     url: "https://<subdomain>.<domain>/conversations/<convId>",
     type: "url"
   })
   // Wait for Changes tab to load
   // The frontend calls: /api/git/changes/%2Fworkspace%2Fproject%2Fopenhands-infra
   // The interceptor rewrites to: /api/git/changes/project/openhands-infra
   // The agent-server resolves this as /workspace/project/openhands-infra (the cloned repo)
   ```

7. Verify that changed files inside the connected repo are listed
   ```javascript
   // The Changes tab should show modified files from the cloned repo
   // (e.g., files the agent modified inside /workspace/project/openhands-infra/)
   // If the repo was just cloned with no modifications, Changes should be empty (not an error)
   mcp__chrome-devtools__take_snapshot({})
   // Verify: no error messages, file list renders (or empty state if no changes)
   ```

8. Click a changed file to trigger diff
   ```javascript
   // The frontend sends: /api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2F<filename>
   // The interceptor rewrites to: /api/git/diff/project/openhands-infra/<filename>
   ```

9. Verify the diff API URL was rewritten correctly
   ```javascript
   mcp__chrome-devtools__list_console_messages({ types: ["log"] })
   // Look for:
   // "XHR patched: https://<ip>:8000/api/git/diff/%2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore
   //           -> https://<host>/runtime/<convId>/8000/api/git/diff/project/openhands-infra/.gitignore"
   ```

10. Verify the diff request returns 200 (not 500)
    ```javascript
    mcp__chrome-devtools__list_network_requests({ resourceTypes: ["fetch", "xhr"] })
    // Look for: GET /runtime/<convId>/8000/api/git/diff/project/openhands-infra/.gitignore → 200
    ```

### Acceptance Criteria

| # | Criteria | Verification |
|---|----------|--------------|
| 1 | Interceptor matches localhost URL | Console log shows "Fetch patched:" or "XHR patched:" message |
| 2 | Changes API: bare repo name normalized | URL contains `/api/git/changes/project/openhands-infra` (not bare name or `.`) |
| 3 | Changes API: URL-encoded path normalized | `%2Fworkspace%2Fproject%2Fopenhands-infra` → `project/openhands-infra` |
| 4 | Changes tab shows connected repo files | Modified files from the cloned repo are listed (or empty state if no changes) |
| 5 | Diff API: path preserves repo context | `%2Fworkspace%2Fproject%2Fopenhands-infra%2F.gitignore` → `project/openhands-infra/.gitignore` |
| 6 | Diff API returns 200 | Network request shows `/api/git/diff/project/openhands-infra/.gitignore` → 200 |
| 7 | No-repo: Changes API uses workspace root | `%2Fworkspace%2Fproject` → `.` (no repo connected) |
| 8 | No-repo: dotfile diff uses workspace root | `%2Fworkspace%2Fproject%2F.gitignore` → `./.gitignore` (not `project/.gitignore`) |
| 9 | No-repo: clicking .gitignore shows diff | Diff view renders file content without "Internal Server Error" |

### No-Repo Dotfile Regression Test

When no repo is connected, the workspace root has `.gitignore` from `git init /workspace`. Clicking
it to view the diff must NOT produce "Internal Server Error: File does not exist: /mnt/efs/project/.gitignore".

1. Create a new scratch conversation (no repo connected)
2. Wait for sandbox to start and Changes tab to show `.gitignore`
3. Click `.gitignore` to expand the diff
4. Verify console log shows correct rewrite:
   ```
   XHR patched: https://<ip>:8000/api/git/diff/%2Fworkspace%2Fproject%2F.gitignore
             -> https://<host>/runtime/<convId>/8000/api/git/diff/./.gitignore
   ```
   - The path must be `./.gitignore` (dotfile treated as file in workspace root)
   - NOT `project/.gitignore` (dotfile incorrectly treated as repo name)
5. Verify diff view renders the `.gitignore` content without errors

### Alternative: Full Flow with Connected Repo

For a full end-to-end test with an actual connected GitHub repo (public repos work without tokens):

```javascript
// Create conversation with a connected repo via API
mcp__chrome-devtools__evaluate_script({
  function: `async () => {
    const resp = await fetch('/api/v1/app-conversations', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ selected_repository: 'zxkane/openhands-infra' })
    });
    return await resp.json();
  }`
})
// Navigate to the conversation, wait for sandbox, then click Changes button
// The frontend will call: http://<private-ip>:8000/api/git/changes/openhands-infra
// which gets intercepted and rewritten to /api/git/changes/project/openhands-infra
// The agent-server resolves /workspace/project/openhands-infra — the cloned repo
// Click a changed file to trigger diff — the diff path preserves the repo context too.
```

### Notes

- This test validates the `normalizeGitUrl()` function in `patch-fix.js`
- The interceptor only triggers for URLs matching `httpPattern` (localhost, `host.docker.internal`,
  VPC private IPs like `172.31.x.x`) — these are the URLs the agent-server returns to the frontend
- The frontend sends paths in two forms:
  - Changes API: `%2Fworkspace%2Fproject%2F<repo>` or bare `<repo>` → normalized to `project/<repo>`
  - Diff API: `%2Fworkspace%2Fproject%2F<repo>%2F<file>` or `<repo>%2F<file>` → normalized to `project/<repo>/<file>`
- **Dotfile distinction**: Repo names never start with `.`. Segments starting with `.` (e.g., `.gitignore`, `.env`)
  are treated as files in the workspace root, not repo names. `%2Fworkspace%2Fproject%2F.gitignore` → `./.gitignore`
- The agent-server WORKDIR is `/workspace`, so `project/<repo>` resolves to `/workspace/project/<repo>/` — the cloned repo directory
- `git init /workspace/project` was removed from the sandbox entrypoint to avoid creating an unnecessary intermediate git repo
  that would shadow the cloned repo's changes
- Public repos (e.g., `zxkane/openhands-infra`) do NOT require GitHub integration — they can be
  opened via `POST /api/v1/app-conversations` with `selected_repository`
- Without the fix, the Changes tab showed empty for connected repos because it queried the outer
  `/workspace` repo instead of the nested cloned repo at `/workspace/project/<repo>/`
- The fix is covered by 19 unit regression tests in `docker/test_patch_fix_git_paths.js`
