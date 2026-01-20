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
     --stack-name OpenHands-Edge \
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
