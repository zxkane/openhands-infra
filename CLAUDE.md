# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

**IMPORTANT**: Claude Code MUST follow this workflow for all feature development and bug fixes.

### Workflow Steps

```
┌─────────────────────────────────────────────────────────────────┐
│  1. CREATE BRANCH                                               │
│     git checkout -b feat/<feature-name> or fix/<bug-name>       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. IMPLEMENT CHANGES                                           │
│     - Write code                                                │
│     - Update unit tests (npm run test)                          │
│     - Update E2E test cases if needed (test/E2E_TEST_CASES.md)  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. LOCAL VERIFICATION                                          │
│     - npm run build                                             │
│     - npm run test                                              │
│     - npx cdk deploy --all (deploy to AWS)                      │
│     - Run E2E tests via Chrome DevTools MCP                     │
│     - Verify ALL tests pass before proceeding                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. COMMIT AND CREATE PR                                        │
│     - git add -A && git commit -m "type(scope): description"    │
│     - git push -u origin <branch-name>                          │
│     - Create PR via GitHub MCP or gh CLI                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. WAIT FOR PR CHECKS                                          │
│     - Monitor GitHub Actions checks                             │
│     - If checks FAIL → Return to Step 2, fix issues             │
│     - If checks PASS → Proceed to Step 6                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  6. ADDRESS REVIEWER BOT FINDINGS                               │
│     - Review Amazon Q Developer comments                        │
│     - Review other automated security/code review findings      │
│     - Fix issues or add documentation explaining design choice  │
│     - Push fixes and wait for checks again                      │
│     - Reply DIRECTLY to each review comment (not a single PR    │
│       comment) and RESOLVE each conversation thread             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  7. READY FOR MERGE                                             │
│     - All checks passed                                         │
│     - All reviewer comments addressed                           │
│     - PR is mergeable                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Branch Naming Convention

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<name>` | `feat/cross-user-authorization` |
| Bug fix | `fix/<name>` | `fix/websocket-connection` |
| Refactor | `refactor/<name>` | `refactor/openresty-container` |
| Documentation | `docs/<name>` | `docs/runtime-routing` |

### Commit Message Format

```
type(scope): description

Types: feat, fix, docs, refactor, test, chore
Scope: runtime, edge, compute, security, etc.
```

### PR Checks to Monitor

| Check | Description | Action if Failed |
|-------|-------------|------------------|
| CI / build-and-test | Build + all unit tests (Jest + pytest) | Fix code or update snapshots |
| Security Scan | SAST, npm audit, secrets | Fix security issues |
| Amazon Q Developer | Security review | Address findings or document design decisions |

### Responding to Review Comments

**IMPORTANT**: When addressing reviewer bot findings, you MUST:
1. Reply directly to each review comment thread (NOT add a single general PR comment)
2. Resolve each conversation after replying

**Step 1: Reply to each discussion**
```bash
# Get review comment IDs
gh api repos/{owner}/{repo}/pulls/{pr}/comments \
  --jq '.[] | {id: .id, path: .path, body: .body[:50]}'

# Reply to each comment using in_reply_to
gh api repos/{owner}/{repo}/pulls/{pr}/comments \
  -X POST \
  -f body="Addressed in commit abc123 - <description of fix>" \
  -F in_reply_to=<comment_id>
```

**Step 2: Resolve each review thread**
```bash
# Get review thread IDs
gh api graphql -f query='
query {
  repository(owner: "{owner}", name: "{repo}") {
    pullRequest(number: {pr}) {
      reviewThreads(first: 10) {
        nodes {
          id
          isResolved
          comments(first: 1) {
            nodes { body }
          }
        }
      }
    }
  }
}'

# Resolve each thread
gh api graphql -f query='
mutation {
  resolveReviewThread(input: {threadId: "<thread_id>"}) {
    thread { isResolved }
  }
}'
```

**Wrong approach** (single PR comment):
```bash
# DON'T do this - it doesn't close the discussion threads
gh pr comment {pr} --body "Fixed all issues"
```

This ensures:
- Each discussion thread is properly replied to
- Conversations are marked as resolved
- PR shows all conversations as resolved

### No Environment-Specific Information in Source Control

**CRITICAL**: This is an open source project. Source-controlled files must NOT contain:

| Prohibited | Use Instead |
|------------|-------------|
| Real domain names (e.g., `mycompany.com`) | Placeholders: `{domain}`, `{subdomain}.{domain}`, or `example.com` |
| AWS account IDs (except `123456789012`) | Placeholder: `<aws-account-id>` or `123456789012` |
| Real resource ARNs | Generic ARNs with placeholders |
| IP addresses | Placeholders: `<ip-address>` |
| Email addresses | Placeholders: `<email>`, `user@example.com` |

**Allowed placeholders**: `{domain}`, `{subdomain}`, `{port}`, `{convId}`, `<aws-account-id>`, `123456789012` (AWS documentation standard), `example.com`

**Where environment-specific info belongs**:
- `CLAUDE.local.md` - User's local project instructions (gitignored)
- `.env` files - Environment variables (gitignored)
- `cdk.context.json` - CDK lookup cache (gitignored)

## Common Commands

```bash
# Build TypeScript
npm run build

# Watch mode
npm run watch

# Run all tests (TypeScript + Python)
npm run test

# Run TypeScript tests only
npm run test:ts

# Run Python tests only
npm run test:py

# Setup Python test environment (first time only)
python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt

# Synthesize CloudFormation (requires context)
npx cdk synth --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region>

# Deploy all stacks
npx cdk deploy --all --context ...

# Deploy single stack
npx cdk deploy OpenHands-Edge --context ...

# Show diff before deploy
npx cdk diff --all --context ...

# Destroy all stacks
npx cdk destroy --all --context ...
```

## Required Context Parameters

All CDK commands require these context parameters:
- `vpcId` - Existing VPC ID
- `hostedZoneId` - Route 53 Hosted Zone ID
- `domainName` - Domain name (e.g., example.com)
- `subDomain` - Optional, defaults to "openhands"
- `region` - Optional, defaults to us-east-1

## Architecture

### Stack Dependency Graph (7 Stacks)

```
AuthStack (us-east-1) ← Cognito User Pool (shared across domains)
    ↓
NetworkStack (main region)
    ↓
SecurityStack (main region) ← depends on NetworkStack.output
    ↓
MonitoringStack (main region) ← independent
    ↓
DatabaseStack (main region) ← depends on Network + Security outputs
    ↓
ComputeStack (main region) ← depends on Network + Security + Monitoring + Database outputs
    ↓
EdgeStack (us-east-1) ← depends on ComputeStack outputs + AuthStack
```

### Self-Healing Architecture

The infrastructure is designed for **self-healing** - when EC2 instances are replaced during CDK deployments or ASG health checks, conversation history is preserved:

- **Aurora Serverless v2 PostgreSQL**: Stores conversation metadata with IAM authentication (no passwords)
- **S3 Data Bucket**: Stores conversation events and user settings
- **EFS Workspace File System**: Stores sandbox workspaces and app state under `/data/openhands` (survives EC2 replacement)
- **EBS Volume**: Instance-local storage mounted at `/data` (ephemeral across EC2 replacement)

### Cross-Region Deployment

- **Main region stacks**: Network, Security, Monitoring, Database, Compute (VPC, Aurora, EC2, Internal ALB)
- **us-east-1 stack**: Edge (Cognito, Lambda@Edge, CloudFront with VPC Origin, WAF, Route 53)

Cross-region references are enabled via `crossRegionReferences: true`.

### CloudFront VPC Origin

The infrastructure uses CloudFront VPC Origin to connect directly to the internal ALB:
- No public-facing ALB required
- CloudFront → VPC Origin → Internal ALB → EC2
- Enhanced security: ALB is only accessible via CloudFront

### Data Flow Between Stacks

Each stack exposes an `output` property (typed in `lib/interfaces.ts`) consumed by dependent stacks:
- `NetworkStack.output` → SecurityStack, DatabaseStack, ComputeStack
- `SecurityStack.output` → DatabaseStack, ComputeStack
- `MonitoringStack.output` → ComputeStack
- `DatabaseStack.output` → ComputeStack
- `ComputeStack.output` + `alb` → EdgeStack

### Key Files

| File | Purpose |
|------|---------|
| `bin/openhands-infra.ts` | CDK entry point, context validation, stack orchestration |
| `lib/interfaces.ts` | Shared TypeScript interfaces for stack I/O |
| `lib/network-stack.ts` | VPC import, VPC Endpoints |
| `lib/security-stack.ts` | IAM Roles, Security Groups |
| `lib/monitoring-stack.ts` | CloudWatch Logs, Alarms, Dashboard, Backup, S3 Data Bucket |
| `lib/database-stack.ts` | Aurora Serverless v2 PostgreSQL with IAM Authentication |
| `lib/compute-stack.ts` | EC2 ASG, Launch Template, Internal ALB, OpenResty container |
| `lib/edge-stack.ts` | Cognito, Lambda@Edge, CloudFront (VPC Origin), WAF, Route 53 |
| `config/config.toml` | OpenHands application configuration (LLM, sandbox, security) |
| `docker/patch-fix.js` | Frontend JavaScript patches (URL rewriting, settings auto-config, runtime subdomain routing) |
| `docker/openresty/` | OpenResty proxy container (Dockerfile, nginx.conf, docker_discovery.lua) |
| `test/E2E_TEST_CASES.md` | Comprehensive E2E test cases with acceptance criteria |

### Runtime Subdomain Routing

User applications running inside sandbox containers are accessible via dedicated runtime subdomains:

```
https://{port}-{convId}.runtime.{subdomain}.{domain}/
```

**Example**: `https://5000-{convId}.runtime.{subdomain}.{domain}/`

**Request Flow**:
```
Browser → CloudFront → Lambda@Edge (JWT verify + inject user_id) → ALB → OpenResty (verify ownership) → Container App
```

**Key Components**:

| Component | File | Purpose |
|-----------|------|---------|
| ACM Certificate | `lib/edge-stack.ts` | Wildcard cert includes `*.runtime.{subdomain}.{domain}` SAN |
| Route 53 | `lib/edge-stack.ts` | Wildcard A record `*.runtime.{subdomain}` → CloudFront |
| Lambda@Edge viewer-request | `lib/edge-stack.ts` | Verifies JWT, injects `X-Cognito-User-Id`, rewrites URI |
| Lambda@Edge origin-response | `lib/edge-stack.ts` | Adds security headers (X-Frame-Options, CSP, cookie isolation) |
| OpenResty Proxy | `docker/openresty/nginx.conf` | Verifies container ownership, proxies to container |
| Lua Docker Discovery | `docker/openresty/docker_discovery.lua` | Finds container by `conversation_id` label, returns IP + port + user_id |
| Frontend Patch | `docker/patch-fix.js` | Rewrites `localhost:port` URLs to runtime subdomain format |

**Security**: Runtime requests require authentication and authorization:
1. **Authentication**: Lambda@Edge verifies JWT (`id_token` cookie) and redirects to login if invalid
2. **Authorization**: OpenResty verifies container's `user_id` label matches requesting user
3. **Backwards Compatibility**: Containers without `user_id` label allow access (requires OpenHands core update)

**Dual Routing Approach**:

| Route Type | Pattern | Use Case | Lambda@Edge |
|------------|---------|----------|-------------|
| Path-based | `/runtime/{convId}/{port}/...` | Agent WebSocket, API calls | Yes (auth required) |
| Subdomain | `{port}-{convId}.runtime.{domain}/` | User apps (Flask, Express) | Yes (auth required) |

**URL Rewriting (patch-fix.js)**:
- Agent WebSocket (`/sockets/*`) → Path-based: `wss://{domain}/runtime/{convId}/{port}/sockets/events/...`
- API calls (`/api/*`) → Path-based: preserves main domain authentication
- User app requests → Subdomain: apps run at domain root

**Why Subdomain Routing for User Apps?**
- Apps run at domain root (`/`) instead of `/runtime/{cid}/{port}/`
- Internal routes like `/add`, `/api/users` resolve correctly
- Each runtime has isolated cookies (security)

**Why Path-based Routing for Agent Communication?**
- WebSocket connections use same-origin cookie authentication
- API calls need session cookies from main domain
- Agent-server events flow through: `wss://{domain}/runtime/{convId}/{port}/sockets/events/...`

### Runtime Port Access

Runtime subdomains support access to **any port** inside sandbox containers:
- `https://5000-{convId}.runtime.{subdomain}.{domain}/` → Flask app on port 5000
- `https://3000-{convId}.runtime.{subdomain}.{domain}/` → Express app on port 3000
- `https://8080-{convId}.runtime.{subdomain}.{domain}/` → Any web server

**How it works**: OpenResty queries Docker API to get the container's bridge network IP, then proxies directly to `container_ip:any_port`. No Docker port mapping required.

**Technical Details**:
- Lua script finds container by `conversation_id` label
- Gets container IP from `NetworkSettings.Networks` (iterates all networks)
- Port routing logic:
  1. First tries direct connection to `container_ip:requested_port` (100ms TCP probe)
  2. If unreachable, looks up Docker port mapping (PublicPort → PrivatePort)
  3. Falls back to requested port if no mapping found
- OpenResty runs as container on same Docker network as sandboxes

## EC2 User Data

The ComputeStack generates inline user data that:
1. Installs Docker and Docker Compose (ARM64)
2. Configures CloudWatch Agent
3. Formats and mounts data EBS volume to `/data`
4. Mounts EFS to `/data/openhands` for persistent workspaces
5. Creates docker-compose.yml dynamically
6. Loads `config/config.toml` from the repo at CDK synth time
7. Starts OpenHands via systemd service

**Configuration**: Edit `config/config.toml` to change LLM model, sandbox settings, or security options. The config is embedded into user data during `cdk synth`.

## Cognito User Management

Create a new user:
```bash
aws cognito-idp admin-create-user \
  --user-pool-id <user-pool-id> \
  --username <email> \
  --user-attributes Name=email,Value=<email> Name=email_verified,Value=true \
  --temporary-password "<temp-password>" \
  --message-action SUPPRESS \
  --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id <user-pool-id> \
  --username <email> \
  --password "<password>" \
  --permanent \
  --region us-east-1
```

## Lambda@Edge Development Guidelines

### External Handler Files Required

**CRITICAL**: Lambda@Edge handler code MUST be stored in external files under `lib/lambda-edge/`, NOT inlined in CDK stack definitions.

| Do | Don't |
|----|-------|
| `lib/lambda-edge/auth-handler.js` + `fs.readFileSync()` | `code: lambda.Code.fromInline(\`...\`)` with embedded code |
| External file with `{{PLACEHOLDER}}` syntax | Template literals with `${variable}` in stack |

**Rationale**:
1. **Unit Testing**: External files enable Jest unit tests with mocking
2. **Maintainability**: Easier to read, edit, and debug
3. **Code Review**: Changes are visible in diff without escaping issues
4. **IDE Support**: Proper syntax highlighting and linting

### Placeholder Replacement Pattern

Lambda@Edge cannot access environment variables or regional services. Configuration must be embedded at synth time using placeholder replacement:

```typescript
// In CDK stack (lib/edge-stack.ts)
const authHandlerPath = path.join(__dirname, 'lambda-edge', 'auth-handler.js');
let authHandlerCode = fs.readFileSync(authHandlerPath, 'utf-8');

authHandlerCode = authHandlerCode
  .replace(/'{{USER_POOL_ID}}'/g, `'${userPoolId}'`)
  .replace(/'{{CLIENT_ID}}'/g, `'${clientId}'`);

const authFunction = new lambda.Function(this, 'AuthFunction', {
  code: lambda.Code.fromInline(authHandlerCode),
  // ...
});
```

```javascript
// In external handler (lib/lambda-edge/auth-handler.js)
const CONFIG = {
  userPoolId: '{{USER_POOL_ID}}',  // Replaced at synth time
  clientId: '{{CLIENT_ID}}',
};
```

### Testing External Handlers

```javascript
// test/lambda-edge-auth.test.ts
import { handler, getCookie, parseRuntimeSubdomain } from '../lib/lambda-edge/auth-handler.js';

describe('auth-handler', () => {
  test('parseRuntimeSubdomain extracts port and convId', () => {
    expect(parseRuntimeSubdomain('5000-abc123.runtime.example.com'))
      .toEqual({ port: '5000', convId: 'abc123', isRuntime: true });
  });
});
```

## Lambda@Edge Deletion Note

Lambda@Edge functions cannot be deleted immediately after CloudFront distribution removal. AWS requires several hours for edge replicas to be cleaned up. If stack deletion fails due to Lambda@Edge, use `--retain-resources` flag.

## Deployment

### Prerequisites

1. AWS CLI configured with appropriate credentials
2. Node.js 20+ installed
3. CDK bootstrapped in both regions (main region and us-east-1 for Lambda@Edge)

### Bootstrap CDK (First Time Only)

```bash
npx cdk bootstrap --region <main-region>
npx cdk bootstrap --region us-east-1  # Required for Lambda@Edge and CloudFront
```

### Deploy All Stacks

**⚠️ IMPORTANT: Multi-Domain Cognito Callback URLs**

When multiple domains share the same Cognito User Pool (Auth stack), deploying one domain without specifying ALL callback domains will **break authentication for other domains**. The CDK will replace Cognito callback URLs entirely with only the current domain.

**Option A: Exclude Auth Stack (Recommended for routine updates)**

For non-auth changes (Compute, Edge, Network, etc.), exclude Auth stack to preserve existing Cognito configuration:

```bash
npx cdk deploy --all --exclusively \
  OpenHands-Network OpenHands-Monitoring OpenHands-Security \
  OpenHands-Database OpenHands-Compute OpenHands-Edge \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region> \
  --require-approval never
```

**Option B: Include All Callback Domains (Required when deploying Auth stack)**

For first-time deployment or Cognito changes, specify ALL domains that share the Auth stack:

```bash
npx cdk deploy --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region> \
  --context authCallbackDomains='["domain1.example.com","domain2.example.com"]' \
  --require-approval never
```

**Decision Matrix:**

| Change Type | Deploy Command |
|-------------|----------------|
| Compute/Edge/Network changes | Option A (exclude Auth stack) |
| Cognito configuration changes | Option B (include all callback domains) |
| First-time deployment | Option B (include all callback domains) |

**Deployment Order** (handled automatically by CDK):
1. OpenHands-Auth (us-east-1) - Cognito User Pool (only if included)
2. OpenHands-Network (main region)
3. OpenHands-Security (main region) - depends on Network
4. OpenHands-Monitoring (main region) - independent
5. OpenHands-Database (main region) - depends on Network, Security
6. OpenHands-Compute (main region) - depends on Network, Security, Monitoring, Database
7. OpenHands-Edge (us-east-1) - depends on Compute, Auth

### Verify Deployment

```bash
# Test site accessibility (should redirect to Cognito login)
curl -s -o /dev/null -w "%{http_code}" https://<subdomain>.<domain-name>

# Check EC2 instance health
aws autoscaling describe-auto-scaling-groups \
  --region <region> \
  --query 'AutoScalingGroups[?contains(Tags[?Key==`Project`].Value, `OpenHands`)].Instances[*].HealthStatus' \
  --output text

# Check target group health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn> \
  --region <region>
```

## E2E Testing with Chrome DevTools

> **Comprehensive Test Cases**: For detailed, step-by-step E2E test cases with acceptance criteria, see [`test/E2E_TEST_CASES.md`](test/E2E_TEST_CASES.md). This file contains:
> - TC-001: Deploy Infrastructure
> - TC-002: Create Test User in Cognito
> - TC-003: Login via Chrome DevTools
> - TC-004: Verify Conversation List
> - TC-005: Start New Conversation
> - TC-006: Execute Flask Todo App Prompt
> - TC-007: Verify Runtime Application Accessible
> - TC-008: Verify In-App Routing

### Prerequisites

1. Chrome DevTools MCP server configured
2. Cognito user created with verified email

### Testing Authentication Flow

1. **Navigate to application**:
   - Open Chrome and navigate to `https://<subdomain>.<domain-name>`
   - Should redirect to Cognito login page

2. **Login with Cognito credentials**:
   - Enter email and password
   - Should redirect back to application after successful login

3. **Verify application state**:
   - Check for `id_token` cookie (HttpOnly, Secure)
   - Application should render correctly

4. **Test logout flow**:
   - Navigate to `https://<subdomain>.<domain-name>/_logout`
   - Should clear cookie and redirect to Cognito logout

### Chrome DevTools MCP Commands

```javascript
// Take snapshot of current page
mcp__chrome-devtools__take_snapshot({})

// Navigate to URL
mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain-name>", type: "url" })

// Fill login form
mcp__chrome-devtools__fill({ uid: "<email-field-uid>", value: "<email>" })
mcp__chrome-devtools__fill({ uid: "<password-field-uid>", value: "<password>" })
mcp__chrome-devtools__click({ uid: "<submit-button-uid>" })

// Check cookies
mcp__chrome-devtools__evaluate_script({
  function: "() => document.cookie"
})

// List network requests
mcp__chrome-devtools__list_network_requests({})

// Take screenshot
mcp__chrome-devtools__take_screenshot({})
```

### Common E2E Test Scenarios

1. **Health Check**: Verify `/api/health` returns 200
2. **Authentication**: Test login, session persistence, logout
3. **CORS**: Verify correct CORS headers
4. **Security Headers**: Check CSP, X-Frame-Options, etc.
5. **Error Handling**: Test 401/403/500 error pages

### Testing Auto-Close Settings Modal & Conversation Creation

When LLM is configured via `config.toml`, the AI Provider Configuration modal should auto-close and default settings should be created automatically. This ensures users can immediately create conversations without manual configuration.

**Test Flow**:

1. **Logout and login fresh**:
   ```javascript
   mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain-name>/_logout", type: "url" })
   // Then login via Cognito
   ```

2. **Verify modal is auto-closed**:
   - Page should show "Let's Start Building!" without modal overlay
   - Console should show "Settings modal removed from DOM"

3. **Verify settings were created**:
   ```javascript
   mcp__chrome-devtools__evaluate_script({
     function: "() => fetch('/api/settings').then(r => r.status)"
   })
   // Should return 200, not 404
   ```

4. **Verify conversation creation works**:
   - Click "New Conversation" button
   - Should NOT return 400 "Settings not found" error
   - Conversation should start successfully

**Expected Console Log Sequence**:
```
OpenHands localhost/host.docker.internal URL fix loaded
OpenHands auto-close settings modal patch loaded
LLM configured via config.toml, checking if settings exist...
Settings not found, creating default settings...
Default settings created successfully
Settings modal removed from DOM
```

**Expected Network Request Sequence**:

| # | Method | URL | Expected Status |
|---|--------|-----|-----------------|
| 1 | GET | `/api/options/models` | 200 |
| 2 | GET | `/api/settings` | 404 |
| 3 | POST | `/api/settings` | 200/201 |
| 4 | POST | `/api/conversations` | 200 ✅ |

**Related files**:
- `docker/patch-fix.js` - Frontend JavaScript patches injected at container startup
- `docker/apply-patch.sh` - Shell script that applies patches to index.html

### Testing Conversation Functionality (Full E2E)

This test verifies that a new conversation works correctly end-to-end, including workspace connectivity, git integration, and AI agent response with runtime URL rewriting.

**Prerequisites**:
- Logged into the application
- Chrome DevTools MCP server connected

**Test Flow**:

#### Step 1: Create New Conversation

```javascript
// Navigate to home page and click "Start new conversation"
mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain-name>", type: "url" })
mcp__chrome-devtools__take_snapshot({})
// Click the "Start new conversation" link (uid from snapshot)
mcp__chrome-devtools__click({ uid: "<start-new-conversation-uid>" })
```

#### Step 2: Verify Chatbox Connected

Wait for the conversation to load and verify the chatbox shows "Waiting for task" status.

```javascript
// Wait for conversation page to load
mcp__chrome-devtools__wait_for({ text: "What do you want to build?", timeout: 30000 })
mcp__chrome-devtools__take_snapshot({})
```

**Expected UI Elements**:
- StaticText "What do you want to build?" - input prompt visible
- StaticText "Waiting for task" - agent is ready
- Button "Changes" - git panel available

#### Step 3: Verify Changes Panel Loads Workspace

Click the "Changes" button and verify it loads without errors.

```javascript
// Click Changes button (get uid from snapshot)
mcp__chrome-devtools__click({ uid: "<changes-button-uid>" })
mcp__chrome-devtools__take_snapshot({})
// Check network requests for git API
mcp__chrome-devtools__list_network_requests({ resourceTypes: ["xhr", "fetch"] })
```

**Expected Results**:
| Check | Expected |
|-------|----------|
| Network: `/api/conversations/.../git/changes` | 200 OK |
| Changes panel | Shows workspace files (e.g., `.vscode/settings.json`) |
| No 500 errors | Git path regression fixed |

**Console Verification** (if git paths were rewritten):
```
Fetch patched: http://localhost:xxxxx/api/git/changes/... -> https://.../runtime/xxxxx/api/git/changes/.
```

#### Step 4: Send Flask App Request and Verify Response

Submit a task to the AI agent and verify it responds correctly.

```javascript
// Type in the chat input
mcp__chrome-devtools__fill({ uid: "<chat-input-uid>", value: "Create a simple Flask app that returns 'Hello World' and run it on port 5000" })
// Click send button or press Enter
mcp__chrome-devtools__click({ uid: "<send-button-uid>" })
// Or use keyboard
mcp__chrome-devtools__press_key({ key: "Enter" })
```

**Wait for AI Response**:
```javascript
// Wait for agent to start responding (status changes from "Waiting for task")
mcp__chrome-devtools__wait_for({ text: "Running", timeout: 60000 })
// Take snapshot to see agent progress
mcp__chrome-devtools__take_snapshot({})
```

#### Step 5: Verify Runtime URL Rewriting

When the AI agent runs the Flask app and outputs the URL, verify it's rewritten to the accessible path-based URL.

```javascript
// Wait for the Flask app to be running
mcp__chrome-devtools__wait_for({ text: "runtime", timeout: 120000 })
mcp__chrome-devtools__take_snapshot({})
// Check console for URL rewriting
mcp__chrome-devtools__list_console_messages({})
```

**Expected URL Display**:
| Original (localhost) | Rewritten (accessible) |
|---------------------|------------------------|
| `http://localhost:5000` | `https://5000-<convId>.runtime.<subdomain>.<domain-name>/` |

**Expected Console Logs**:
```
Text URL rewritten: http://localhost:5000 -> https://5000-<convId>.runtime.<subdomain>.<domain-name>/
```

> **Note**: Runtime URLs now use subdomain routing (`{port}-{convId}.runtime.{subdomain}.{domain}`) instead of path-based routing. This ensures internal app routes work correctly since apps run at the domain root.

#### Step 6: Verify Flask App is Accessible

Click the rewritten URL or navigate directly to verify the Flask app is running.

```javascript
// If URL is clickable in chat, click it
mcp__chrome-devtools__click({ uid: "<flask-url-link-uid>" })
// Or navigate directly (using runtime subdomain)
mcp__chrome-devtools__navigate_page({ url: "https://5000-<convId>.runtime.<subdomain>.<domain-name>/", type: "url" })
mcp__chrome-devtools__take_snapshot({})
```

**Expected Result**: Page shows "Hello World" from Flask app.

**Full E2E Test Checklist**:

| # | Test | Verification Method | Expected Result |
|---|------|---------------------|-----------------|
| 1 | Conversation created | URL changes to `/conversations/<id>` | ✅ |
| 2 | Chatbox connected | "Waiting for task" visible | ✅ |
| 3 | Changes panel loads | Network request 200, files displayed | ✅ |
| 4 | Git path correct | No 500 error, no path duplication | ✅ |
| 5 | AI agent responds | Status changes to "Running" | ✅ |
| 6 | URL rewritten | localhost → `{port}-{convId}.runtime.{domain}/` | ✅ |
| 7 | Runtime accessible | Flask app returns "Hello World" | ✅ |
| 8 | In-app routing works | Internal routes resolve correctly | ✅ |

## Post-Infrastructure Change Workflow

**⚠️ MANDATORY: This is a continuous workflow. After deploying infrastructure changes, you MUST immediately proceed to E2E testing WITHOUT waiting for user input. Do not stop, summarize, or ask for confirmation between steps.**

After modifying any infrastructure code in this repository, follow this complete workflow:

### Step 1: Build and Deploy

```bash
# 1. Build TypeScript to catch compile errors
npm run build

# 2. Run tests to verify CDK snapshot integrity
npm run test

# 3. Preview changes (optional but recommended)
npx cdk diff --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context deployRegion=<region>

# 4. Deploy changes
npx cdk deploy --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context deployRegion=<region> \
  --require-approval never
```

**→ IMMEDIATELY proceed to Step 2 after deployment completes. Do NOT stop here.**

### Step 2: E2E Testing with Chrome DevTools (MANDATORY)

**This step is REQUIRED for all infrastructure changes. Proceed immediately after deployment WITHOUT asking the user.**

After deployment completes, verify the portal is accessible with correct credentials using Chrome DevTools MCP:

```javascript
// 1. Navigate to the application
mcp__chrome-devtools__navigate_page({ url: "https://<subdomain>.<domain-name>", type: "url" })

// 2. Wait for redirect to Cognito login and take snapshot
mcp__chrome-devtools__take_snapshot({})

// 3. Fill in Cognito login credentials (get UIDs from snapshot)
mcp__chrome-devtools__fill({ uid: "<email-field-uid>", value: "<cognito-user-email>" })
mcp__chrome-devtools__fill({ uid: "<password-field-uid>", value: "<cognito-user-password>" })

// 4. Click sign-in button
mcp__chrome-devtools__click({ uid: "<signin-button-uid>" })

// 5. Wait for redirect back to application
mcp__chrome-devtools__wait_for({ text: "OpenHands", timeout: 10000 })

// 6. Take screenshot to verify successful login
mcp__chrome-devtools__take_screenshot({})

// 7. Verify authentication cookie is set
mcp__chrome-devtools__evaluate_script({
  function: "() => document.cookie.includes('id_token')"
})
```

**→ IMMEDIATELY proceed to Step 3 verification. Do NOT stop here.**

### Step 3: Verification Checklist

After E2E testing, verify the following:

| Check | Expected Result |
|-------|-----------------|
| Initial URL access | 302 redirect to Cognito login |
| Cognito login page | Renders correctly with email/password fields |
| After login | Redirects back to application with `id_token` cookie |
| Application page | Renders OpenHands interface correctly |
| Logout (`/_logout`) | Clears cookie and redirects to Cognito logout |
| Cookie attributes | `HttpOnly`, `Secure`, `SameSite=Lax` |

**→ IMMEDIATELY proceed to Step 4 for full functionality verification. Do NOT stop here.**

### Step 4: Full Functionality Verification (REQUIRED)

**CRITICAL**: Before marking any deployment as complete, you MUST verify all of the following:

| # | Verification Step | How to Verify | Expected Result |
|---|-------------------|---------------|-----------------|
| 1 | **Login portal without error** | Navigate to `https://<subdomain>.<domain-name>`, login with Cognito credentials | Home page loads without errors, no console errors |
| 2 | **Conversations can be listed/fetched** | Check Network tab for `GET /api/conversations?limit=10` | Returns 200 OK with JSON array (empty `[]` is OK for new users) |
| 3 | **Create new conversation and wait for ready** | Click "Start new conversation" or "New Conversation" button | Conversation creates, status reaches "Waiting for task" within 2-5 minutes |
| 4 | **Agent processes request properly** | Type a simple request like "What is 2+2?" and press Enter | Agent responds with answer, no errors in conversation |

**If ANY of these verifications fail, the deployment is NOT complete. Investigate and fix before proceeding.**

### Step 5: Report Results and Complete

**Only after ALL verification steps pass**, report the E2E test results:

```markdown
## E2E Test Results

| Step | Test | Result |
|------|------|--------|
| 1 | Login portal | ✅ PASS |
| 2 | Conversation list | ✅ PASS |
| 3 | New conversation | ✅ PASS |
| 4 | Agent response | ✅ PASS |

All E2E tests passed. Deployment verified.
```

**The task is NOT complete until this report is provided with all tests passing.**

#### Quick Verification Commands (SSH to EC2)

```bash
# Get instance ID
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names OpenHands-Compute-OpenHandsAsgASG16C624EA-CyJw2oPLGP43 \
  --region us-west-2 \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text)

# SSH via SSM
aws ssm start-session --target $INSTANCE_ID --region us-west-2

# Check all patches applied
docker logs openhands-app 2>&1 | grep -i patch

# Check for database errors
docker logs openhands-app 2>&1 | grep -iE "(error|exception|failed)" | tail -20

# Check PostgreSQL connection
docker logs openhands-app 2>&1 | grep -i "alembic"
# Should show: "Context impl PostgresqlImpl" and "Will assume transactional DDL"

# Check API requests
docker logs openhands-app 2>&1 | grep "/api/conversations" | tail -10
```

### Troubleshooting Common Issues

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| "Token verification failed" | JWK to PEM conversion error | Check `jwkToPem` function in edge-stack.ts |
| 502 Bad Gateway | ALB target unhealthy | Check EC2 instance health and security groups |
| Redirect loop | Cookie not being set | Check cookie domain and path settings |
| CORS errors | Missing headers | Check CloudFront response headers policy |
| CloudFront 403 | WAF blocking request | Check WAF rules and logs |

### Lambda@Edge Log Locations

Lambda@Edge logs appear in CloudWatch in the **region closest to the user**, not us-east-1:

```bash
# Find Lambda@Edge logs (check multiple regions)
for region in us-east-1 us-west-2 eu-west-1 ap-northeast-1; do
  aws logs describe-log-groups \
    --log-group-name-prefix '/aws/lambda/us-east-1.OpenHands-Edge' \
    --region "$region" \
    --query 'logGroups[].logGroupName' \
    --output text
done

# Get recent logs
aws logs tail '/aws/lambda/us-east-1.OpenHands-Edge-AuthFunction<suffix>' \
  --region <user-region> \
  --since 1h
```

## Architecture Deep Dive

This section provides detailed knowledge about the authentication, database, and conversation storage systems that enable self-healing across EC2 instance replacements.

### Authentication System

#### Request Flow

```
User Request
    ↓
CloudFront (Edge)
    ↓
Lambda@Edge (JWT Validation)
    ↓ (if valid)
Inject User Headers (X-Cognito-*)
    ↓
Origin (ALB → EC2)
    ↓
OpenHands App (CognitoUserAuth)
```

#### Cognito User Pool (`lib/edge-stack.ts`)

| Setting | Value | Notes |
|---------|-------|-------|
| Location | us-east-1 | Required for Lambda@Edge |
| Sign-up | Disabled | Admin creates users |
| Sign-in | Email-based | |
| Password Policy | 12+ chars | Uppercase, lowercase, numbers, symbols |
| MFA | Optional TOTP | |
| Access Token | 1 hour | API access |
| ID Token | 1 day | Identity (stored in cookie) |
| Refresh Token | 30 days | Session persistence |

#### Lambda@Edge Authentication (`lib/edge-stack.ts:168-558`)

Three authentication flows:

1. **OAuth Callback (`/_callback`)**: Receives auth code → exchanges for tokens → verifies ID token signature via JWKS → sets `id_token` cookie (HttpOnly, Secure, SameSite=Lax) → redirects to destination

2. **Logout (`/_logout`)**: Clears `id_token` cookie → redirects to Cognito logout URL

3. **Request Validation**: Extracts `id_token` from cookie → verifies JWT signature against Cognito JWKS → validates issuer, expiration, audience → **injects user headers** → redirects to login if invalid

#### User Header Injection (`lib/edge-stack.ts:527-546`)

**Critical for conversation persistence**: Lambda@Edge injects verified user information into request headers:

```javascript
// Clear any existing headers to prevent spoofing
delete request.headers['x-cognito-user-id'];
delete request.headers['x-cognito-email'];
delete request.headers['x-cognito-email-verified'];

// Inject verified user information
request.headers['x-cognito-user-id'] = [{
  key: 'X-Cognito-User-Id',
  value: payload.sub  // Cognito user ID (UUID)
}];
request.headers['x-cognito-email'] = [{
  key: 'X-Cognito-Email',
  value: payload.email || ''
}];
```

#### CognitoUserAuth Class (OpenHands Backend)

Configuration in `lib/compute-stack.ts:480`:
```yaml
- USER_AUTH_CLASS=openhands.server.user_auth.cognito_user_auth.CognitoUserAuth
```

The OpenHands app reads injected headers:
```python
class CognitoUserAuth(DefaultUserAuth):
    async def get_user_id(self) -> str | None:
        return self._user_id  # From X-Cognito-User-Id header

    @classmethod
    async def get_instance(cls, request: Request) -> UserAuth:
        user_id = request.headers.get('x-cognito-user-id')
        email = request.headers.get('x-cognito-email')
        # ...
```

#### Security Measures

- **Header Spoofing Prevention**: Lambda@Edge clears existing `x-cognito-*` headers before setting verified values
- **JWKS Signature Verification**: Full RS256 signature verification against Cognito's public keys
- **Token Validation**: Issuer, expiration, and audience validated
- **HttpOnly Cookies**: Token cookies cannot be accessed by JavaScript
- **WAF Protection**: AWS WAF rules protect against common attacks

### Database Architecture

#### Aurora Serverless v2 Configuration (`lib/database-stack.ts`)

| Setting | Value | Notes |
|---------|-------|-------|
| Engine | PostgreSQL 15.4 | Aurora Serverless v2 |
| Min ACU | 0.5 | ~$43/month minimum |
| Max ACU | 4 | Auto-scales with usage |
| IAM Auth | Enabled | No passwords required |
| Encryption | Yes | At-rest encryption |
| Backup | 35 days | Automatic daily backups |
| Removal Policy | SNAPSHOT | Creates backup on deletion |

#### IAM Database Authentication

**Why IAM Auth?**
- No passwords to store, rotate, or manage
- EC2 uses its IAM role for authentication
- Tokens expire after 15 minutes (auto-refreshed)
- Audit trail via CloudTrail

**Token Generation Flow** (`lib/compute-stack.ts:564-638`):

1. **Systemd Timer**: Runs every 10 minutes
2. **Token Script**: `/usr/local/bin/refresh-db-token.sh`
3. **AWS CLI**: `aws rds generate-db-auth-token`
4. **Output**: `/data/openhands/config/database.env`

```bash
# Generated DATABASE_URL format
DATABASE_URL=postgresql://openhands_iam:<iam-token>@<cluster-endpoint>:5432/openhands?sslmode=require
```

#### IAM Policy for RDS Connect (`lib/compute-stack.ts:259-273`)

```typescript
new iam.PolicyStatement({
  actions: ['rds-db:connect'],
  resources: [
    `arn:aws:rds-db:${region}:${account}:dbuser:${clusterResourceId}/${databaseUser}`,
  ],
});
```

#### Database User Setup (One-Time)

After first deployment, the IAM database user must be created in PostgreSQL. This is a **one-time setup** that persists across all subsequent deployments.

**Step 1: Get admin credentials from Secrets Manager**

```bash
aws secretsmanager get-secret-value \
  --secret-id openhands/database/admin \
  --region <region> \
  --query 'SecretString' --output text | jq -r '.password'
```

**Step 2: Connect to database via EC2 (Session Manager)**

```bash
# Get EC2 instance ID
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names OpenHands-ASG \
  --region <region> \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text)

# Connect via SSM
aws ssm start-session --target $INSTANCE_ID --region <region>

# On EC2, connect to PostgreSQL
PGPASSWORD='<admin-password>' psql \
  -h <cluster-endpoint> \
  -U postgres \
  -d openhands
```

**Step 3: Create IAM user and grant permissions**

```sql
-- Create the IAM authentication user
CREATE USER openhands_iam;
GRANT rds_iam TO openhands_iam;

-- Grant database-level permissions
GRANT ALL PRIVILEGES ON DATABASE openhands TO openhands_iam;

-- Grant schema-level permissions (required for table access)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO openhands_iam;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO openhands_iam;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO openhands_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO openhands_iam;
```

**Verification**: After setup, the EC2 instance should connect automatically using IAM tokens (refreshed every 10 minutes via systemd timer).

### Conversation Storage

#### Storage Locations

| Data Type | Storage | Persistence | Notes |
|-----------|---------|-------------|-------|
| Conversation Metadata | Aurora PostgreSQL | Permanent | User ID, title, timestamps |
| Conversation Events | S3 | Permanent | Agent actions, tool outputs |
| User Settings | S3 | Permanent | LLM config, preferences |
| Workspace Files | EFS | Persistent | Code, project files (`/data/openhands/workspace`) |

#### Storage Path Logic (OpenHands)

```python
# openhands/storage/locations.py
def get_conversation_dir(sid, user_id=None):
    if user_id:
        return f'users/{user_id}/conversations/{sid}/'  # User-specific path
    else:
        return f'sessions/{sid}/'  # Fallback (no user)
```

**Important**: Without proper `user_id` from CognitoUserAuth, conversations would be stored in `sessions/` and not associated with any user.

#### S3 File Store Configuration (`lib/compute-stack.ts:485-488`)

```yaml
environment:
  - FILE_STORE=s3
  - FILE_STORE_PATH=<bucket-name>
  - AWS_S3_BUCKET=<bucket-name>
```

#### S3 Bucket Security (`lib/monitoring-stack.ts`)

| Setting | Value | Purpose |
|---------|-------|---------|
| Encryption | SSE-S3 | At-rest encryption |
| Versioning | Enabled | 30-day retention for old versions |
| Public Access | Blocked | All public access blocked |
| SSL | Enforced | HTTPS only |
| Removal Policy | RETAIN | Data preserved if stack deleted |

### Self-Healing Data Flow

When a new EC2 instance launches:

1. **User Data Script** runs:
   - Installs Docker, CloudWatch Agent
   - Formats fresh EBS volume
   - Generates IAM auth token for Aurora
   - Starts OpenHands container

2. **OpenHands Startup**:
   - Connects to Aurora (IAM auth)
   - Loads existing conversation metadata
   - Connects to S3 for conversation events

3. **User Access**:
   - Authenticates via Cognito (unchanged)
   - Lambda@Edge injects user headers
   - OpenHands retrieves user's conversations from Aurora
   - User sees all previous conversations

### Testing Self-Healing

```bash
# 1. Create a conversation in the application

# 2. Force instance replacement
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id <instance-id> \
  --should-decrement-desired-capacity false \
  --region <region>

# 3. Wait for new instance (5-10 minutes)
watch -n 10 "aws autoscaling describe-auto-scaling-groups \
  --query 'AutoScalingGroups[0].Instances[*].[InstanceId,HealthStatus]' \
  --output table"

# 4. Verify conversations persist
# - Log in to application
# - Previous conversations should be visible
```

## Security Scanning

### Run Local Security Check

```bash
chmod +x security-check.sh
./security-check.sh
```

This script checks for:
- Hardcoded secrets in Lambda@Edge
- Path traversal vulnerabilities
- Overly permissive IAM policies
- User data injection risks
- Security headers configuration
- KMS key configuration
- Secrets in git history
- Environment file exposure
- NPM dependency vulnerabilities

### CI/CD Security Scanning

The `.github/workflows/security-scan.yml` workflow runs automatically on:
- Push to main/develop branches
- Pull requests to main
- Daily at 2 AM UTC

It includes:
- npm audit
- Checkov (IaC scanning)
- git-secrets
- Semgrep SAST
- OWASP Dependency Check
- cfn-lint
