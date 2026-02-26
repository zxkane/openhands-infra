# Architecture Deep Dive

This document provides detailed technical knowledge about the authentication, database, sandbox orchestration, and conversation storage systems that enable self-healing across ECS Fargate task replacements.

## Architecture Overview (10 Stacks)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           us-east-1                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ AuthStack: Cognito User Pool, managed login branding             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    │                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ EdgeStack: Lambda@Edge, CloudFront, WAF, Route 53                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (HTTP Origin)
┌─────────────────────────────────────────────────────────────────────────┐
│                           Main Region                                    │
│                                                                          │
│  ┌───────────────┐    ┌────────────────┐    ┌──────────────────┐        │
│  │ NetworkStack  │───▶│ SecurityStack  │───▶│ MonitoringStack  │        │
│  │ VPC, Endpoints│    │ Fargate roles  │    │ Logs, S3, Alarms │        │
│  └───────────────┘    │ SGs, KMS       │    └──────────────────┘        │
│         │             └────────────────┘           │                    │
│         │                    │                      │                    │
│         ▼                    ▼                      │                    │
│  ┌──────────────┐  ┌───────────────────────┐       │                    │
│  │ ClusterStack │  │    DatabaseStack       │       │                    │
│  │ ECS Cluster  │  │  Aurora Serverless v2  │       │                    │
│  │ Cloud Map    │  │  RDS Proxy             │       │                    │
│  └──────────────┘  └───────────────────────┘       │                    │
│         │                   │                      │                    │
│         ├──────▶ ┌──────────────────────────────────────┐              │
│         │        │           SandboxStack                │              │
│         │        │  DynamoDB, Orchestrator, Sandbox Tasks │              │
│         │        │  Idle Monitor, Task State Lambda       │              │
│         │        └──────────────────────────────────────┘              │
│         │                   │                                           │
│         ▼                   ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      ComputeStack                                │    │
│  │   Fargate Services (App + OpenResty), ALB, EFS, Lambda TG       │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Authentication System

### Request Flow

```
User Request
    ↓
CloudFront (Edge)
    ↓
Lambda@Edge (JWT Validation)
    ↓ (if valid)
Inject User Headers (X-Cognito-*)
    ↓
Origin (ALB → Fargate)
    ↓
OpenHands App (CognitoUserAuth)
```

### Cognito User Pool Configuration

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

### Lambda@Edge Authentication Flows

Four authentication flows handled by `lib/lambda-edge/auth-handler.js`:

1. **OAuth Callback (`/_callback`)**: Receives auth code → exchanges for tokens → verifies ID token signature via JWKS → sets `id_token` cookie (HttpOnly, Secure, SameSite=Lax) → redirects to destination

2. **Logout (`/_logout`)**: Clears `id_token` cookie → redirects to Cognito logout URL

3. **Runtime Subdomain**: Verify JWT → inject `X-Cognito-User-Id` → rewrite URI to `/runtime/{convId}/{port}/...` → allow/redirect

4. **Main Domain Request Validation**: Extracts `id_token` from cookie → verifies JWT signature against Cognito JWKS → validates issuer, expiration, audience → **injects user headers** → redirects to login if invalid

### User Header Injection

**Critical for conversation persistence and multi-tenant isolation**: Lambda@Edge injects verified user information into request headers, clearing any existing headers to prevent spoofing:

- `X-Cognito-User-Id`: Cognito user ID (UUID from `payload.sub`)
- `X-Cognito-Email`: User's email address

### CognitoUserAuth Class

The OpenHands backend reads injected headers via `CognitoUserAuth` class configured in `lib/compute-stack.ts`:
```yaml
USER_AUTH_CLASS=openhands.server.user_auth.cognito_user_auth.CognitoUserAuth
```

### Security Measures

- **Header Spoofing Prevention**: Lambda@Edge clears existing `x-cognito-*` headers before setting verified values
- **JWKS Signature Verification**: Full RS256 signature verification against Cognito's public keys
- **Token Validation**: Issuer, expiration, and audience validated
- **HttpOnly Cookies**: Token cookies cannot be accessed by JavaScript
- **WAF Protection**: AWS WAF rules protect against common attacks

## Database Architecture

### Aurora Serverless v2 Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Engine | PostgreSQL 15.8 | Aurora Serverless v2 |
| Min ACU | 0.5 | ~$43/month minimum |
| Max ACU | 4 | Auto-scales with usage |
| IAM Auth | Enabled (backup) | For direct cluster admin access |
| Encryption | Yes | At-rest encryption |
| Backup | 35 days | Automatic daily backups |
| Removal Policy | SNAPSHOT | Creates backup on deletion |

### Database Authentication

**Primary: RDS Proxy with Password Auth**

The application connects through RDS Proxy using password-based authentication via Secrets Manager:

1. **DatabaseStack** creates a proxy user with credentials stored in Secrets Manager (`openhands/database/proxy-user`)
2. **RDS Proxy** handles connection pooling and credential rotation
3. **Fargate App Service** receives the DB password via ECS native secret injection
4. No token refresh needed — RDS Proxy manages connection lifecycle

**Backup: IAM Authentication**

IAM auth is also enabled on the cluster for direct admin access:
- Used by the DB bootstrap Lambda (custom resource) for one-time setup
- Can be used for manual admin tasks via `aws rds generate-db-auth-token`

### Database Bootstrap (Automated)

The `db-bootstrap` Lambda function (custom resource) automatically runs on first deployment:
- Creates the proxy user with appropriate permissions
- Grants schema-level permissions for future tables
- No manual SQL setup required

## Sandbox Orchestration

### Architecture

```
App Service → Orchestrator Lambda (via Cloud Map DNS)
                     ↓
              DynamoDB Registry ← EventBridge (idle monitor, task state)
                     ↓
              ECS Fargate Tasks (per-conversation sandbox)
                     ↓
              EFS Access Points (per-conversation isolation)
```

### Sandbox Lifecycle

| Action | Trigger | What Happens |
|--------|---------|-------------|
| **Start** | User creates conversation | Orchestrator: create EFS AP → register task def → RunTask → update DynamoDB |
| **Resume** | User resumes archived conversation | Same as Start (AP may already exist) |
| **Stop** | User stops conversation | Orchestrator: StopTask → cleanup AP |
| **Idle Timeout** | EventBridge (5-min schedule) | Idle Monitor Lambda: detect stale tasks → StopTask → delete AP |
| **Task Crash** | ECS task state change event | Task State Lambda: update DynamoDB → delete AP |

### DynamoDB Sandbox Registry

| Attribute | Type | Description |
|-----------|------|-------------|
| `conversation_id` | PK | Conversation UUID |
| `user_id` | GSI | For user-scoped queries |
| `status` | GSI | RUNNING, STOPPED, etc. |
| `task_arn` | String | ECS Fargate task ARN |
| `access_point_id` | String | EFS access point ID |
| `task_definition_arn` | String | Per-conversation task def |
| `last_activity_at` | Number | Unix timestamp for idle detection |

### Per-Conversation EFS Isolation

Each sandbox mounts an EFS access point rooted at `/sandbox-workspace/<conversation_id>/`:
- Container sees `/mnt/efs/` = access point root (cannot traverse to parent/sibling directories)
- Workspace files at `/mnt/efs/workspace/` persist across task restarts
- SDK conversation cache at `/mnt/efs/<CID_hex>/events/` enables LLM context restoration

## Conversation Storage

### Storage Locations

| Data Type | Storage | Written By | Persistence |
|-----------|---------|-----------|-------------|
| Conversation Metadata | Aurora PostgreSQL | App server | Permanent |
| Conversation Events | S3 (`FILE_STORE=s3`) | App server | Permanent (authority for UI) |
| User Settings / Secrets | S3 | App server | Permanent (KMS encrypted) |
| Workspace Files | EFS | Sandbox agent-server | Persistent (per-conversation AP) |
| SDK Conversation Cache | EFS | Sandbox SDK | Persistent (LLM context restoration) |
| Sandbox State | DynamoDB | Orchestrator | Permanent (task registry) |

### Storage Path Logic

```python
# openhands/storage/locations.py
def get_conversation_dir(sid, user_id=None):
    if user_id:
        return f'users/{user_id}/conversations/{sid}/'  # User-specific path
    else:
        return f'sessions/{sid}/'  # Fallback (no user)
```

**Important**: Without proper `user_id` from CognitoUserAuth, conversations would be stored in `sessions/` and not associated with any user.

### S3 Bucket Security

| Setting | Value | Purpose |
|---------|-------|---------|
| Encryption | SSE-S3 | At-rest encryption |
| Versioning | Enabled | 30-day retention for old versions |
| Public Access | Blocked | All public access blocked |
| SSL | Enforced | HTTPS only |
| Removal Policy | RETAIN | Data preserved if stack deleted |

## Self-Healing Data Flow

When a Fargate task is replaced (deployment, scaling, health check failure):

1. **ECS Service** launches new task:
   - Fargate pulls container images from ECR
   - Mounts EFS app workspace at `/data/openhands`
   - Injects secrets via ECS native secret injection (DB password, sandbox secret key)

2. **OpenHands App Startup**:
   - Connects to Aurora via RDS Proxy (password auth, no token refresh)
   - Loads existing conversation metadata
   - Connects to S3 for conversation events

3. **User Access**:
   - Authenticates via Cognito (unchanged)
   - Lambda@Edge injects user headers
   - OpenHands retrieves user's conversations from Aurora
   - User sees all previous conversations

4. **Sandbox Resume**:
   - When user accesses an archived conversation, orchestrator creates new sandbox task
   - EFS access point preserves workspace files from previous session
   - SDK conversation cache enables LLM context restoration

### Testing Self-Healing

```bash
# 1. Create a conversation in the application

# 2. Force Fargate app service redeployment
aws ecs update-service --cluster <cluster-name> \
  --service openhands-app --force-new-deployment \
  --region <region>

# 3. Wait for new task to stabilize (2-5 minutes)
aws ecs describe-services --cluster <cluster-name> \
  --services openhands-app \
  --query 'services[0].{running:runningCount,desired:desiredCount,pending:pendingCount}' \
  --region <region>

# 4. Verify conversations persist
# - Log in to application
# - Previous conversations should be visible
# - Resume an archived conversation to verify workspace files persist
```
