# Architecture Deep Dive

This document provides detailed technical knowledge about the authentication, database, and conversation storage systems that enable self-healing across EC2 instance replacements.

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
Origin (ALB → EC2)
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

Three authentication flows handled by `lib/lambda-edge/auth-handler.js`:

1. **OAuth Callback (`/_callback`)**: Receives auth code → exchanges for tokens → verifies ID token signature via JWKS → sets `id_token` cookie (HttpOnly, Secure, SameSite=Lax) → redirects to destination

2. **Logout (`/_logout`)**: Clears `id_token` cookie → redirects to Cognito logout URL

3. **Request Validation**: Extracts `id_token` from cookie → verifies JWT signature against Cognito JWKS → validates issuer, expiration, audience → **injects user headers** → redirects to login if invalid

### User Header Injection

**Critical for conversation persistence**: Lambda@Edge injects verified user information into request headers, clearing any existing headers to prevent spoofing:

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
| Engine | PostgreSQL 15.4 | Aurora Serverless v2 |
| Min ACU | 0.5 | ~$43/month minimum |
| Max ACU | 4 | Auto-scales with usage |
| IAM Auth | Enabled | No passwords required |
| Encryption | Yes | At-rest encryption |
| Backup | 35 days | Automatic daily backups |
| Removal Policy | SNAPSHOT | Creates backup on deletion |

### IAM Database Authentication

**Why IAM Auth?**
- No passwords to store, rotate, or manage
- EC2 uses its IAM role for authentication
- Tokens expire after 15 minutes (auto-refreshed)
- Audit trail via CloudTrail

**Token Generation Flow**:
1. **Systemd Timer**: Runs every 10 minutes
2. **Token Script**: `/usr/local/bin/refresh-db-token.sh`
3. **AWS CLI**: `aws rds generate-db-auth-token`
4. **Output**: `/data/openhands/config/database.env`

### Database User Setup (One-Time)

After first deployment, create the IAM database user in PostgreSQL:

```sql
-- Create the IAM authentication user
CREATE USER openhands_iam;
GRANT rds_iam TO openhands_iam;

-- Grant database-level permissions
GRANT ALL PRIVILEGES ON DATABASE openhands TO openhands_iam;

-- Grant schema-level permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO openhands_iam;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO openhands_iam;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO openhands_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO openhands_iam;
```

## Conversation Storage

### Storage Locations

| Data Type | Storage | Persistence | Notes |
|-----------|---------|-------------|-------|
| Conversation Metadata | Aurora PostgreSQL | Permanent | User ID, title, timestamps |
| Conversation Events | S3 | Permanent | Agent actions, tool outputs |
| User Settings | S3 | Permanent | LLM config, preferences |
| Workspace Files | EFS | Persistent | Code, project files (`/data/openhands/workspace`) |

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
