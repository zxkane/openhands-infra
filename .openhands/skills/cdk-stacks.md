---
triggers:
- stack
- cdk stack
- network-stack
- compute-stack
- auth-stack
- edge-stack
- database-stack
- aurora
- lambda@edge
---

# lib/CLAUDE.md - Stack Implementation Reference

This document provides implementation details for the CDK stack files in this directory.

## Stack Architecture (7 Stacks)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           us-east-1                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ AuthStack: Cognito User Pool, managed login branding             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                    │                                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ EdgeStack: Lambda@Edge, CloudFront (VPC Origin), WAF, Route 53   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (VPC Origin)
┌─────────────────────────────────────────────────────────────────────────┐
│                           Main Region (us-west-2)                        │
│                                                                          │
│  ┌───────────────┐    ┌────────────────┐    ┌──────────────────┐        │
│  │ NetworkStack  │───▶│ SecurityStack  │───▶│ MonitoringStack  │        │
│  │ VPC, Endpoints│    │ IAM, SGs       │    │ Logs, S3, Alarms │        │
│  └───────────────┘    └────────────────┘    └──────────────────┘        │
│         │                    │                      │                    │
│         ▼                    ▼                      │                    │
│  ┌─────────────────────────────────────┐           │                    │
│  │         DatabaseStack               │           │                    │
│  │   Aurora Serverless v2 PostgreSQL   │           │                    │
│  │        (IAM Authentication)         │           │                    │
│  └─────────────────────────────────────┘           │                    │
│                      │                              │                    │
│                      ▼                              ▼                    │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      ComputeStack                                │    │
│  │   EC2 ASG (Graviton), Internal ALB, nginx runtime proxy         │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## File Reference

| File | Purpose | Key Resources |
|------|---------|---------------|
| `interfaces.ts` | TypeScript interfaces for stack I/O | OpenHandsConfig, *StackOutput |
| `network-stack.ts` | VPC import, VPC Endpoints | SSM, ECR, S3, Logs endpoints |
| `security-stack.ts` | IAM roles, Security Groups | EC2 role, ALB SG, EC2 SG |
| `monitoring-stack.ts` | Observability & data store | CloudWatch, S3 data bucket |
| `database-stack.ts` | Persistent storage | Aurora Serverless v2, IAM auth |
| `compute-stack.ts` | Application runtime | EC2 ASG, Internal ALB, User Data |
| `auth-stack.ts` | Shared authentication | Cognito User Pool, managed login |
| `edge-stack.ts` | Edge & CDN | Lambda@Edge, CloudFront, WAF, Route 53 |

## Stack Dependencies

```typescript
// bin/openhands-infra.ts
securityStack.addDependency(networkStack);
securityStack.addDependency(monitoringStack);
databaseStack.addDependency(networkStack);
databaseStack.addDependency(securityStack);
computeStack.addDependency(networkStack);
computeStack.addDependency(securityStack);
computeStack.addDependency(monitoringStack);
computeStack.addDependency(databaseStack);
edgeStack.addDependency(computeStack);
edgeStack.addDependency(authStack);  // Uses Cognito from AuthStack
```

## interfaces.ts

Defines typed contracts between stacks:

```typescript
interface OpenHandsConfig {
  vpcId: string;           // Existing VPC
  hostedZoneId: string;    // Route 53 zone
  domainName: string;      // e.g., example.com
  subDomain: string;       // e.g., openhands
  region: string;          // Main deployment region
}

interface DatabaseStackOutput {
  clusterEndpoint: string;    // Aurora cluster DNS
  clusterPort: string;        // 5432
  clusterResourceId: string;  // For IAM auth ARN
  databaseName: string;       // openhands
  databaseUser: string;       // openhands_iam
  securityGroupId: string;    // Aurora SG
}
```

## database-stack.ts

### Aurora Serverless v2 with IAM Authentication

**Why IAM Auth?**
- No passwords to manage or rotate
- EC2 uses its IAM role to generate short-lived tokens
- Audit trail via CloudTrail

**Configuration:**
```typescript
serverlessV2MinCapacity: 0.5,  // ~$43/month minimum
serverlessV2MaxCapacity: 4,     // Auto-scales with load
iamAuthentication: true,        // No password needed
```

### One-Time Database Setup

After first deployment, create the IAM user in PostgreSQL:

```bash
# 1. Get admin credentials from Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id openhands/database/admin \
  --region <region> \
  --query 'SecretString' --output text | jq -r '.password'

# 2. Connect to database (via SSM Session Manager on EC2)
PGPASSWORD='<admin-password>' psql \
  -h <cluster-endpoint> \
  -U postgres \
  -d openhands

# 3. Create IAM user and grant permissions
CREATE USER openhands_iam;
GRANT rds_iam TO openhands_iam;
GRANT ALL PRIVILEGES ON DATABASE openhands TO openhands_iam;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO openhands_iam;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO openhands_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO openhands_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO openhands_iam;
```

## compute-stack.ts

### User Data Script (16KB Limit)

EC2 user data is limited to 16KB. The script is compacted using `\n` in template literals:

```typescript
// Compact format (fits in 16KB)
`cat > /etc/systemd/system/openhands.service << SERVICE\n[Unit]\nDescription=...\nSERVICE`,

// NOT verbose format (exceeds 16KB)
'cat > /etc/systemd/system/openhands.service << SERVICE',
'[Unit]',
'Description=...',
'SERVICE',
```

### IAM Token Refresh

Aurora IAM tokens expire every 15 minutes. A systemd timer refreshes every 10 minutes:

```typescript
// Token refresh script location
'/usr/local/bin/refresh-db-token.sh'

// Output file consumed by OpenHands
'/data/openhands/config/database.env'
// Contains: DATABASE_URL=postgresql://openhands_iam:<token>@<host>:5432/openhands?sslmode=require

// Systemd timer
'db-token-refresh.timer'  // Runs every 10 minutes
```

### Docker Image Versions

```typescript
const DEFAULT_OPENHANDS_VERSION = '1.1.0';
const DEFAULT_RUNTIME_VERSION = '1.1-nikolaik';
```

Update these when upgrading OpenHands.

### nginx Runtime Proxy (Port 8080)

Proxies `/runtime/{port}/` to localhost containers (simplified example):

```nginx
location ~ ^/runtime/(?<target_port>\d+)(?<remaining_path>/.*)?$ {
    set $proxy_path $remaining_path;
    if ($proxy_path = "") {
        set $proxy_path "/";
    }
    proxy_pass http://127.0.0.1:$target_port$proxy_path;
}
```

Note: The actual implementation in `docker/openresty/nginx.conf` includes additional 
logic for container discovery via Docker API and user authorization.

**Dynamic Port Support**: Agent-server containers run with `network_mode='host'` (via Patch 7 in apply-patch.sh), allowing dynamic ports from user applications (Flask apps, etc.) to be accessible via `/runtime/{port}/`.

## edge-stack.ts

### Lambda@Edge JWT Validation

Four authentication flows:

1. **`/_callback`**: OAuth code → tokens → set cookie → redirect
2. **`/_logout`**: Clear cookie → Cognito logout
3. **Runtime subdomain**: Verify JWT → inject `X-Cognito-User-Id` → rewrite URI → allow/redirect
4. **Main domain**: Verify JWT → inject headers → allow/redirect

### User Header Injection

Lambda@Edge injects verified user info (prevents spoofing):

```typescript
// Clear existing headers first
delete request.headers['x-cognito-user-id'];
delete request.headers['x-cognito-email'];

// Inject verified values
request.headers['x-cognito-user-id'] = [{ value: payload.sub }];
request.headers['x-cognito-email'] = [{ value: payload.email }];
```

OpenHands reads these via `CognitoUserAuth` class.

### CloudFront VPC Origin

Direct connection to internal ALB (no public ALB needed):

```typescript
const vpcOrigin = new cloudfront.origins.VpcOrigin(alb, {
  protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
  httpPort: 80,
});
```

## Common Operations

### Verify Database Connectivity

```bash
# SSH to EC2
aws ssm start-session --target <instance-id> --region <region>

# Check token refresh
cat /data/openhands/config/database.env

# Test connection
source /data/openhands/config/database.env
psql "$DATABASE_URL" -c "SELECT 1"
```

### Check User Data Size

```bash
npm run build
# Check cdk.out for user data size
wc -c cdk.out/OpenHands-Compute.template.json
```

### Force Instance Replacement

```bash
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id <id> \
  --should-decrement-desired-capacity false \
  --region <region>
```

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| User data exceeds 16384 bytes | Verbose comments/scripts | Compact using `\n` in template literals |
| Database connection refused | IAM user not created | Run one-time SQL setup |
| Token expired errors | Timer not running | Check `systemctl status db-token-refresh.timer` |
| 502 on /runtime/{port}/ | Patch 7 not applied | Check apply-patch.sh logs, verify network_mode='host' |
| Lambda@Edge can't delete | Replicas still exist | Wait 1-2 hours, retry |

## Security Notes

- **No hardcoded secrets**: All credentials via IAM roles or Secrets Manager
- **Header spoofing prevention**: Lambda@Edge clears & re-injects user headers
- **Runtime authorization**: OpenResty verifies container `user_id` label matches requesting user
- **Private subnets**: EC2 and Aurora in private subnets only
- **VPC Endpoints**: No internet gateway needed for AWS services
- **WAF**: Protects CloudFront distribution

### Runtime Authorization (docker/openresty/)

Runtime requests are authenticated and authorized:

1. **Lambda@Edge** (`lib/edge-stack.ts`): Verifies JWT, injects `X-Cognito-User-Id` header
2. **OpenResty** (`docker/openresty/nginx.conf`): Checks container's `user_id` label matches header
3. **Docker Discovery** (`docker/openresty/docker_discovery.lua`): Returns container IP, port, and user_id

**Implementation**: Patch 16 in `docker/patch-fix.js` modifies the OpenHands `DockerRuntime` class to add `user_id` label when creating sandbox containers. Containers without this label allow access (backwards compatibility for existing containers).
