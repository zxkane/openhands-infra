# lib/CLAUDE.md - Stack Implementation Reference

This document provides implementation details for the CDK stack files in this directory.

## Stack Architecture (10 Stacks)

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
│                           Main Region (us-west-2)                        │
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
│  │ Cloud Map    │  └───────────────────────┘       │                    │
│  └──────────────┘           │                      │                    │
│         │                   ▼                      ▼                    │
│         ├──────▶ ┌──────────────────────────────────────┐              │
│         │        │           SandboxStack                │              │
│         │        │  DynamoDB, Orchestrator, Sandbox Tasks │              │
│         │        └──────────────────────────────────────┘              │
│         │                   │                                           │
│         ▼                   ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      ComputeStack                                │    │
│  │   Fargate Services (App + OpenResty), ALB, EFS, Lambda TG       │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## File Reference

| File | Purpose | Key Resources |
|------|---------|---------------|
| `interfaces.ts` | TypeScript interfaces for stack I/O | OpenHandsConfig, *StackOutput |
| `network-stack.ts` | VPC import, VPC Endpoints | SSM, ECR, S3, Logs endpoints |
| `security-stack.ts` | IAM roles, Security Groups, KMS | Fargate task/execution roles, ALB SG, App SG |
| `monitoring-stack.ts` | Observability & data store | CloudWatch, S3 data bucket |
| `database-stack.ts` | Persistent storage | Aurora Serverless v2, RDS Proxy |
| `cluster-stack.ts` | Shared ECS infrastructure | ECS Cluster, Cloud Map namespace |
| `sandbox-stack.ts` | Sandbox containers | DynamoDB, Orchestrator, Task definitions |
| `compute-stack.ts` | Application runtime | Fargate services, ALB, EFS |
| `user-config-stack.ts` | User Configuration API | Lambda (ALB target group) |
| `auth-stack.ts` | Shared authentication | Cognito User Pool, managed login |
| `edge-stack.ts` | Edge & CDN | Lambda@Edge, CloudFront, WAF, Route 53 |

## Stack Dependencies

```typescript
// bin/openhands-infra.ts
securityStack.addDependency(networkStack);
securityStack.addDependency(monitoringStack);
databaseStack.addDependency(networkStack);
databaseStack.addDependency(securityStack);
clusterStack.addDependency(networkStack);
sandboxStack.addDependency(networkStack);
sandboxStack.addDependency(monitoringStack);
sandboxStack.addDependency(clusterStack);
userConfigStack.addDependency(monitoringStack);
userConfigStack.addDependency(securityStack);
computeStack.addDependency(networkStack);
computeStack.addDependency(securityStack);
computeStack.addDependency(monitoringStack);
computeStack.addDependency(databaseStack);
computeStack.addDependency(userConfigStack);
computeStack.addDependency(clusterStack);
computeStack.addDependency(sandboxStack);
edgeStack.addDependency(computeStack);
edgeStack.addDependency(authStack);
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

## user-config-stack.ts

### User Configuration API

Provides per-user configuration management via Lambda integrated with ALB.

**Architecture:**
- Lambda function (`openhands-user-config-api`) - Python 3.12 on ARM64
- Exported to ComputeStack for ALB target group integration
- Routes via ALB listener rule for `/api/v1/user-config/*`

**Key Change (v2):** Replaced HTTP API Gateway with ALB Lambda target group for:
- Architecture consistency (single entry point via ALB)
- Cost optimization (no API Gateway fees)
- Simplified security (no additional execute-api endpoint)

**Environment Variables:**
```typescript
DATA_BUCKET: dataBucket.bucketName,  // S3 bucket for user data
KMS_KEY_ID: kmsKey.keyId,             // KMS key for secrets encryption
LOG_LEVEL: 'INFO',
```

**IAM Permissions:**
- S3 `grantReadWrite` on `users/*` prefix
- KMS `grantEncryptDecrypt` + `kms:GenerateDataKey`

**API Routes (via ALB):**
| Path | Methods |
|------|---------|
| `/api/v1/user-config/mcp` | GET, PUT |
| `/api/v1/user-config/mcp/servers` | POST |
| `/api/v1/user-config/mcp/servers/{serverId}` | PUT, DELETE |
| `/api/v1/user-config/secrets` | GET |
| `/api/v1/user-config/secrets/{secretId}` | PUT, DELETE |
| `/api/v1/user-config/integrations` | GET |
| `/api/v1/user-config/integrations/{provider}` | PUT, DELETE |
| `/api/v1/user-config/merged` | GET |

**ALB Integration (compute-stack.ts):**
```typescript
// Lambda target group with priority 5 listener rule
const userConfigTargetGroup = new elbv2.ApplicationTargetGroup(this, 'UserConfigTargetGroup', {
  targetType: elbv2.TargetType.LAMBDA,
  targets: [new targets.LambdaTarget(props.userConfigFunction)],
});

listener.addTargetGroups('VerifiedUserConfigRule', {
  priority: 5,
  conditions: [
    elbv2.ListenerCondition.pathPatterns(['/api/v1/user-config/*']),
    elbv2.ListenerCondition.httpHeader('X-Origin-Verify', [originVerifySecret]),
  ],
  targetGroups: [userConfigTargetGroup],
});
```

### KMS Envelope Encryption

Secrets are encrypted using envelope encryption:
1. Generate data key (DEK) using KMS `GenerateDataKey`
2. Encrypt secrets JSON with DEK using AES-256-GCM
3. Store encrypted DEK + nonce + ciphertext in S3

**Decryption:**
1. Read encrypted envelope from S3
2. Decrypt DEK using KMS `Decrypt`
3. Decrypt secrets using DEK + AES-256-GCM

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

### Fargate Services

Two separate ECS Fargate services run the application:

1. **App Service** (`openhands-app`): 4 vCPU / 8 GB ARM64
   - Cloud Map DNS: `app.openhands.local:3000`
   - EFS mount at `/data/openhands` for workspace persistence
   - Secrets: `OH_SECRET_KEY`, `DB_PASS` via ECS native injection

2. **OpenResty Service** (`openhands-openresty`): 0.25 vCPU / 512 MB ARM64
   - Runtime proxy on port 8080
   - Routes `/runtime/{convId}/{port}/...` to sandbox Fargate tasks

### Docker Image Versions

```typescript
const DEFAULT_OPENHANDS_VERSION = '1.3.0';
const DEFAULT_RUNTIME_VERSION = '1.3-nikolaik';
```

Update these when upgrading OpenHands.

### Database Credentials

DB password is injected via ECS native secrets (from Secrets Manager `openhands/database/proxy-user`).
No token refresh needed — RDS Proxy handles connection pooling.

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
# ECS exec into app container
aws ecs execute-command --cluster <cluster-name> --task <task-id> \
  --container openhands-app --interactive --command "/bin/bash" --region <region>

# Check DB_PASS is injected
echo $DB_PASS | head -c 5
```

### Force Service Redeployment

```bash
aws ecs update-service --cluster <cluster-name> \
  --service openhands-app --force-new-deployment --region <region>
```

### Check Cloud Map DNS

```bash
aws servicediscovery discover-instances \
  --namespace-name openhands.local --service-name app --region <region>
```

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Database connection refused | DB user not created | Run one-time SQL setup |
| 502 on /runtime/{port}/ | Sandbox task not running | Check orchestrator logs |
| Lambda@Edge can't delete | Replicas still exist | Wait 1-2 hours, retry |
| Service stuck in PROVISIONING | No available Fargate capacity | Check service events |

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
3. **Docker Discovery** (`docker/openresty/sandbox_discovery.lua`): Returns container IP, port, and user_id

**Implementation**: Patch 16 in `docker/patch-fix.js` modifies the OpenHands `DockerRuntime` class to add `user_id` label when creating sandbox containers. Containers without this label allow access (backwards compatibility for existing containers).
