# OpenHands AWS Infrastructure

AWS CDK TypeScript project for deploying [OpenHands](https://github.com/All-Hands-AI/OpenHands) - an AI-driven development platform.

## Architecture Overview

```
User → CloudFront (WAF+Lambda@Edge Auth) → HTTP Origin → ALB (origin verified) → EC2 m7g.xlarge Graviton (ASG)
           │                                                                              ↓
           └── Cognito (OAuth2, Managed Login v2)                             OpenHands Docker + Watchtower
                                                                                          ↓
                                                                        VPC Endpoints → Bedrock / CloudWatch Logs
                                                                                          ↓
                                                                        RDS Proxy → Aurora Serverless v2 PostgreSQL

Runtime Apps:
{port}-{convId}.runtime.{subdomain}.{domain} → CloudFront → Lambda@Edge → OpenResty → Docker Container
```

Key features:
- **CloudFront with Origin Verification**: ALB requires X-Origin-Verify header - direct access returns 403
- **Internet-facing ALB**: Required for WebSocket support (CloudFront VPC Origin doesn't support WebSocket)
- **Self-Healing Architecture**: Conversation history persists across EC2 instance replacements
- **Runtime Subdomain Routing**: User apps accessible via `{port}-{convId}.runtime.{subdomain}.{domain}` with proper in-app routing

## Features

- **Graviton (ARM64)**: Cost-optimized m7g.xlarge instances (~20% cheaper than x86)
- **AWS Bedrock**: LLM inference via IAM Role (no API keys)
- **Aurora Serverless v2**: PostgreSQL database with RDS Proxy for connection pooling and high availability
- **S3 Data Persistence**: Conversation events, settings stored in S3 (survives instance replacement)
- **EFS Workspace Persistence**: Sandbox workspaces stored in EFS under `/data/openhands` (survives instance replacement)
- **Self-Healing**: ASG with ELB health checks + persistent database = no data loss on instance replacement
- **Auto-updates**: Watchtower for Docker image updates
- **Security**: Cognito auth (30-day session), WAF, VPC Endpoints, private subnets, Secrets Manager
- **Monitoring**: CloudWatch Logs, Alarms, Dashboard
- **Backup**: AWS Backup with 14-day retention, Aurora automatic backups (35 days)
- **Runtime Subdomain**: Apps run at domain root with proper internal routing and cookie isolation

## Prerequisites

- AWS CLI configured with appropriate credentials
- Node.js 20+ and npm
- Existing VPC with private subnets and NAT Gateway
- Existing Route 53 Hosted Zone

## Deployment

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Context

Required context parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `vpcId` | Existing VPC ID | `vpc-0123456789abcdef0` |
| `hostedZoneId` | Route 53 Hosted Zone ID | `Z0123456789ABCDEFGHIJ` |
| `domainName` | Domain name | `example.com` |
| `subDomain` | Subdomain for OpenHands | `openhands` |
| `region` | AWS region (optional, defaults to us-east-1) | `us-west-2` |
| `siteName` | Cognito managed login site name (optional) | `Openhands on AWS` |
| `authCallbackDomains` | Extra OAuth callback domains for shared Cognito client (optional; JSON array or comma-separated) | `["openhands.example.com","openhands.test.example.com"]` |
| `authDomainPrefixSuffix` | Suffix for Cognito domain prefix (optional; avoids collisions) | `shared` |
| `edgeStackSuffix` | Suffix for Edge stack name in us-east-1 (optional; enables multiple Edge stacks) | `my-project` |

### 3. Bootstrap CDK (First Time Only)

CDK must be bootstrapped in both regions since Edge resources are deployed to us-east-1:

```bash
npx cdk bootstrap --region <your-main-region>
npx cdk bootstrap --region us-east-1  # Required for Lambda@Edge and CloudFront
```

### 4. Deploy

```bash
# Deploy all stacks
npx cdk deploy --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region> \
  --require-approval never
```

**Deployment Order** (handled automatically by CDK):
0. Auth (us-east-1) - shared Cognito (managed login branding + multi-domain callbacks)
1. Network (main region)
2. Monitoring (main region) - independent, creates S3 data bucket
3. Security (main region) - depends on Network, Monitoring
4. Database (main region) - depends on Network, Security
5. Compute (main region) - depends on Network, Security, Monitoring, Database
6. Edge (us-east-1) - depends on Compute

### 5. Access OpenHands

After deployment, access OpenHands at:
```
https://<subdomain>.<domain-name>
```

## Stack Structure

| Stack | Region | Description |
|-------|--------|-------------|
| `OpenHands-Auth` | us-east-1 | Cognito User Pool + Managed Login v2 branding |
| `OpenHands-Network` | Main | VPC import, VPC Endpoints |
| `OpenHands-Monitoring` | Main | CloudWatch Logs, Alarms, Dashboard, Backup, S3 Data Bucket |
| `OpenHands-Security` | Main | IAM Roles, Security Groups |
| `OpenHands-Database` | Main | Aurora Serverless v2 PostgreSQL with RDS Proxy |
| `OpenHands-Compute` | Main | EC2 ASG, Launch Template, Internal ALB |
| `OpenHands-Edge-*` | us-east-1 | Lambda@Edge, CloudFront (VPC Origin), WAF, Route 53 (per domain/environment) |

**Notes**:
- Cognito is provisioned in `OpenHands-Auth` so multiple Edge stacks can reuse a single user pool/client.
- To add another domain/environment, include it in `authCallbackDomains`, deploy `OpenHands-Auth`, then deploy a new `OpenHands-Edge-<edgeStackSuffix>`.
- The Database stack is **required** for self-healing architecture - it persists conversation history across EC2 instance replacements.

## Multi-Domain Deployment

You can deploy multiple OpenHands instances on different domains, all sharing the same backend infrastructure (Compute, Database, etc.) but with separate CloudFront distributions and DNS records.

### Architecture

```
                                 ┌─────────────────────────────────┐
                                 │      AuthStack (us-east-1)      │
                                 │  Shared Cognito User Pool       │
                                 │  - Multi-domain callbacks       │
                                 └─────────────────────────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│  EdgeStack-Domain1      │   │  EdgeStack-Domain2      │   │  EdgeStack-DomainN      │
│  (us-east-1)            │   │  (us-east-1)            │   │  (us-east-1)            │
│  - CloudFront           │   │  - CloudFront           │   │  - CloudFront           │
│  - Lambda@Edge          │   │  - Lambda@Edge          │   │  - Lambda@Edge          │
│  - WAF                  │   │  - WAF                  │   │  - WAF                  │
│  - Route 53 records     │   │  - Route 53 records     │   │  - Route 53 records     │
│  - ACM Certificate      │   │  - ACM Certificate      │   │  - ACM Certificate      │
└─────────────────────────┘   └─────────────────────────┘   └─────────────────────────┘
              │                               │                               │
              └───────────────────────────────┼───────────────────────────────┘
                                              │
                                              ▼
                           ┌─────────────────────────────────────┐
                           │     ComputeStack (main region)      │
                           │  - ALB with origin verification     │
                           │  - EC2 ASG                          │
                           │  - SSM parameters in us-east-1      │
                           └─────────────────────────────────────┘
                                              │
                           ┌──────────────────┴──────────────────┐
                           ▼                                     ▼
              ┌─────────────────────────┐          ┌─────────────────────────┐
              │     DatabaseStack       │          │    MonitoringStack      │
              │  Aurora PostgreSQL      │          │  S3, CloudWatch         │
              └─────────────────────────┘          └─────────────────────────┘
```

### Step 1: Configure Shared Authentication

First, configure the Auth stack with all domains that will use it:

```bash
# Deploy Auth stack with all callback domains
npx cdk deploy OpenHands-Auth \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<primary-hosted-zone-id> \
  --context domainName=<primary-domain> \
  --context subDomain=openhands \
  --context region=<main-region> \
  --context authCallbackDomains='["openhands.domain1.com","openhands.domain2.com"]' \
  --require-approval never
```

### Step 2: Deploy Backend Infrastructure

Deploy the shared backend infrastructure (only once):

```bash
npx cdk deploy OpenHands-Network OpenHands-Monitoring OpenHands-Security OpenHands-Database OpenHands-Compute \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<primary-hosted-zone-id> \
  --context domainName=<primary-domain> \
  --context subDomain=openhands \
  --context region=<main-region> \
  --require-approval never
```

### Step 3: Deploy Edge Stacks for Each Domain

Deploy a separate Edge stack for each domain:

```bash
# Domain 1 (e.g., openhands.test.example.com)
npx cdk deploy OpenHands-Edge-Test \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-for-test-example-com> \
  --context domainName=test.example.com \
  --context subDomain=openhands \
  --context region=<main-region> \
  --context edgeStackSuffix=Test \
  --exclusively \
  --require-approval never

# Domain 2 (e.g., openhands.prod.example.com)
npx cdk deploy OpenHands-Edge-Prod \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-for-prod-example-com> \
  --context domainName=prod.example.com \
  --context subDomain=openhands \
  --context region=<main-region> \
  --context edgeStackSuffix=Prod \
  --exclusively \
  --require-approval never
```

**Important**: Use `--exclusively` flag when deploying individual Edge stacks to avoid redeploying the backend stacks with different domain context.

### How It Works

1. **Shared Cognito**: All domains use the same Cognito User Pool. Users can log in with the same credentials on any domain.

2. **ALB Origin Verification**: The internet-facing ALB is protected by a custom `X-Origin-Verify` header. Direct access returns 403 - only CloudFront with the valid header can reach the ALB.

3. **SSM Parameter Sharing**: ComputeStack writes ALB DNS name and origin secret to SSM parameters in us-east-1. Edge stacks read from these parameters, avoiding CDK cross-region reference conflicts.

4. **Unique Resource Names**: Each Edge stack has unique CloudFront ResponseHeadersPolicy names (includes domain) to avoid naming conflicts.

### Adding a New Domain

To add a new domain to an existing deployment:

1. **Update Auth stack** with the new callback domain:
   ```bash
   npx cdk deploy OpenHands-Auth \
     --context authCallbackDomains='["existing.com","new-domain.com"]' \
     ...
   ```

2. **Deploy new Edge stack**:
   ```bash
   npx cdk deploy OpenHands-Edge-NewDomain \
     --context hostedZoneId=<zone-for-new-domain> \
     --context domainName=new-domain.com \
     --context edgeStackSuffix=NewDomain \
     --exclusively \
     ...
   ```

### Removing a Domain

To remove a domain:

1. **Delete the Edge stack**:
   ```bash
   aws cloudformation delete-stack --stack-name OpenHands-Edge-<Suffix> --region us-east-1
   ```

2. **Optionally update Auth stack** to remove the callback domain (not required, but keeps config clean).

## Cost Estimate

### Base Infrastructure (~$375-420/month)

| Component | Monthly Cost (USD) | Usage Assumption |
|-----------|--------------------|------------------|
| EC2 m7g.xlarge Graviton | ~$112 | 730 hours (24/7) |
| EBS gp3 300GB | ~$30 | 300GB storage |
| Aurora Serverless v2 | ~$43-80 | 0.5-4 ACU (scales with usage) |
| RDS Proxy | ~$18 | 730 hours |
| S3 Data Bucket | ~$1-5 | Depends on usage |
| NAT Gateway | ~$0-35 | Depends on traffic |
| CloudFront | ~$85 | 1TB data transfer |
| ALB | ~$25 | 730 hours + LCUs |
| VPC Endpoints (8) | ~$50 | 8 endpoints × 730 hours |
| CloudWatch | ~$5 | Logs, metrics, alarms |
| Route 53 | ~$1 | 1 hosted zone + queries |

### Bedrock Usage (Variable)

Claude 4.5 models available on Amazon Bedrock:

| Model | Model ID | Input (per 1M) | Output (per 1M) |
|-------|----------|----------------|-----------------|
| Claude Opus 4.5 | `anthropic.claude-opus-4-5-20251101-v1:0` | $5 | $25 |
| Claude Sonnet 4.5 | `anthropic.claude-sonnet-4-5-20250929-v1:0` | $3 | $15 |
| Claude Haiku 4.5 | `anthropic.claude-haiku-4-5-20251001-v1:0` | $1 | $5 |

**Example**: 10M input + 2M output tokens/month with Claude Sonnet 4.5 ≈ $60/month

**Note**: Claude Sonnet 4.5 pricing increases for prompts >200K tokens ($6 input / $22.50 output per 1M).

## VPC Requirements

Your existing VPC must have:
- At least 2 private subnets in different AZs
- NAT Gateway for outbound internet access
- DNS hostnames enabled

## Data Persistence

OpenHands data is stored durably for self-healing across instance replacements:

| Data Type | Storage | Persistence |
|-----------|---------|-------------|
| Conversation Metadata | Aurora PostgreSQL | Permanent (via RDS Proxy) |
| Conversation Events | S3 | Permanent (survives instance replacement) |
| User Settings | S3 | Permanent |
| Workspace Files | EFS | Persistent (survives instance replacement) |

**Aurora Serverless v2 with RDS Proxy**:
- PostgreSQL 15.8 with RDS Proxy for connection pooling
- Password-based authentication via Secrets Manager (no token refresh needed)
- Serverless v2: 0.5-4 ACU (auto-scales with usage)
- 35-day automatic backup retention
- Storage encryption enabled
- CloudWatch logs export
- Removal policy: SNAPSHOT (creates final backup on deletion)

**RDS Proxy Benefits**:
- Connection pooling for efficient database connections
- Automatic failover handling
- No IAM token refresh required (uses stable passwords from Secrets Manager)
- Improved application availability during database maintenance

**S3 Bucket Configuration**:
- SSE-S3 encryption
- Versioning enabled (30-day retention for old versions)
- Block all public access
- Enforce SSL
- Removal policy: RETAIN (data preserved if stack is deleted)

### Conversation Resume (Self-Healing)

When EC2 instances are replaced (ASG scaling, CDK deployment, health check failure), sandbox Docker containers are terminated. OpenHands marks these conversations as `ARCHIVED` because the sandbox is missing. However, all conversation data is preserved:

| Data | Storage | Survives EC2 Replacement |
|------|---------|--------------------------|
| Conversation metadata | Aurora PostgreSQL | ✅ Yes |
| Conversation events/history | S3 | ✅ Yes |
| Workspace files | EFS (`/data/openhands`) | ✅ Yes |

**Auto-Resume Flow**:

```
User clicks archived conversation
    ↓
Frontend detects ARCHIVED status
    ↓
Calls POST /api/v1/app-conversations/{id}/resume
    ↓
Backend recreates sandbox container with:
  - Same conversation ID
  - user_id label (for authorization)
  - EFS workspace mounted
    ↓
Page reloads → conversation is usable again
```

**What happens automatically**:
1. User navigates to an archived conversation
2. Frontend patch detects `status: ARCHIVED` and triggers resume
3. Backend creates a new sandbox container with the original workspace
4. Container gets `user_id` label for runtime URL authorization
5. Page reloads and conversation is ready for use

**Note**: The workspace files on EFS are preserved, so any code or files created in the previous session are still available after resume.

## Session Management

Cognito token validity configuration:

| Token Type | Validity | Description |
|------------|----------|-------------|
| Access Token | 1 hour | API access token |
| ID Token | 1 day | Identity token (stored in cookie) |
| Refresh Token | 30 days | Used to obtain new tokens |

Users stay logged in for up to 30 days without re-authentication.

## Runtime Subdomain Routing

When AI agents run applications (e.g., Flask, Node.js) inside the sandbox, they are accessible via dedicated runtime subdomains:

```
https://{port}-{convId}.runtime.{subdomain}.{domain}/
```

**Example**: `https://5000-abc123def456.runtime.openhands.example.com/`

### Benefits

| Feature | Benefit |
|---------|---------|
| Domain Root | Apps run at `/` - internal routes (e.g., `/add`, `/api`) work correctly |
| Cookie Isolation | Each runtime has isolated cookies (no cross-runtime cookie leakage) |
| Security Headers | X-Frame-Options, CSP, X-XSS-Protection automatically applied |
| No Authentication | Runtime subdomains bypass Cognito (apps are public within the conversation) |

### Architecture

```
User Browser
    ↓
https://5000-{convId}.runtime.openhands.example.com/
    ↓
CloudFront (matches *.runtime.* wildcard certificate)
    ↓
Lambda@Edge (viewer-request: parse subdomain, rewrite URI to /runtime/{convId}/{port}/...)
    ↓
ALB → EC2 → OpenResty
    ↓
Lua Docker Discovery (find container by convId, route to container IP:port)
    ↓
User App (Flask/Node.js/etc. inside sandbox container)
```

### Security Considerations

- **Cookie Isolation**: Cookies set by runtime apps are scoped to the exact subdomain only
- **No Domain Attribute**: Cookies don't leak to parent domain or other subdomains
- **SameSite=Strict**: Cross-site requests don't carry cookies
- **Security Headers**: Lambda@Edge origin-response adds protective headers

## Security

- EC2 instances in private subnets only
- All AWS service access via VPC Endpoints
- IAM Role with least privilege (Bedrock, Logs, SSM, S3, Secrets Manager)
- Database credentials stored in AWS Secrets Manager
- RDS Proxy with TLS-encrypted connections
- Cognito authentication for all requests (30-day session)
- WAF protection with rate limiting
- EBS, S3, and Aurora storage encryption enabled

## Useful Commands

```bash
# Build TypeScript
npm run build

# Watch for changes
npm run watch

# Run tests
npm run test

# Show diff before deploy
npx cdk diff --all --context ...

# Synthesize CloudFormation
npx cdk synth --all --context ...

# Destroy all stacks
npx cdk destroy --all --context ...
```

## Troubleshooting

### VPC Lookup Fails
Ensure the VPC exists and your AWS credentials have `ec2:DescribeVpcs` permission.

### Certificate Validation Pending
ACM certificates use DNS validation. Ensure the Hosted Zone is correctly configured.

### EC2 Instance Not Starting
Check CloudWatch Logs at `/openhands/application` for container startup errors.

## CI/CD

This project uses GitHub Actions for continuous integration:

| Workflow | Trigger | Description |
|----------|---------|-------------|
| **CI** | Push/PR to main, develop | Build TypeScript, run all tests (Jest + pytest) |
| **Security Scan** | Push/PR to main, daily | npm audit, Checkov, git-secrets, Semgrep SAST, cfn-lint |

### Running Tests Locally

```bash
# Run all tests (build + TypeScript + Python)
npm run test

# Run TypeScript tests only
npm run test:ts

# Run Python tests only (requires .venv)
npm run test:py

# Update snapshots after intentional changes
npm run test:ts -- -u
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

This infrastructure project deploys [OpenHands](https://github.com/All-Hands-AI/OpenHands). See the [OpenHands License](https://github.com/All-Hands-AI/OpenHands/blob/main/LICENSE) for the main application.
