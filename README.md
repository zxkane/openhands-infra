# OpenHands AWS Infrastructure

AWS CDK TypeScript project for deploying [OpenHands](https://github.com/All-Hands-AI/OpenHands) - an AI-driven development platform.

## Architecture Overview

```
User → CloudFront (WAF+Lambda@Edge Auth) → VPC Origin → Internal ALB → EC2 m7g.xlarge Graviton (ASG)
           │                                                                    ↓
           └── Cognito (OAuth2)                                     OpenHands Docker + Watchtower
                                                                                ↓
                                                              VPC Endpoints → Bedrock / CloudWatch Logs
                                                                                ↓
                                                              RDS Proxy → Aurora Serverless v2 PostgreSQL

Runtime Apps:
{port}-{convId}.runtime.{subdomain}.{domain} → CloudFront → Lambda@Edge → OpenResty → Docker Container
```

Key features:
- **CloudFront VPC Origin**: Connects directly to internal ALB without exposing it to the internet
- **Internal ALB**: No public IP, accessible only via CloudFront VPC Origin
- **Self-Healing Architecture**: Conversation history persists across EC2 instance replacements
- **Runtime Subdomain Routing**: User apps accessible via `{port}-{convId}.runtime.{subdomain}.{domain}` with proper in-app routing

## Features

- **Graviton (ARM64)**: Cost-optimized m7g.xlarge instances (~20% cheaper than x86)
- **AWS Bedrock**: LLM inference via IAM Role (no API keys)
- **Aurora Serverless v2**: PostgreSQL database with RDS Proxy for connection pooling and high availability
- **S3 Data Persistence**: Conversation events, settings stored in S3 (survives instance replacement)
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
| `OpenHands-Network` | Main | VPC import, VPC Endpoints |
| `OpenHands-Monitoring` | Main | CloudWatch Logs, Alarms, Dashboard, Backup, S3 Data Bucket |
| `OpenHands-Security` | Main | IAM Roles, Security Groups |
| `OpenHands-Database` | Main | Aurora Serverless v2 PostgreSQL with RDS Proxy |
| `OpenHands-Compute` | Main | EC2 ASG, Launch Template, Internal ALB |
| `OpenHands-Edge` | us-east-1 | Cognito, Lambda@Edge, CloudFront (VPC Origin), WAF, Route 53 |

**Notes**:
- The Edge stack combines authentication (Cognito, Lambda@Edge) and CDN (CloudFront, WAF) into a single stack to avoid cross-stack reference issues during CloudFormation updates.
- The Database stack is **required** for self-healing architecture - it persists conversation history across EC2 instance replacements.

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

| Model | Input Tokens | Output Tokens | Cost per 1M Tokens |
|-------|--------------|---------------|-------------------|
| Claude 3.5 Sonnet | - | - | $3 input / $15 output |
| Claude 3 Haiku | - | - | $0.25 input / $1.25 output |

**Example**: 10M input + 2M output tokens/month with Claude 3.5 Sonnet ≈ $60/month

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
| Workspace Files | Local EBS | Ephemeral (cleared on instance replacement) |

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

## License

This project is for deploying OpenHands. See [OpenHands License](https://github.com/All-Hands-AI/OpenHands/blob/main/LICENSE) for the main application.
