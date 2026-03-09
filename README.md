<div align="center">

# 🚀 OpenHands on AWS

### Self-host your AI coding agent — fully serverless, zero idle cost

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/zxkane/openhands-infra/actions/workflows/ci.yml/badge.svg)](https://github.com/zxkane/openhands-infra/actions/workflows/ci.yml)
[![CDK](https://img.shields.io/badge/AWS_CDK-TypeScript-orange)](https://aws.amazon.com/cdk/)
[![OpenHands](https://img.shields.io/badge/OpenHands-Compatible-green)](https://github.com/All-Hands-AI/OpenHands)

Deploy [OpenHands](https://github.com/All-Hands-AI/OpenHands) on AWS with **production-grade infrastructure** in minutes.
ECS Fargate • Bedrock LLM • Per-conversation isolation • Self-healing architecture.

[**Getting Started**](#-quick-start) · [**Architecture**](#architecture-overview) · [**Cost Estimate**](#cost-estimate) · [**Blog Post**](https://kane.mx/posts/2026/serverless-multi-tenant-openhands-on-aws/)

</div>

---

## Why This Project?

Running OpenHands locally is great for trying it out. Running it for a **team** or in **production** is a different story:

| Challenge | How This Project Solves It |
|-----------|---------------------------|
| **"I don't want to manage servers"** | Fully serverless — ECS Fargate, Aurora Serverless, no EC2 instances |
| **"Idle cost is too high"** | Sandboxes scale to zero when not in use; pay only for active conversations |
| **"Multi-user access control"** | Cognito authentication with 30-day sessions, per-user conversation isolation |
| **"My conversations disappear on restart"** | Self-healing: Aurora + S3 + EFS persist everything across Fargate task replacements |
| **"I need AWS access from the AI agent"** | Optional scoped IAM credentials for sandbox containers (least-privilege) |
| **"Setting up infra is painful"** | One `cdk deploy --all` command — 10 stacks deployed in the right order automatically |

## ✨ Key Features

- **🏗️ Fully Serverless** — ECS Fargate (ARM64) for compute, Aurora Serverless v2 for database, no instances to patch
- **💰 Zero Idle Cost** — Sandbox containers spin up per-conversation and stop automatically after idle timeout
- **🔒 Per-Conversation Isolation** — Each sandbox gets a dedicated EFS access point; no cross-conversation access
- **🔄 Self-Healing Architecture** — Conversations resume seamlessly after Fargate task replacement (Aurora + S3 + EFS)
- **🤖 AWS Bedrock** — LLM inference via IAM Role, no API keys to manage
- **🌐 Multi-Domain Support** — Share one backend across multiple CloudFront distributions and domains
- **🔐 Enterprise Security** — Cognito auth, WAF, VPC Endpoints, private subnets, KMS encryption, Secrets Manager
- **🚀 Runtime Subdomain** — Agent-built apps accessible via `{port}-{convId}.runtime.{subdomain}.{domain}`
- **📊 Observability** — CloudWatch Logs, Alarms, Container Insights, AWS Backup (14-day retention)
- **🏎️ Warm Pool** — Pre-warmed sandbox tasks for instant conversation starts

## Architecture Overview

```
User → CloudFront (WAF+Lambda@Edge Auth) → ALB (origin verified) → ECS Fargate (App + OpenResty)
           │                                                                  ↓
           └── Cognito (OAuth2, Managed Login v2)                  Cloud Map → Sandbox Fargate Tasks
                                                                              ↓
                                                        VPC Endpoints → Bedrock / CloudWatch Logs
                                                                              ↓
                                                        RDS Proxy → Aurora Serverless v2 PostgreSQL

Sandbox Orchestration:
App → Orchestrator Lambda → DynamoDB Registry → Sandbox Fargate Tasks (per-conversation EFS isolation)

Runtime Apps:
{port}-{convId}.runtime.{subdomain}.{domain} → CloudFront → Lambda@Edge → OpenResty → Sandbox Fargate Task
```

> 📐 For a detailed architecture deep dive (10-stack breakdown, data flows, sandbox lifecycle), see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 🚀 Quick Start

### Prerequisites

- AWS CLI configured with appropriate credentials
- Node.js 22+ and npm
- Existing VPC with private subnets and NAT Gateway
- Existing Route 53 Hosted Zone

### 1. Install Dependencies

```bash
git clone https://github.com/zxkane/openhands-infra.git
cd openhands-infra
npm install
```

### 2. Bootstrap CDK (First Time Only)

```bash
npx cdk bootstrap --region <your-main-region>
npx cdk bootstrap --region us-east-1  # Required for Lambda@Edge and CloudFront
```

### 3. Create Sandbox Secret Key (First Time Only)

```bash
aws secretsmanager create-secret \
  --name openhands/sandbox-secret-key \
  --secret-string "$(openssl rand -base64 32)" \
  --region <your-main-region> \
  --description "OpenHands sandbox secret key for session encryption"
```

> **Note**: This secret must exist in each region where you deploy.

### 4. Deploy

```bash
npx cdk deploy --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region> \
  --require-approval never
```

That's it! Access OpenHands at `https://<subdomain>.<domain-name>` 🎉

## Configuration

<details>
<summary><strong>📋 All Context Parameters</strong></summary>

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
| `sandboxAwsAccess` | Enable sandbox AWS access (optional, defaults to false) | `true` |
| `sandboxAwsPolicyFile` | Path to custom IAM policy JSON for sandbox (optional) | `config/sandbox-aws-policy.json` |
| `skipS3Endpoint` | Skip S3 Gateway endpoint if VPC already has one (optional) | `true` |
| `warmPoolSize` | Number of pre-warmed sandbox Fargate tasks (optional, default: 2) | `3` |
| `idleTimeoutMinutes` | Minutes before idle sandbox is stopped (optional, default: 30, staging: 10) | `15` |
| `sandboxSociImageUri` | SOCI v2 image URI for Fargate lazy loading (optional, see AGENTS.md) | `<ecr-uri>:tag-soci` |

</details>

## Stack Structure

The project deploys **10 stacks** with automatic dependency resolution:

| Stack | Region | Description |
|-------|--------|-------------|
| `OpenHands-Auth` | us-east-1 | Cognito User Pool + Managed Login v2 branding |
| `OpenHands-Network` | Main | VPC import, VPC Endpoints |
| `OpenHands-Monitoring` | Main | CloudWatch Logs, Alarms, S3 Data Bucket, Backup |
| `OpenHands-Security` | Main | IAM Roles, Security Groups, KMS key |
| `OpenHands-Database` | Main | Aurora Serverless v2 PostgreSQL with RDS Proxy |
| `OpenHands-UserConfig` | Main | User Configuration API Lambda (MCP, Secrets, Integrations) |
| `OpenHands-Cluster` | Main | Shared ECS Cluster + Cloud Map namespace |
| `OpenHands-Sandbox` | Main | Sandbox Fargate tasks, DynamoDB registry, Orchestrator Lambda |
| `OpenHands-Compute` | Main | Fargate services (App + OpenResty), ALB, EFS |
| `OpenHands-Edge-*` | us-east-1 | Lambda@Edge, CloudFront, WAF, Route 53 (per domain/environment) |

**Deployment Order** (handled automatically by CDK):
0. Auth → 1. Network → 2. Monitoring → 3. Security → 4. Database → 5. UserConfig → 6. Cluster → 7. Sandbox → 8. Compute → 9. Edge

## Cost Estimate

### Base Infrastructure (~$250-350/month)

| Component | Monthly Cost (USD) | Notes |
|-----------|--------------------|-------|
| Fargate App Service (1 vCPU / 2 GB ARM64) | ~$30 | Auto-scales 1-3 |
| Fargate OpenResty Service (0.25 vCPU / 512 MB) | ~$8 | Auto-scales 1-3 |
| Fargate Sandbox Tasks | ~$0-50 | On-demand, per-conversation |
| Aurora Serverless v2 | ~$43-80 | 0.5-4 ACU |
| RDS Proxy | ~$18 | |
| CloudFront | ~$85 | 1TB data transfer |
| VPC Endpoints (10) | ~$60 | |
| ALB | ~$25 | |
| Other (EFS, S3, NAT, CW, R53, DDB) | ~$10-50 | Usage-dependent |

### Bedrock LLM Cost (Variable)

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|----------------------|------------------------|
| Claude Opus 4.5 | $5 | $25 |
| Claude Sonnet 4.5 | $3 | $15 |
| Claude Haiku 4.5 | $1 | $5 |

**Example**: 10M input + 2M output tokens/month with Claude Sonnet 4.5 ≈ **$60/month**

## Advanced Topics

<details>
<summary><strong>🌐 Multi-Domain Deployment</strong></summary>

You can deploy multiple OpenHands instances on different domains, all sharing the same backend infrastructure.

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
                           │  - Fargate services (App+OpenResty) │
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

```bash
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

```bash
npx cdk deploy OpenHands-Network OpenHands-Monitoring OpenHands-Security \
  OpenHands-Database OpenHands-UserConfig OpenHands-Cluster \
  OpenHands-Sandbox OpenHands-Compute \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<primary-hosted-zone-id> \
  --context domainName=<primary-domain> \
  --context subDomain=openhands \
  --context region=<main-region> \
  --require-approval never
```

### Step 3: Deploy Edge Stacks for Each Domain

```bash
# Domain 1
npx cdk deploy OpenHands-Edge-Test \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-for-test-example-com> \
  --context domainName=test.example.com \
  --context subDomain=openhands \
  --context region=<main-region> \
  --context edgeStackSuffix=Test \
  --exclusively \
  --require-approval never

# Domain 2
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

### Managing Domains

**Adding a new domain:**
1. Update Auth stack with the new callback domain
2. Deploy a new Edge stack with `--context edgeStackSuffix=<Name> --exclusively`

**Removing a domain:**
1. `aws cloudformation delete-stack --stack-name OpenHands-Edge-<Suffix> --region us-east-1`
2. Optionally update Auth stack to remove the callback domain

</details>

<details>
<summary><strong>🔄 Conversation Resume (Self-Healing)</strong></summary>

When sandbox Fargate tasks stop (idle timeout, crash, or deployment), conversations become `ARCHIVED`. All data is preserved:

| Data | Storage | Survives Task Stop |
|------|---------|-------------------|
| Conversation metadata | Aurora PostgreSQL | ✅ |
| Conversation events/history | S3 | ✅ |
| Workspace files | EFS (per-conversation access point) | ✅ |

**Auto-Resume Flow:**

```
User clicks archived conversation
    ↓
Frontend detects ARCHIVED status
    ↓
Calls POST /api/v1/app-conversations/{id}/resume
    ↓
App → Orchestrator Lambda:
  - Creates new EFS access point for conversation
  - Registers new task definition with access point
  - Launches Fargate sandbox task
  - Updates DynamoDB registry
    ↓
Page reloads → conversation is usable again
```

Workspace files on EFS are preserved via the access point, so code and files from the previous session remain available after resume.

</details>

<details>
<summary><strong>🔐 Sandbox AWS Access</strong></summary>

Enable AI agents in sandbox containers to access AWS services with scoped IAM credentials:

```bash
npx cdk deploy --all \
  --context sandboxAwsAccess=true \
  --context sandboxAwsPolicyFile=config/sandbox-aws-policy.json \
  ...
```

### ⚠️ Customize the Policy File

The default `config/sandbox-aws-policy.json` grants broad permissions. **Customize this for your use case!**

**Example: Purpose-built policy for S3 and DynamoDB only:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Access",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    },
    {
      "Sid": "AllowDynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:*:*:table/my-table"
    }
  ]
}
```

### Hardcoded Explicit Denies

These actions are **always denied** regardless of your policy:

| Category | Denied Actions |
|----------|----------------|
| IAM Users | `iam:CreateUser`, `iam:DeleteUser`, `iam:CreateAccessKey` |
| IAM Policies | `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy` |
| IAM Roles | `iam:CreateRole`, `iam:DeleteRole`, `iam:AttachRolePolicy` |
| Account | `organizations:*`, `account:*`, `billing:*` |
| Role Assumption | `sts:AssumeRole` (prevents lateral movement) |

</details>

<details>
<summary><strong>🌍 Runtime Subdomain Routing</strong></summary>

When AI agents run applications (e.g., Flask, Node.js) inside the sandbox, they are accessible via dedicated runtime subdomains:

```
https://{port}-{convId}.runtime.{subdomain}.{domain}/
```

**Example**: `https://5000-abc123def456.runtime.openhands.example.com/`

| Feature | Benefit |
|---------|---------|
| Domain Root | Apps run at `/` — internal routes work correctly |
| Cookie Isolation | Each runtime has isolated cookies |
| Security Headers | X-Frame-Options, CSP, X-XSS-Protection applied automatically |
| No Authentication | Runtime subdomains bypass Cognito (public within conversation) |

### Architecture

```
User Browser
    ↓
https://5000-{convId}.runtime.openhands.example.com/
    ↓
CloudFront (matches *.runtime.* wildcard certificate)
    ↓
Lambda@Edge (viewer-request: parse subdomain, rewrite URI)
    ↓
ALB → OpenResty → Sandbox Discovery (DynamoDB) → User App
```

</details>

<details>
<summary><strong>💾 Data Persistence</strong></summary>

| Data Type | Storage | Persistence |
|-----------|---------|-------------|
| Conversation Metadata | Aurora PostgreSQL | Permanent (via RDS Proxy) |
| Conversation Events | S3 | Permanent (survives task replacement) |
| User Settings / Secrets | S3 | Permanent (KMS envelope encryption) |
| Workspace Files | EFS | Persistent (per-conversation access points) |
| SDK Conversation Cache | EFS | Persistent (enables LLM context restoration) |
| Sandbox Registry | DynamoDB | Permanent (task state, user ownership) |

**Aurora Serverless v2**: PostgreSQL 15.8, RDS Proxy connection pooling, 0.5-4 ACU auto-scaling, 35-day backups.

**S3 Bucket**: SSE-S3 encryption, versioning (30-day retention), RETAIN removal policy.

</details>

<details>
<summary><strong>🔒 Security</strong></summary>

- Fargate tasks in private subnets only
- Per-conversation EFS isolation via access points
- All AWS service access via VPC Endpoints
- IAM Roles with least privilege per service
- Database credentials in Secrets Manager
- RDS Proxy with TLS-encrypted connections
- User secrets protected by KMS envelope encryption
- Cognito authentication (30-day sessions)
- Lambda@Edge header spoofing prevention
- WAF protection with rate limiting
- S3 and Aurora storage encryption

**Session Management:**

| Token Type | Validity | Description |
|------------|----------|-------------|
| Access Token | 1 hour | API access token |
| ID Token | 1 day | Identity token (stored in cookie) |
| Refresh Token | 30 days | Used to obtain new tokens |

</details>

## VPC Requirements

Your existing VPC must have:
- At least 2 private subnets in different AZs
- NAT Gateway for outbound internet access
- DNS hostnames enabled

## CI/CD

| Workflow | Trigger | Description |
|----------|---------|-------------|
| **CI** | Push/PR to main, develop | Build TypeScript, run all tests (Jest + pytest) |
| **Security Scan** | Push/PR to main, daily | npm audit, Checkov, git-secrets, Semgrep SAST, cfn-lint |

```bash
npm run test        # Run all tests
npm run test:ts     # TypeScript tests only
npm run test:py     # Python tests only
npm run test:ts -- -u  # Update snapshots
```

## Useful Commands

```bash
npm run build       # Build TypeScript
npm run watch       # Watch for changes
npx cdk diff --all  # Show diff before deploy
npx cdk synth --all # Synthesize CloudFormation
npx cdk destroy --all  # Destroy all stacks
```

## Troubleshooting

<details>
<summary>Common issues</summary>

**VPC Lookup Fails** — Ensure the VPC exists and your AWS credentials have `ec2:DescribeVpcs` permission.

**Certificate Validation Pending** — ACM certificates use DNS validation. Ensure the Hosted Zone is correctly configured.

**Fargate Task Not Starting** — Check CloudWatch Logs at `/openhands/application` for container startup errors. Check ECS service events for Fargate capacity issues.

</details>

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

This infrastructure project deploys [OpenHands](https://github.com/All-Hands-AI/OpenHands). See the [OpenHands License](https://github.com/All-Hands-AI/OpenHands/blob/main/LICENSE) for the main application.

---

<div align="center">

**If this project helps you deploy OpenHands, consider giving it a ⭐**

Built with ❤️ using [AWS CDK](https://aws.amazon.com/cdk/) and [OpenHands](https://github.com/All-Hands-AI/OpenHands)

</div>
