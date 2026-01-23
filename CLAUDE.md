# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

**IMPORTANT**: Claude Code MUST follow this workflow for all feature development and bug fixes.

### Workflow Steps

```
1. CREATE BRANCH     → git checkout -b feat/<name> or fix/<name>
2. IMPLEMENT CHANGES → Write code, update tests
3. LOCAL VERIFICATION→ npm run build && npm run test && npx cdk deploy --all
4. COMMIT AND PR     → git commit && git push && create PR
5. WAIT FOR CHECKS   → Monitor GitHub Actions, fix if failed
6. ADDRESS FINDINGS  → Review Amazon Q Developer comments
7. READY FOR MERGE   → All checks passed
```

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<name>` | `feat/cross-user-authorization` |
| Bug fix | `fix/<name>` | `fix/websocket-connection` |
| Refactor | `refactor/<name>` | `refactor/openresty-container` |

### Commit Message Format

```
type(scope): description

Types: feat, fix, docs, refactor, test, chore
Scope: runtime, edge, compute, security, etc.
```

### No Environment-Specific Information in Source Control

**CRITICAL**: Source-controlled files must NOT contain real domain names, AWS account IDs, resource ARNs, or IP addresses. Use placeholders like `{domain}`, `<aws-account-id>`, `example.com`.

Environment-specific info belongs in:
- `CLAUDE.local.md` - Local project instructions (gitignored)
- `.env` files - Environment variables (gitignored)
- `cdk.context.json` - CDK lookup cache (gitignored)

## Common Commands

```bash
npm run build          # Build TypeScript
npm run test           # Run all tests (TypeScript + Python)
npm run test:ts        # TypeScript tests only
npm run test:py        # Python tests only

# CDK commands (require context parameters)
npx cdk synth --all --context vpcId=<vpc-id> --context hostedZoneId=<zone-id> --context domainName=<domain> --context subDomain=<sub> --context region=<region>
npx cdk deploy --all --context ...
npx cdk diff --all --context ...
```

## Required Context Parameters

- `vpcId` - Existing VPC ID
- `hostedZoneId` - Route 53 Hosted Zone ID
- `domainName` - Domain name (e.g., example.com)
- `subDomain` - Optional, defaults to "openhands"
- `region` - Optional, defaults to us-east-1

## Architecture

### Stack Dependency Graph (7 Stacks)

```
AuthStack (us-east-1) ─────────────────────────┐
                                               │
NetworkStack (main region)                     │
    ↓                                          │
SecurityStack ← depends on Network             │
    ↓                                          │
MonitoringStack ← independent                  │
    ↓                                          │
DatabaseStack ← depends on Network + Security  │
    ↓                                          │
ComputeStack ← depends on all above            │
    ↓                                          │
EdgeStack (us-east-1) ← depends on Compute + Auth
```

### Self-Healing Architecture

- **Aurora Serverless v2 PostgreSQL**: Conversation metadata with IAM authentication
- **S3 Data Bucket**: Conversation events, user settings, workspace files
- **EBS Volume**: Temporary storage formatted on each instance launch

### Cross-Region Deployment

- **Main region**: Network, Security, Monitoring, Database, Compute
- **us-east-1**: Auth (Cognito), Edge (Lambda@Edge, CloudFront, WAF, Route 53)

### Key Files

| File | Purpose |
|------|---------|
| `bin/openhands-infra.ts` | CDK entry point |
| `lib/*.ts` | CDK stack definitions (see `lib/CLAUDE.md`) |
| `docker/` | Container patches and proxy (see `docker/CLAUDE.md`) |
| `test/` | Tests and E2E cases (see `test/CLAUDE.md`) |
| `config/config.toml` | OpenHands application configuration |

## Deployment

### Prerequisites

1. AWS CLI configured
2. Node.js 20+
3. CDK bootstrapped in both regions

### Bootstrap CDK (First Time Only)

```bash
npx cdk bootstrap --region <main-region>
npx cdk bootstrap --region us-east-1  # Required for Lambda@Edge
```

### Deploy All Stacks

```bash
npx cdk deploy --all \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<hosted-zone-id> \
  --context domainName=<domain-name> \
  --context subDomain=<subdomain> \
  --context region=<region> \
  --require-approval never
```

## Cognito User Management

```bash
# Create user
aws cognito-idp admin-create-user \
  --user-pool-id <user-pool-id> \
  --username <email> \
  --user-attributes Name=email,Value=<email> Name=email_verified,Value=true \
  --temporary-password "<temp-password>" \
  --message-action SUPPRESS \
  --region us-east-1

# Set permanent password
aws cognito-idp admin-set-user-password \
  --user-pool-id <user-pool-id> \
  --username <email> \
  --password "<password>" \
  --permanent \
  --region us-east-1
```

## Troubleshooting

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| "Token verification failed" | JWK to PEM error | Check `jwkToPem` in edge-stack.ts |
| 502 Bad Gateway | ALB target unhealthy | Check EC2 instance health |
| Redirect loop | Cookie not set | Check cookie domain settings |
| CloudFront 403 | WAF blocking | Check WAF rules and logs |

### Lambda@Edge Log Locations

Lambda@Edge logs appear in CloudWatch in the **region closest to the user**:

```bash
for region in us-east-1 us-west-2 eu-west-1 ap-northeast-1; do
  aws logs describe-log-groups \
    --log-group-name-prefix '/aws/lambda/us-east-1.OpenHands-Edge' \
    --region "$region" --query 'logGroups[].logGroupName' --output text
done
```

## Security Scanning

```bash
./security-check.sh  # Local security check
```

CI/CD runs automatically: npm audit, Checkov, git-secrets, Semgrep, OWASP Dependency Check, cfn-lint.
