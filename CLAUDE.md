# CLAUDE.md

## Development Workflow (MANDATORY)

**CRITICAL**: All feature development and bug fixes MUST strictly follow the `github-workflow` skill.

Before ANY code changes involving functionality:
1. **Invoke skill**: Use `/github-workflow` or load the skill
2. **Follow the 10-step workflow** - NO shortcuts allowed
3. **Do NOT merge** - Report status and wait for user decision

The workflow includes:
- Step 2: Write new unit tests + update E2E test cases
- Steps 6-7: Address ALL reviewer bot findings (Q, Codex, etc.) and iterate until no new findings
- Steps 8-9: Deploy to staging + run full E2E tests
- Step 10: Report ready status (DO NOT MERGE)

## Quick Reference

- **Branch naming**: `feat/<name>`, `fix/<name>`, `refactor/<name>`, `docs/<name>`
- **Commit format**: `type(scope): description`
- **GitHub workflow**: Use `.claude/skills/github-workflow/` for PR creation, review comments, reviewer bots

### Source Control Rules

**CRITICAL**: Open source project. Source-controlled files must NOT contain real domain names, AWS account IDs, resource ARNs, IP addresses, or emails. Use placeholders: `{domain}`, `<aws-account-id>`, `123456789012`, `example.com`.

## Commands

```bash
npm run build          # Build TypeScript
npm run watch          # Watch mode
npm run test           # Run all tests (TypeScript + Python)
npm run test:ts        # TypeScript tests only
npm run test:py        # Python tests only

# CDK commands (require context parameters)
npx cdk synth --all --context vpcId=<vpc-id> --context hostedZoneId=<zone-id> --context domainName=<domain> --context subDomain=<sub> --context region=<region>
npx cdk deploy --all --context ...
npx cdk diff --all --context ...
```

### Required Context Parameters

- `vpcId` - Existing VPC ID
- `hostedZoneId` - Route 53 Hosted Zone ID
- `domainName` - Domain name (e.g., example.com)
- `subDomain` - Optional, defaults to "openhands"
- `region` - Optional, defaults to us-east-1

### Prerequisites (First-Time Deployment)

Create sandbox secret key before first deployment:
```bash
aws secretsmanager create-secret --name openhands/sandbox-secret-key \
  --secret-string "$(openssl rand -base64 32)" --region <region> \
  --description "OpenHands sandbox secret key for session encryption"
```

## Architecture (8 Stacks)

```
AuthStack (us-east-1) ← Cognito User Pool (shared across domains)
    ↓
NetworkStack (main region)
    ↓
SecurityStack ← depends on Network, creates KMS key
    ↓
MonitoringStack ← independent, S3 data bucket
    ↓
DatabaseStack ← depends on Network + Security
    ↓
UserConfigStack ← depends on Security (KMS) + Monitoring (S3), creates Lambda
    ↓
ComputeStack ← depends on Network + Security + Monitoring + Database + UserConfig
    ↓           (routes /api/v1/user-config/* to Lambda via ALB target group)
EdgeStack (us-east-1) ← depends on Compute + Auth
```

**Self-healing**: Aurora PostgreSQL + S3 + EFS preserve data across EC2 replacements.

## Key Files

| File | Purpose |
|------|---------|
| `bin/openhands-infra.ts` | CDK entry point |
| `lib/interfaces.ts` | Stack I/O interfaces |
| `lib/*-stack.ts` | Individual stack definitions |
| `config/config.toml` | OpenHands app config (LLM, sandbox) |
| `config/sandbox-aws-policy.json` | Customizable IAM policy for sandbox |
| `docker/patch-fix.js` | Frontend patches (URL rewriting) |
| `docker/openresty/` | OpenResty proxy container |
| `lambda/user-config/` | User config API Lambda |
| `lib/lambda-edge/` | Lambda@Edge handlers |
| `test/E2E_TEST_CASES.md` | E2E test cases |
| `docs/ARCHITECTURE.md` | Architecture deep dive |

## User Configuration (Multi-Tenant)

Per-user customization stored in S3:
- **MCP Servers**: Custom servers that extend/override global config
- **Encrypted Secrets**: API keys with KMS envelope encryption
- **Integrations**: GitHub, Slack with auto-MCP support

Feature flag: `USER_CONFIG_ENABLED` environment variable on EC2.

## Runtime Subdomain Routing

User apps accessible via: `https://{port}-{convId}.runtime.{subdomain}.{domain}/`

**Flow**: Browser → CloudFront → Lambda@Edge (JWT + user_id) → ALB → OpenResty (verify ownership) → Container

**Dual routing**:
| Route | Pattern | Use Case |
|-------|---------|----------|
| Path-based | `/runtime/{convId}/{port}/...` | Agent WebSocket, API calls |
| Subdomain | `{port}-{convId}.runtime.{domain}/` | User apps (Flask, Express) |

## Deployment

### Deploy (Exclude Auth - Recommended for routine updates)

```bash
npx cdk deploy --all --exclusively \
  OpenHands-Network OpenHands-Monitoring OpenHands-Security \
  OpenHands-Database OpenHands-UserConfig OpenHands-Compute OpenHands-Edge \
  --context vpcId=<vpc-id> \
  --context hostedZoneId=<zone-id> \
  --context domainName=<domain> \
  --context subDomain=<sub> \
  --context region=<region> \
  --require-approval never
```

### Deploy Auth Stack (Include ALL callback domains)

```bash
npx cdk deploy --all \
  --context authCallbackDomains='["domain1.example.com","domain2.example.com"]' \
  --context ...
```

| Change Type | Command |
|-------------|---------|
| Compute/Edge/Network | Exclude Auth stack |
| Cognito changes | Include all callback domains |
| First deployment | Include all callback domains |

### Cognito User Management

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <pool-id> --username <email> \
  --user-attributes Name=email,Value=<email> Name=email_verified,Value=true \
  --temporary-password "<temp>" --message-action SUPPRESS --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id <pool-id> --username <email> \
  --password "<password>" --permanent --region us-east-1
```

## Lambda@Edge Guidelines

- **External files required**: Store handlers in `lib/lambda-edge/`, NOT inline
- **Placeholder replacement**: Use `{{PLACEHOLDER}}` syntax, replaced at synth time
- **Deletion note**: Lambda@Edge requires hours for cleanup after CloudFront removal

## Post-Deploy Workflow

**MANDATORY**: After infrastructure changes, proceed through all steps without stopping.

1. **Build & Test**: `npm run build && npm run test`
2. **Deploy**: See commands above
3. **E2E Test**: See `test/E2E_TEST_CASES.md`
4. **Verify**:
   - Login portal without error
   - Conversations list loads (200 OK)
   - New conversation reaches "Waiting for task"
   - Agent responds to simple request

## Troubleshooting

| Issue | Check |
|-------|-------|
| 502 Bad Gateway | EC2 health, security groups |
| Token verification failed | Lambda@Edge logs (check region closest to user) |
| Redirect loop | Cookie domain settings |
| CORS errors | CloudFront response headers policy |
| CloudFront 403 | WAF rules and logs |

### Quick EC2 Debug

```bash
# SSM to EC2
aws ssm start-session --target <instance-id> --region <region>

# Check logs
docker logs openhands-app 2>&1 | grep -iE "(error|exception|failed)" | tail -20
```

## Security Scanning

```bash
./security-check.sh  # Local security check
```

CI/CD: `.github/workflows/security-scan.yml` runs on push/PR with npm audit, Checkov, Semgrep, OWASP checks.
