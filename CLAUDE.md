# CLAUDE.md

## Development Workflow (MANDATORY)

**CRITICAL**: All feature development, bug fixes, and dependency updates MUST strictly follow the `github-workflow` skill.

### Rule 1: ALWAYS Invoke the Skill First

Before ANY code changes — features, fixes, refactors, dependency bumps — you MUST:
1. **Invoke skill**: Use `/github-workflow` or read `.claude/skills/github-workflow/SKILL.md`
2. **Follow ALL 10 steps** in order — NO shortcuts, NO skipping steps
3. **Do NOT merge** - Report status and wait for user decision

**Common violation**: Skipping skill invocation and jumping straight to coding. This causes missed steps (reviewer bot iteration, PR templates, E2E test selection). The skill is not optional guidance — it is the required process.

### Rule 2: ALWAYS Use Git Worktrees for Code Changes

**Every** branch that changes code MUST use a worktree for isolation:
```bash
git fetch origin main
git worktree add .worktrees/<name> -b <type>/<name> origin/main
cd .worktrees/<name>
npm install   # worktrees don't share node_modules
# ... do all work here ...
```

After merge, clean up:
```bash
git worktree remove .worktrees/<name>
git branch -d <type>/<name>
```

**Common violation**: Using `git checkout -b` on the main working tree. This pollutes the workspace and risks uncommitted changes interfering with the feature branch.

**Only exception**: Trivial docs-only changes (README typos) with zero code impact.

### Rule 3: Complete ALL Workflow Steps

The 10-step workflow is not a suggestion — every step must be completed:
- Step 1: Create **worktree** + branch (not `git checkout -b`)
- Step 2: Implement + write/update tests
- Step 3: Build + test locally
- Step 4: Commit + create PR with checklist template
- Steps 5-7: CI checks + address ALL reviewer bot findings + iterate until clean
- Steps 8-9: Deploy to staging + run E2E tests (use `test/select-e2e-tests.sh`)
- Step 10: Report ready status (DO NOT MERGE unless user explicitly says to)

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

### Optional Context Parameters

- `skipS3Endpoint` - Skip S3 Gateway endpoint if VPC already has one
- `sandboxAwsAccess` - Enable sandbox AWS access (default: false)
- `sandboxAwsPolicyFile` - Path to custom IAM policy for sandbox
- `warmPoolSize` - Pre-warmed sandbox Fargate tasks (default: 2)
- `idleTimeoutMinutes` - Sandbox idle timeout (default: 30, staging: 10)
- `edgeStackSuffix` - Suffix for Edge stack name (multi-environment)
- `authCallbackDomains` - OAuth callback domains (JSON array or comma-separated)
- `authDomainPrefixSuffix` - Cognito domain prefix suffix (default: "shared")

### Prerequisites (First-Time Deployment)

Create sandbox secret key before first deployment:
```bash
aws secretsmanager create-secret --name openhands/sandbox-secret-key \
  --secret-string "$(openssl rand -base64 32)" --region <your-main-region> \
  --description "OpenHands sandbox secret key for session encryption"
```

## Architecture (10 Stacks)

```
AuthStack (us-east-1) ← Cognito User Pool (shared across domains)
    ↓
NetworkStack (main region)
    ↓
SecurityStack ← depends on Network, creates KMS key, Fargate roles
    ↓
MonitoringStack ← independent, S3 data bucket
    ↓
DatabaseStack ← depends on Network + Security
    ↓
UserConfigStack ← depends on Security (KMS) + Monitoring (S3), creates Lambda
    ↓
ClusterStack ← depends on Network, shared ECS cluster + Cloud Map namespace
    ↓
SandboxStack ← depends on Network + Monitoring + Cluster
    ↓
ComputeStack ← depends on Network + Security + Monitoring + Database + UserConfig + Cluster + Sandbox
    ↓           (Fargate services for app + OpenResty, ALB, routes /api/v1/user-config/* to Lambda)
EdgeStack (us-east-1) ← depends on Compute + Auth
```

**Self-healing**: Aurora PostgreSQL + S3 + EFS preserve data across Fargate task replacements.

## Conversation Data Storage

Dual storage architecture — app-server writes to S3 (authority), sandbox SDK writes to EFS (cache):

| Data Type | Storage | Written By | Notes |
|-----------|---------|-----------|-------|
| Conversation metadata | Aurora PostgreSQL | App server | User ID, title, timestamps |
| Conversation events | **S3** (`FILE_STORE=s3`) | App server | Authority for UI display |
| User settings / secrets | S3 | App server | LLM config, API keys |
| Workspace code | **EFS** | Sandbox agent-server | `/workspace/project` persisted via access point |
| SDK conversation cache | **EFS** | Sandbox agent-server SDK | `events/`, `base_state.json` — LLM context restoration |

### SDK Conversation Cache (`OH_CONVERSATIONS_PATH`)

- Entrypoint sets `OH_CONVERSATIONS_PATH=/mnt/efs` in sandbox container
- **SDK hardcoded behavior**: Creates `<CID_hex>/` subdirectory (UUID without hyphens)
- Path on EFS: `/sandbox-workspace/<CID>/<CID_hex>/events/` (AP root + SDK subdir)
- This cache enables fast LLM context restoration on sandbox restart
- Losing this cache (e.g., migration) is non-fatal — UI history loads from S3, LLM restarts without prior context

### Per-Conversation EFS Isolation

Each sandbox mounts an EFS access point rooted at `/sandbox-workspace/<conversation_id>/`:
- Container sees `/mnt/efs/` = access point root (cannot traverse to parent/sibling directories)
- On `/start` and `/resume`: orchestrator creates AP → registers task def → RunTask
- On `/stop`, `/pause`, crash: cleanup AP + deregister task def
- Access point lifecycle managed by orchestrator, idle monitor Lambda, and task state Lambda

### IAM Permissions for EFS Access Points

| Action | Required Resource ARN |
|--------|----------------------|
| `CreateAccessPoint`, `TagResource` | `arn:...:file-system/<id>` |
| `DeleteAccessPoint`, `DescribeAccessPoints` | `arn:...:access-point/*` |
| `ecs:RegisterTaskDefinition` with tags | `ecs:TagResource` on `*` |

Must include **both** file-system and access-point ARNs in IAM policies.

## Key Files

| File | Purpose |
|------|---------|
| `bin/openhands-infra.ts` | CDK entry point |
| `lib/interfaces.ts` | Stack I/O interfaces |
| `lib/*-stack.ts` | Individual stack definitions (10 stacks) |
| `lib/cluster-stack.ts` | Shared ECS cluster + Cloud Map |
| `lib/sandbox-stack.ts` | Sandbox orchestration (DynamoDB, Lambda, Fargate tasks) |
| `config/config.toml` | OpenHands app config (LLM, sandbox) |
| `config/sandbox-aws-policy.json` | Customizable IAM policy for sandbox |
| `docker/patch-fix.js` | Frontend patches (URL rewriting) |
| `docker/openresty/` | OpenResty proxy container (Fargate service) |
| `lambda/user-config/` | User config API Lambda |
| `lambda/sandbox-monitor/` | Sandbox idle monitor Lambda |
| `lambda/sandbox-task-state/` | ECS task state change handler Lambda |
| `lambda/db-bootstrap/` | Database bootstrap custom resource Lambda |
| `lib/lambda-edge/` | Lambda@Edge handlers |
| `test/E2E_TEST_CASES.md` | E2E test cases |
| `docs/ARCHITECTURE.md` | Architecture deep dive |
| `.github/workflows/release-prepare.yml` | Automated release PR with LLM changelog |
| `.github/workflows/release-publish.yml` | Auto tag + GitHub Release on merge |

## User Configuration (Multi-Tenant)

Per-user customization stored in S3:
- **MCP Servers**: Custom servers that extend/override global config
- **Encrypted Secrets**: API keys with KMS envelope encryption
- **Integrations**: GitHub, Slack with auto-MCP support

Feature flag: `USER_CONFIG_ENABLED` environment variable on Fargate app service (auto-set when KMS key exists).

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
  OpenHands-Database OpenHands-UserConfig OpenHands-Cluster \
  OpenHands-Sandbox OpenHands-Compute OpenHands-Edge \
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
| Compute/Edge/Network/Cluster | Exclude Auth stack |
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
| 502 Bad Gateway | ECS service health, target group targets |
| Token verification failed | Lambda@Edge logs (check region closest to user) |
| Redirect loop | Cookie domain settings |
| CORS errors | CloudFront response headers policy |
| CloudFront 403 | WAF rules and logs |
| Service not starting | ECS task stopped reason, CloudWatch logs |

### Quick ECS Debug

```bash
# Check ECS services
aws ecs describe-services --cluster <cluster-name> \
  --services openhands-app openhands-openresty --region <region>

# Tail app logs
aws logs tail /openhands/application --follow --region <region>

# ECS exec into app container
aws ecs execute-command --cluster <cluster-name> --task <task-id> \
  --container openhands-app --interactive --command "/bin/bash" --region <region>
```

## Release Process (Automated)

Releases are automated via two GitHub Actions workflows.

### Creating a Release

1. **Trigger** `release-prepare.yml` via GitHub Actions UI with the version number (e.g., `0.4.0`)
2. The workflow automatically:
   - Gathers commits since last tag, enriches with PR data
   - Generates changelog via GitHub Models (GPT-4o) using existing CHANGELOG.md format
   - Bumps `package.json`, prepends changelog to `CHANGELOG.md`
   - Creates `release/v{version}` branch and opens a PR
3. **Review** the generated PR — edit changelog if needed
4. **Merge** the PR to trigger `release-publish.yml`, which creates the git tag and GitHub Release

### Key Files

| File | Purpose |
|------|---------|
| `.github/workflows/release-prepare.yml` | Manual trigger: changelog generation + release PR |
| `.github/workflows/release-publish.yml` | Auto trigger: tag + GitHub Release on PR merge |

### Prerequisites

- Repo setting **"Allow GitHub Actions to create and approve pull requests"** must be enabled (Settings > Actions > General > Workflow permissions)

## Security Scanning

```bash
./security-check.sh  # Local security check
```

CI/CD: `.github/workflows/security-scan.yml` runs on push/PR with npm audit, Checkov, Semgrep, OWASP checks.
