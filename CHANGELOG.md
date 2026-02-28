# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-28

### Added

#### Infrastructure
- **Per-conversation EFS access points for multi-tenant isolation** (#36)
  - Dynamically create EFS access points per conversation to enforce isolated filesystem access for sandbox containers.
  - On sandbox `/start` or `/resume`, EFS access points are created at `/sandbox-workspace/<conversation_id>` with uid/gid 1000.

#### Compute
- **Migration from EC2 to ECS Fargate for all services** (#29)
  - Eliminated dependency on EC2 instances, Launch Templates, and Auto Scaling Groups.
  - Expanded architecture to 10 stacks, introducing a shared ECS cluster (ClusterStack).
  - Migrated OpenHands app service to ECS Fargate task setup: 4 vCPU, 8 GB RAM.
  - Migrated OpenResty proxy service: 0.25 vCPU, 512 MB RAM.
  - ECS native secrets integration for `OH_SECRET_KEY` and `DB_PASS`.
  
- **ECS Fargate sandbox orchestrator with Cloud Map service discovery** (#28)
  - Implemented a TypeScript-based Fastify orchestrator service for sandbox operations (RunTask, StopTask, DescribeTasks, cleanup stale records).
  - Integrated private DNS resolution using Cloud Map (`orchestrator.openhands.local:8081`).
  - Added EventBridge + Lambda-driven cleanup of stale ECS Tasks.

#### Enhancements
- **Upgrade OpenHands to v1.4.0** (#30)
  - Updated OpenHands runtime from 1.3.0 to 1.4.0 (63+ upstream commits merged).
  - Upgraded Agent Server SDK from v1.8.1 to v1.11.4, including 13 custom patches.
  - Improved E2E testing coverage with updated test cases reflecting ECS Fargate migration.

### Changed

#### Deployment Workflow
- **GitHub Actions release process improvement** (#46)
  - Switched from default `GITHUB_TOKEN` to GitHub App token for triggering dependent workflows.
  - Ensures the `build-and-test` CI workflow triggers correctly on release PRs.

### Fixed

#### Infrastructure
- **Bedrock model access for sandbox task role** (#44)
  - Added `bedrock:InvokeModel` permission to the `sandboxTaskRole` to resolve access errors in production deployments.

- **Explicit creation of CloudWatch log groups in MonitoringStack** (#43)
  - Fixed OpenResty container startup failure due to missing CloudWatch log groups.
  - Addressed incorrect assumption that ECS Fargate auto-creates log groups with the `awslogs` driver.

- **Skip parameters for conflicting VPC endpoints** (#42)
  - Added `skipDynamoDbEndpoint` and `skipInterfaceEndpoints` parameters to prevent conflicts during production deployments caused by pre-existing VPC endpoints.

#### Security
- **Remove self-referencing Sandbox Security Group rule** (#34)
  - Removed ingress rules allowing inter-sandbox communications on all TCP ports to enhance network isolation and security.

#### Docker Images
- **Resolved CVEs in system packages for all Docker images** (#38)
  - Upgraded system packages in OpenResty, App (OpenHands), and Sandbox images using `apt-get` and `apk` commands.
  - Addressed critical OS-level vulnerabilities flagged during reliability scans.

- **Updated OpenResty base image for CVE remediation** (#35)
  - Migrated to `openresty/openresty:1.27.1.2-alpine-fat` from `1.25.3.1-alpine-fat`.

#### Sandboxes
- **Fix sandbox status initialization on SPA navigation** (#39)
  - Patched sandbox auto-initialization for client-side navigation (`pushState`/`popstate`) on the OpenHands dashboard.
  
- **Register conversation with agent-server during resume** (#31)
  - Ensured conversations are registered with the agent-server API (`POST /api/conversations`) after resuming sandboxes.

- **Handle `.git` ownership issues on sandbox stop/resume** (#32)
  - Addressed HTTP 500 errors caused by mismatched permissions in the `.git` workspace folder during sandbox resume.

### Documentation

#### Deployment Guide
- **ECS Fargate architecture update** (#37)
  - Comprehensive restructuring of architecture documentation to match recent migration updates.
  - Updated deployment prerequisites, stack details, and diagrams.

#### Development Workflow
- **Git worktree guidance added** (#33)
  - Enhanced `github-workflow` skill with clear instructions and common error avoidance tips for using git worktrees efficiently.

[1.0.0]: https://github.com/zxkane/openhands-infra/compare/v0.3.0...v1.0.0

## [0.3.0] - 2026-02-14

### Added

#### CI/CD Automation
- **Automated release workflows integrated with LLM-generated changelogs** (#26)
  - Introduced two GitHub Actions workflows:
    - `release-prepare.yml` for manual release preparation with commit/PR enrichment and LLM-assisted changelog generation.
    - `release-publish.yml` for automated version tagging and package publishing.

#### Infrastructure
- **OpenHands upgraded to v1.3.0** (#22)
  - Upgraded from v1.2.1 with support for new upstream features:
    - CORS environment variable `OH_ALLOW_CORS_ORIGINS_0` for customizable origins.
    - Host network mode enabled via `OH_SANDBOX_USE_HOST_NETWORK=true`.
  - Applied multi-tenant conversation isolation update (Patch 27) and webhook callback UUID + secret fixes (Patches 28/29).

### Changed

#### Code Refactor
- Replaced runtime regex patching with fork-based patches (#23):
  - Deprecated `apply-patch.sh` with 29 regex-based patches and introduced clean upstream modifications stored in `zxkane/openhands@custom-v1.3.0-r1`.
  - Consolidated patching process to Docker build time, reducing container startup complexity.

### Fixed

#### Mobile Interface
- **Fix for iPhone historical conversation messages** (#24):
  - Addressed viewport-specific React component remounts causing conversation history issues.
  - Replaced synchronous DOM walking with `requestIdleCallback`-based batched processing to improve performance.
  - Applied temporary React Fiber patch to resolve stuck skeleton loading state on mobile viewports.

### Documentation

#### Deployment Guide
- Added prerequisites for creating sandbox secret key before first-time deployment (#21):
  - Updated README.md to include a required step for configuring the `sandbox secret key`.
  - Prerequisites documented in `CLAUDE.md` with accompanying CLI command examples.

[0.3.0]: https://github.com/zxkane/openhands-infra/compare/v0.2.0...v0.3.0

## [0.2.0] - 2026-02-02

### Added

#### Cost Management
- **Dynamic cost allocation tags** via CDK context (#14)
  - `STAGE` tag auto-detected from domainName (`test.*` → staging, otherwise production)
  - `Project` and `Purpose` tags configurable via `--context` parameters
  - All tags integrated with AWS Cost Allocation for billing visibility

### Fixed

#### Authentication & Security
- **Runtime subdomain cookie access** - Changed `SameSite=Lax` to `SameSite=None` in Lambda@Edge auth handler to enable cookies on cross-subdomain fetch requests (#16)
- **npm package vulnerabilities** - Added override for `fast-xml-parser` to v5.3.4 to fix GHSA-37qj-frw5-hhjh RangeError DoS bug (#18)

#### Sandbox & Conversation Resume
- **Conversation resume after EC2 replacement** - Pass `OH_SECRET_KEY` to sandbox containers via Secrets Manager for encrypted secrets decryption (#17)
- **Bedrock token expiration** - Fixed by using EC2 instance role instead of sandbox STS credentials for LLM calls (#17)

#### Frontend Patches
- **MCP server deduplication** - Intercept XMLHttpRequest instead of fetch to prevent global MCP servers from being duplicated in user settings (#15)
- **Global MCP server protection** - Disable Edit/Delete buttons for system-managed MCP servers defined in config.toml (#15)

[0.2.0]: https://github.com/zxkane/openhands-infra/releases/tag/v0.2.0

## [0.1.0] - 2026-01-29

### Added

#### Infrastructure (8 CDK Stacks)
- **AuthStack** - Cognito User Pool with OAuth2, managed login, and custom email templates
- **NetworkStack** - VPC configuration with endpoints for AWS services
- **SecurityStack** - KMS keys, IAM roles, security groups
- **MonitoringStack** - CloudWatch dashboards, alarms, S3 data bucket
- **DatabaseStack** - Aurora Serverless v2 PostgreSQL with RDS Proxy
- **UserConfigStack** - User configuration API (Lambda) for multi-tenant MCP management
- **ComputeStack** - EC2 Auto Scaling with Graviton (ARM64) instances
- **EdgeStack** - CloudFront distribution, Lambda@Edge handlers, WAF rules

#### Authentication & Security
- Cognito authentication with 30-day sessions
- Silent token refresh using refresh_token (#11)
- Logout button patch for Cognito authentication (#9)
- Custom Cognito email templates for OpenHands branding (#8)
- Cross-user authorization for runtime requests (#1)
- Multi-domain Cognito callback URL support (#2, #6)
- WAF protection on CloudFront
- Origin verification headers (direct ALB access blocked)
- VPC Endpoints for AWS services
- KMS encryption for secrets

#### Runtime & Compute
- Runtime subdomain routing for user applications
- VS Code URL rewriting for proper subdomain access
- Sandbox AWS access with scoped IAM credentials (#7)
- AWS CLI included in agent-server image (#7)
- Archived conversation resume after EC2 replacement (#3)
- Self-healing architecture with S3 + EFS persistence

#### User Configuration (Multi-Tenant)
- User configuration API for multi-tenant MCP management (#10)
- Per-user MCP server configuration
- Encrypted secrets storage with KMS
- GitHub and Slack integrations support

#### MCP Integration
- AWS Documentation MCP server (shttp)
- Chrome DevTools MCP server (stdio) with correct args (#4)

#### Developer Experience
- GitHub workflow skill with 10-step development process (#12)
- Support for multiple reviewer bots (Amazon Q, Codex)
- PR checklist template and update requirements
- Comprehensive E2E test cases documentation
- OpenHands skills integration (#5)
- CI workflow with security scanning (#3)

### Infrastructure Details

| Component | Technology |
|-----------|------------|
| Compute | EC2 m7g.xlarge (Graviton ARM64) |
| Database | Aurora Serverless v2 PostgreSQL |
| CDN | CloudFront with Lambda@Edge |
| Auth | Cognito User Pool (OAuth2) |
| Storage | S3 (data) + EFS (workspaces) |
| Container | Docker with Watchtower auto-updates |
| Proxy | OpenResty for runtime routing |

[0.1.0]: https://github.com/zxkane/openhands-infra/releases/tag/v0.1.0
