# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-28

### Added

#### Infrastructure
- **Per-conversation EFS access points for sandbox isolation** (#36)
  - Dynamically created EFS access points for each conversation to restrict filesystem visibility to individual workspaces.
  - Process Flow:
    - Creates access point at `/sandbox-workspace/<conversation_id>` with appropriate permissions on sandbox `/start` or `/resume`.
    - Ensures isolation between tenant data during multi-conversation workflows.
  
#### Features
- **Upgraded OpenHands to v1.4.0** (#30)
  - Integrated upstream OpenHands release v1.4.0 (63 commits).
  - Upgraded Agent Server SDK from v1.8.1 to v1.11.4.
  - Cleanly applied 13 custom patches to create fork branch `custom/v1.4.0-fargate`.
  - Enhanced support for ECS Fargate task workflows, including updates to naming compatibility in SDK patch 26.
  - E2E test cases updated to reflect terminologies and behavior changes post EC2 migration.

- **ECS Fargate sandbox orchestrator with Cloud Map service discovery** (#28)
  - Deployed standalone Node.js/TypeScript/Fastify-based sandbox orchestrator service on ECS Fargate.
  - Orchestration capabilities for Fargate tasks integrated with Cloud Map private DNS at `orchestrator.openhands.local:8081`.
  - Implemented workspace isolation via per-conversation CONVERSATION_ID-based EFS subdirectories and stale record cleanup via EventBridge Task State Change events.

### Changed

#### Compute Architecture
- **Migrated all services from EC2 to ECS Fargate** (#29)
  - Fully eliminated EC2 infrastructure for compute services.
  - Introduced `ClusterStack` for ECS services shared configuration, and expanded overall architecture to 10 stacks.
  - Redesigned service deployment:
    - OpenHands app runs with 4 vCPU/8 GB memory.
    - OpenResty proxy uses 0.25 vCPU/512 MB resources.
  - Simplified secrets management with ECS-native secrets integration.

### Fixed

#### Sandbox
- **Grant Bedrock model access for sandbox task role** (#44)
  - Resolved missing `bedrock:InvokeModel` permission for sandbox Fargate tasks in production when `sandboxAwsAccess` flag was disabled, ensuring agent-server access to LLM calls.

- **Self-referencing security group rule removal** (#34)
  - Removed ingress rule on `sandboxTaskSg` allowing inter-sandbox communication across all TCP ports, reinforcing isolation security.
  - Mitigated risks of unauthorized inter-sandbox and orchestrator access.

#### Docker & Dependencies
- **Upgraded system packages in Docker images to address CVEs** (#38)
  - Executed OS-level upgrades in OpenResty (1.25.3.1 → 1.27.1.2), OpenHands app (Debian-based), and sandbox agent-server images to address multiple vulnerabilities flagged in security scans.

- **Base image upgrade for OpenResty** (#35)
  - Upgraded OpenResty base image to `1.27.1.2-alpine-fat` to address critical CVEs, replacing `1.25.3.1-alpine-fat`.

- **Fixed initialization of sandbox on SPA navigation** (#39)
  - Bug causing sandbox initialization to fail when navigating to a conversation via client-side routing fixed by adding hooks for `pushState`/`replaceState` events.

#### Deployment Issues
- **Resolved log creation issue on ECS Fargate deployments** (#43)
  - Added `/openhands/openresty` CloudWatch log group creation logic in MonitoringStack to fix Fargate container startup failures due to pre-deployment dependency on pre-created log groups.

- **Updated VPC endpoint creation logic** (#42)
  - Added parameters to skip creation of DynamoDB and specific interface endpoints, solving conflicts with pre-existing VPC endpoint configurations in production deployments.

### Documentation

#### Deployment and Architecture
- **ECS Fargate architecture documentation overhaul** (#37)
  - Updated README.md, ARCHITECTURE.md, and other guides to reflect migration from EC2 to Fargate.
  - Included revised architecture diagrams, stack organization, and Fargate service lifecycle details.

- **Emphasized git worktree usage in workflows** (#33, #41)
  - Detailed best practices and step-by-step guidance for using git worktrees within `github-workflow` processes to improve repository management consistency.

#### Best Practices
- **Consistent workflow adherence for Claude Code changes** (#41)
  - Strengthened development workflow documentation in `CLAUDE.md`, explicitly calling out common violations and mandating the use of git worktrees and GitHub action invocations before making changes.

- **Updated deployment prerequisites** (#21)
  - Clarified setup instructions for creating sandbox secret keys prior to initial deployment in `CLAUDE.md`.

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
