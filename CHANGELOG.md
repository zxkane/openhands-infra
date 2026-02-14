# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
