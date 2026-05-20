# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-05-20

### Added

#### Features
- **Upgrade OpenHands from v1.6.0 to v1.7.0** (#81)
  - Upgraded OpenHands from v1.6.0 → v1.7.0, incorporating 296 commits and multiple SDK enhancements (v1.15.0 → v1.19.1).
  - Removed deprecated V0 packages, simplifying deployment structure.
  - Improved `llm_config` field compatibility for newer Bedrock inference profiles.
  - Fork updated: `custom/v1.7.0-fargate-r2` (28 cherry-picked commits from v1.6.0).
- **Adaptive thinking support for Claude Opus 4.7 on Bedrock** (#83)
  - Adds SDK Patch 34 (`patch_34_opus_47_adaptive_thinking`) which rewrites kwargs in `chat_options.py` for Claude Opus 4.7 / Mythos Preview models so the Bedrock Converse API receives `thinking={"type":"adaptive"}` plus top-level `output_config={"effort": ...}` instead of the rejected legacy `thinking={"type":"enabled","budget_tokens":...}` shape.
  - Without this fix, switching to `bedrock/global.anthropic.claude-opus-4-7` failed with `BedrockException - "thinking.type.enabled" is not supported for this model`.
  - Other models (Sonnet 4.6/4.5, Haiku 4.5, Opus 4.5) keep the legacy extended-thinking path.
  - Stop-gap pending upstream litellm support; tracks BerriAI/litellm #25957, #27168, #26334.

#### Testing
- **TC-035: Claude Adaptive-Thinking Models on Bedrock** (#83)
  - New E2E test case in `test/E2E_TEST_CASES.md` covering adaptive-only Claude models. Closes the coverage gap that allowed the Opus 4.7 regression to ship in the v1.7.0 upgrade — TC-006 / TC-023 only ever exercised Sonnet 4.6 (default) and Haiku 4.5, both of which accept the legacy `thinking.type=enabled` shape.
  - Asserts on `/openhands/sandbox` CloudWatch logs (load-bearing — OpenHands retries `BadRequestError`, so UI alone gives false confidence). Wired into `test/select-e2e-tests.sh` to auto-trigger on any change under `docker/agent-server-custom/`.

#### Developer Experience
- **Skills Refresh: autonomous-dev-team** (#78)
  - Re-installed and refreshed all autonomous-dev-team skills (`autonomous-common`, `autonomous-dev`, `autonomous-dispatcher`, `autonomous-review`, `create-issue`) to their latest versions for enhanced workflow automation.
  - Added new `skillPath` field for future updates using `npx skills update`.
- **Hooks symlink for autonomous-dev SKILL.md frontmatter resolution** (#75)
  - Adds the `hooks` → `.claude/skills/autonomous-common/hooks` symlink convention so workflow hooks resolve correctly in both the main checkout and per-feature worktrees.

### Changed

#### Platform Updates
- **Default LLM model is now `bedrock/global.anthropic.claude-sonnet-4-6`** (#82)
  - SDK Patch 33 changes the LLM Pydantic default from upstream `claude-sonnet-4-20250514` (Anthropic direct API, requires `ANTHROPIC_API_KEY`) to the Bedrock cross-region inference profile.
  - Prevents fresh conversations with no `agent_settings.llm.model` from falling back to a model that requires an API key the deployment doesn't have, and from freezing that bad default into `base_state.json` on EFS.
- **Pin Docker Base Image to Manifest Digest** (#74)
  - Updated Docker base image references (`openhands:1.6.0`) to specific `sha256` digests, ensuring deterministic builds and avoiding stale cache issues.

#### CI/CD
- **Upgrade GitHub Actions to Node.js 24 Versions** (#80)
  - Resolved deprecation warnings by updating GitHub Actions workflows (`checkout`, `setup-node`, `setup-python`, `github-script`, `upload-artifact`) to latest Node.js 24-compatible versions.

#### Security Updates
- **Upgrade aws-cdk-lib to v2.248.0** (#68)
  - Bumped `aws-cdk-lib` dependency, resolving npm audit findings:
    - **High:** ReDoS vulnerabilities in minimatch `<10.2.3`.
- **Bump non-major dependencies to latest** (#79)
  - Routine npm dependency refresh.

#### Documentation
- **Tighten Rule 1 step 3 of `CLAUDE.md`: explicit user instruction required for merge** (#84)
  - Documents that CI / hook / review signals do not imply merge approval; only the user's explicit `merge` / `merge it` (or equivalent) does.

### Fixed

#### Infrastructure
- **Alpine Package Upgrades in Dockerfiles** (#76, #77)
  - Applied `apk upgrade --no-cache` to multiple Dockerfiles, patching critical CVEs in libraries (openssl, zlib, musl).
- **Force base image re-pull via `LAST_UPDATED` bump** (#73)
  - Bumps the build-arg sentinel so CDK rebuilds the image and pulls the freshest base layer.
- **Revert extra fork patches that broke the base image** (#72)
  - Restores a clean baseline after a regression introduced by a prior patch batch.

#### Developer Tools
- **Restore Missing Fork Patches** (#70, #71)
  - Added missing fork-specific files in `download-fork-patches.sh` to resolve `ImportError` issues during container startup (`skills`/`hooks` API endpoints, `settings.py`).
- **Sync `settings.json` with autonomous-dev-team plugin hooks** (#69)
  - Aligns the project hooks config with the upstream skills package after refresh.

[1.4.0]: https://github.com/zxkane/openhands-infra/compare/v1.3.0...v1.4.0

## [1.3.0] - 2026-04-09

### Changed

#### Platform Updates
- **Upgrade OpenHands from v1.4.0 to v1.6.0** (#65)
  - Merged 341 upstream commits, upgrading the base OpenHands image, SDK (v1.11.5 → v1.15.0), and runtime.
  - Removed custom `S3EventService` module — upstream v1.6.0 ships native `AwsEventService` with identical S3 path format, making the custom implementation redundant.
  - Updated `_build_service_url` patch for new 3-arg signature in v1.6.0 (`url, service_name, runtime_id`).
  - Aligned orchestrator STATUS_MAP values with upstream expectations (`starting`/`error` instead of `pending`/`failed`).
  - Removed deprecated `send_telemetry` config key (removed upstream in v1.6.0).
  - Fork: `custom/v1.6.0-fargate-r1` (20 cherry-picked commits from v1.4.0 fork).

#### Developer Experience
- **Replace github-workflow skill with autonomous-dev-team** (#66)
  - Migrated from custom `github-workflow` skill to upstream [autonomous-dev-team](https://github.com/zxkane/autonomous-dev-team) skills.
  - New skills (`autonomous-dev`, `autonomous-review`, `autonomous-common`, `autonomous-dispatcher`, `create-issue`) support Claude Code, Kiro CLI, and Codex agents.
  - Install via `npx skills add zxkane/autonomous-dev-team -s '*' -a claude-code -a kiro-cli -a codex -y`.

### Fixed

#### CI/CD
- **Add retention-days to security scan artifacts** (#64)
  - Set `retention-days: 3` on security scan artifact uploads to prevent GitHub Actions storage quota exhaustion (was defaulting to 90 days, causing 912 accumulated artifacts).

### Security

- Fixed npm CVEs: handlebars 4.7.9, fast-xml-parser 5.5.10, minimatch 10.2.5, picomatch 4.0.4, path-to-regexp 8.4.2, brace-expansion 5.0.5 (#65)

[1.3.0]: https://github.com/zxkane/openhands-infra/compare/v1.2.0...v1.3.0

## [1.2.0] - 2026-03-11

### Added

#### Sandboxes
- **Startup timing instrumentation and SOCI support** (#58)
  - Added structured timing logs (`sandbox-startup-timing`) to benchmark sandbox startup phases in `/start` and `/resume` routes.
  - Integrated SOCI v2 index generation via `soci convert` for Fargate lazy image loading (requires `soci` CLI >= v0.10).
  - Introduced `sandboxSociImageUri` CDK context parameter for SOCI-enabled sandbox image override.
  - Exported sandbox image ECR URI as `CfnOutput` for SOCI index generation scripts.

### Changed

#### Documentation
- **Improved README for discoverability and engagement** (#60)
  - Restructured README to include a hero section, badges, and explicit value propositions.
  - Transformed features list into an emoji-tagged Key Features section for easier scanning.
  - Enhanced comparison tables and quick links for first-time visitor comprehension.

### Fixed

#### Docker
- **Correct VS Code port mapping from 60001 to 8001** (#62)
  - Resolved 502 runtime subdomain errors caused by incorrect port mapping (`60001` → `8001`) in `patch-exposed-urls.py`.
  - Fixed `can_connect(ip, 60001)` requests that failed to establish upstream connections due to mismatched port configurations in the agent-server SDK.

- **Preserve project/<repo> path for nested repo git changes** (#61)
  - Corrected empty Changes tab for conversations linked to GitHub repositories.
  - Updated `normalizeGitUrl()` to preserve `project/<repo>` paths for accurate nested repo resolution.
  - Removed unnecessary intermediate `git init /workspace/project` repo creation shadowing actual repo changes.

- **Normalize git API paths for connected repos** (#59)
  - Fixed 500 errors in git Changes tab when connecting GitHub repositories to conversations.
  - Adjusted `patch-fix.js` to properly normalize workspace paths containing nested repo directories.

[1.2.0]: https://github.com/zxkane/openhands-infra/compare/v1.1.0...v1.2.0

## [1.1.0] - 2026-03-06

### Added

#### Storage
- **S3 event persistence for conversations** (#56)
  - Introduced `S3EventService` to replace `FilesystemEventService` when `FILE_STORE=s3`.
  - Persisted events to S3 for survival across Fargate task restarts and long-term history for archived conversations.
  - Upgraded `openhands-tools` to v1.11.5 to resolve agent-server SDK mismatches.

#### Sandboxes
- **Conversation archival and lifecycle management** (#54)
  - Added ARCHIVED state for conversations with configurable retention policies.
  - Supported user-initiated conversation deletion and data lifecycle transitions:
    - ARCHIVED conversations retain event history in S3 but can no longer resume.
    - Deleted conversations wipe all associated data.

#### Compute
- **Target tracking auto scaling and rightsizing of app Fargate tasks** (#53)
  - Downsized app Fargate tasks from **4 vCPU / 8 GB** to **1 vCPU / 2 GB** based on CloudWatch metrics.
  - Implemented auto-scaling (1-3 tasks) for both the App and OpenResty services.
  - Achieved ~75% reduction in baseline Fargate costs, reflected in updated README.md cost estimates.
  
- **Bedrock LLM model selection support** (#49)
  - Enabled user-selectable Bedrock LLM models via OpenHands model selection UI.
  - Updated default model to Claude Sonnet 4.6 for optimal cost-performance balance.

#### Documentation
- **Updated documentation with AGENTS.md migration** (#48)
  - Consolidated tool-agnostic documentation into AGENTS.md, standardizing compatible AI coding tools.
  - Added workflow enforcement hooks to prevent direct pushes to the main branch.

### Changed

#### Platform Updates
- **Lambda Node.js runtime upgrade** (#52)
  - Migrated all custom AWS Lambda functions from `NODEJS_22_X` to `NODEJS_24_X`, the latest LTS runtime.

### Fixed

#### Sandboxes
- **Orphan ECS task detection in idle monitor** (#50)
  - Implemented logic to detect and terminate orphan ECS tasks caused by race conditions during concurrent `/resume` requests.

#### Docker and SDK
- **Bedrock improvements and patches for agent-server SDK** (#51)
  - Backported Bedrock updates and patches from OpenHands upstream forks.
  - Resolved Kimi K2.5 max_output_tokens errors with custom SDK patch.

[1.1.0]: https://github.com/zxkane/openhands-infra/compare/v1.0.0...v1.1.0

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
