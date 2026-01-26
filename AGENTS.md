# Repository Purpose

This is an AWS CDK infrastructure project for deploying OpenHands on AWS. It provisions a complete, secure, production-ready environment for running OpenHands AI agents.

## Key Components

- **Network Stack**: VPC, subnets, NAT gateways
- **Auth Stack**: Cognito user pools and authentication
- **Compute Stack**: ECS Fargate services for agent runtime
- **Database Stack**: PostgreSQL for conversation storage
- **Edge Stack**: CloudFront + Lambda@Edge for routing
- **Monitoring Stack**: CloudWatch dashboards and alarms
- **Security Stack**: WAF, IAM roles, and security groups

## Setup Instructions

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run unit tests
npm run test

# Deploy to AWS (requires configured AWS credentials)
npx cdk deploy --all
```

## Repository Structure

- `/lib`: CDK stack definitions (TypeScript)
- `/bin`: CDK app entry point
- `/config`: Configuration files (config.toml)
- `/docker`: Custom container images and patches
- `/lambda`: Lambda function code
- `/test`: Unit tests and E2E test cases
- `/.github`: CI/CD workflows

## Development Guidelines

### Branching Strategy

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

### Testing Requirements

1. **Unit Tests**: Run `npm run test` before committing
2. **Build Verification**: Run `npm run build` to ensure TypeScript compiles
3. **E2E Tests**: Follow test cases in `test/E2E_TEST_CASES.md`

## CI/CD Workflows

- `ci.yml`: Build + all unit tests (Jest + pytest)
- Security scans: SAST, npm audit, secrets detection
- Amazon Q Developer: Automated code review
