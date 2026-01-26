---
triggers:
- security
- iam
- waf
- cognito
- authentication
---

# Security Guidelines

## Security Components

### 1. Authentication (Cognito)

- User pools configured in `lib/auth-stack.ts`
- Custom authentication flow via `cognito_user_auth.py`
- Token validation at Lambda@Edge

### 2. WAF (Web Application Firewall)

- Configured in `lib/security-stack.ts`
- Rate limiting rules
- SQL injection protection
- XSS protection

### 3. IAM Roles

- Least privilege principle
- Service-linked roles for ECS
- Lambda execution roles

## Security Checklist

Before deploying:

1. [ ] Run security scan: `./security-check.sh` (exists in repository root)
2. [ ] Verify no secrets in code: `npm audit`
3. [ ] Check IAM policies are least-privilege
4. [ ] Ensure Cognito settings are production-ready
5. [ ] WAF rules are appropriate for traffic patterns

## Sensitive Files

These files should NEVER be committed:
- `config/config.toml` (if containing secrets)
- `.env` files
- AWS credential files

## Security Reviews

All PRs are automatically reviewed by:
- Amazon Q Developer (security findings)
- GitHub security scanning
- npm audit
