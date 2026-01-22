#!/bin/bash

# Security Check Script for OpenHands Infrastructure
# This script checks for the security issues identified in the security review

set -e

echo "========================================="
echo "OpenHands Infrastructure Security Check"
echo "========================================="
echo ""

ISSUES_FOUND=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check 1: Hardcoded secrets in Lambda@Edge
echo "Checking for hardcoded secrets in Lambda@Edge..."
if grep -q "unsafeUnwrap()" lib/edge-stack.ts 2>/dev/null; then
    echo -e "${RED}[CRITICAL] Found hardcoded secret using unsafeUnwrap() in edge-stack.ts${NC}"
    echo "  Location: lib/edge-stack.ts"
    echo "  Fix: Use AWS Secrets Manager instead of hardcoding secrets"
    ((CRITICAL_ISSUES++))
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] No unsafeUnwrap() usage found${NC}"
fi
echo ""

# Check 2: Path traversal in config reading
echo "Checking for path traversal vulnerabilities..."
if ! grep -q "path.resolve" lib/compute-stack.ts 2>/dev/null; then
    echo -e "${YELLOW}[HIGH] Missing path validation in compute-stack.ts${NC}"
    echo "  Location: lib/compute-stack.ts:readOpenHandsConfig()"
    echo "  Fix: Add path validation using path.resolve() and startsWith() check"
    ((HIGH_ISSUES++))
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] Path validation appears to be present${NC}"
fi
echo ""

# Check 3: Overly permissive IAM policies
echo "Checking for overly permissive IAM policies..."
if grep -q "resources: \['\\*'\]" lib/security-stack.ts 2>/dev/null; then
    echo -e "${YELLOW}[HIGH] Found wildcard resources in IAM policies${NC}"
    echo "  Location: lib/security-stack.ts"
    echo "  Fix: Restrict resources to specific ARNs"
    ((HIGH_ISSUES++))
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] No wildcard resources in IAM policies${NC}"
fi
echo ""

# Check 4: User data injection
echo "Checking for user data injection risks..."
if grep -q "readOpenHandsConfig()" lib/compute-stack.ts 2>/dev/null && ! grep -q "base64" lib/compute-stack.ts 2>/dev/null; then
    echo -e "${YELLOW}[HIGH] Config content directly embedded without encoding${NC}"
    echo "  Location: lib/compute-stack.ts:userData"
    echo "  Fix: Base64 encode config content before embedding"
    ((HIGH_ISSUES++))
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] Config content appears to be properly handled${NC}"
fi
echo ""

# Check 5: Security headers in CloudFront
echo "Checking for security headers configuration..."
if ! grep -q "responseHeadersPolicy" lib/edge-stack.ts 2>/dev/null; then
    echo -e "${YELLOW}[MEDIUM] Missing security headers policy in CloudFront${NC}"
    echo "  Location: lib/edge-stack.ts"
    echo "  Fix: Add responseHeadersPolicy with CSP, X-Frame-Options, etc."
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] Security headers policy found${NC}"
fi
echo ""

# Check 6: Customer-managed KMS keys
echo "Checking for KMS key configuration..."
if ! grep -q "kmsKey" lib/compute-stack.ts 2>/dev/null; then
    echo -e "${YELLOW}[MEDIUM] Using default AWS-managed keys for encryption${NC}"
    echo "  Location: lib/compute-stack.ts"
    echo "  Fix: Implement customer-managed KMS keys"
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] Customer-managed KMS keys configured${NC}"
fi
echo ""

# Check 7: Secrets in tracked files
echo "Checking for secrets in tracked files..."
if command -v git-secrets &> /dev/null; then
    # Allow placeholder AWS account ID used in tests and CDK examples
    git secrets --add --allowed '123456789012' 2>/dev/null || true
    # Only scan tracked files, not git history or untracked/gitignored files
    # This avoids false positives from local config files like cdk.context.json
    if ! git ls-files -z | xargs -0 git secrets --scan -- 2>/dev/null; then
        echo -e "${RED}[CRITICAL] Potential secrets found in tracked files${NC}"
        echo "  Fix: Remove secrets from tracked files"
        ((CRITICAL_ISSUES++))
        ((ISSUES_FOUND++))
    else
        echo -e "${GREEN}[PASS] No secrets detected in tracked files${NC}"
    fi
else
    echo -e "${YELLOW}[WARNING] git-secrets not installed, skipping check${NC}"
fi
echo ""

# Check 8: Check for .env files that shouldn't be committed
echo "Checking for environment files..."
if ls .env* 2>/dev/null | grep -v ".example" > /dev/null; then
    echo -e "${RED}[HIGH] Found .env files that might contain secrets${NC}"
    echo "  Fix: Ensure .env files are in .gitignore"
    ((HIGH_ISSUES++))
    ((ISSUES_FOUND++))
else
    echo -e "${GREEN}[PASS] No .env files found${NC}"
fi
echo ""

# Check 9: Dependencies with known vulnerabilities
echo "Checking npm dependencies for vulnerabilities..."
if command -v npm &> /dev/null; then
    npm_audit=$(npm audit --json 2>/dev/null | jq '.metadata.vulnerabilities.critical + .metadata.vulnerabilities.high' 2>/dev/null || echo "0")
    if [ "$npm_audit" != "0" ] && [ "$npm_audit" != "" ]; then
        echo -e "${YELLOW}[MEDIUM] Found vulnerable npm dependencies${NC}"
        echo "  Run 'npm audit' for details"
        ((ISSUES_FOUND++))
    else
        echo -e "${GREEN}[PASS] No critical npm vulnerabilities${NC}"
    fi
else
    echo -e "${YELLOW}[WARNING] npm not found, skipping dependency check${NC}"
fi
echo ""

# Summary
echo "========================================="
echo "Security Check Summary"
echo "========================================="
echo -e "Critical Issues: ${RED}${CRITICAL_ISSUES}${NC}"
echo -e "High Issues: ${YELLOW}${HIGH_ISSUES}${NC}"
echo -e "Total Issues Found: ${ISSUES_FOUND}"
echo ""

if [ $CRITICAL_ISSUES -gt 0 ]; then
    echo -e "${RED}⚠️  CRITICAL SECURITY ISSUES FOUND - DO NOT DEPLOY TO PRODUCTION${NC}"
    exit 1
elif [ $HIGH_ISSUES -gt 0 ]; then
    echo -e "${YELLOW}⚠️  HIGH SECURITY ISSUES FOUND - ADDRESS BEFORE PRODUCTION${NC}"
    exit 1
elif [ $ISSUES_FOUND -gt 0 ]; then
    echo -e "${YELLOW}⚠️  SECURITY ISSUES FOUND - REVIEW AND ADDRESS${NC}"
    exit 0
else
    echo -e "${GREEN}✅ All security checks passed!${NC}"
    exit 0
fi