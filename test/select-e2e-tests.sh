#!/bin/bash
#
# E2E Test Selector
# Automatically determines which E2E tests to run based on changed files.
#
# Usage:
#   ./test/select-e2e-tests.sh [base_ref]
#
# Arguments:
#   base_ref - Git ref to compare against (default: origin/main)
#
# Output:
#   List of required test cases based on the changes
#

set -e

BASE_REF="${1:-origin/main}"

# Get list of changed files
CHANGED_FILES=$(git diff --name-only "$BASE_REF" 2>/dev/null || git diff --name-only HEAD~1)

# Core tests - always required
CORE_TESTS=(
    "TC-003:Login via Chrome DevTools"
    "TC-004:Verify Conversation List"
    "TC-005:Start New Conversation"
)

# Additional tests based on change categories
AUTH_TESTS=(
    "TC-011:Cross-User Access Denied"
    "TC-012:Unauthenticated Access Denied"
    "TC-013:Main App Access Works"
    "TC-018:Logout Functionality"
)

RUNTIME_TESTS=(
    "TC-006:Execute Flask Todo App"
    "TC-007:Verify Runtime Accessible"
    "TC-008:Verify In-App Routing"
    "TC-009:Verify Web App Subdomain"
    "TC-010:Verify VS Code URL Rewriting"
)

EC2_PERSISTENCE_TESTS=(
    "TC-014:Resume After EC2 Replacement"
    "TC-021:Secrets Persist After EC2"
)

SANDBOX_AWS_TESTS=(
    "TC-017:Sandbox AWS Access"
)

MCP_TESTS=(
    "TC-015:AWS Docs MCP Server"
    "TC-016:Chrome DevTools MCP Server"
)

USER_CONFIG_TESTS=(
    "TC-019:Secrets Page User Isolation"
    "TC-020:Settings Pages User Isolation"
)

# Detect change categories
HAS_AUTH_CHANGES=false
HAS_RUNTIME_CHANGES=false
HAS_EC2_CHANGES=false
HAS_SANDBOX_AWS_CHANGES=false
HAS_MCP_CHANGES=false
HAS_USER_CONFIG_CHANGES=false

for file in $CHANGED_FILES; do
    # Auth/Lambda@Edge changes
    if [[ "$file" =~ lib/lambda-edge/ ]] || [[ "$file" =~ edge-stack\.ts ]] || [[ "$file" =~ auth-stack\.ts ]]; then
        HAS_AUTH_CHANGES=true
    fi

    # Docker/Runtime changes
    if [[ "$file" =~ ^docker/ ]] || [[ "$file" =~ compute-stack\.ts ]]; then
        HAS_RUNTIME_CHANGES=true
    fi

    # EC2/Persistence changes
    if [[ "$file" =~ compute-stack\.ts ]] || [[ "$file" =~ ^docker/.*Dockerfile ]] || [[ "$file" =~ apply-patch\.sh ]]; then
        HAS_EC2_CHANGES=true
    fi

    # Sandbox AWS changes
    if [[ "$file" =~ security-stack\.ts ]] || [[ "$file" =~ sandbox.*credentials ]] || [[ "$file" =~ sandbox-aws-policy\.json ]]; then
        HAS_SANDBOX_AWS_CHANGES=true
    fi

    # MCP config changes
    if [[ "$file" =~ config/config\.toml ]] || [[ "$file" =~ runtime-custom ]]; then
        HAS_MCP_CHANGES=true
    fi

    # User config changes
    if [[ "$file" =~ user-config-stack\.ts ]] || [[ "$file" =~ lambda/user-config/ ]] || [[ "$file" =~ s3_.*_store\.py ]]; then
        HAS_USER_CONFIG_CHANGES=true
    fi
done

# Output results
echo "=========================================="
echo "E2E Test Selector"
echo "=========================================="
echo ""
echo "Base ref: $BASE_REF"
echo "Changed files: $(echo "$CHANGED_FILES" | wc -l | tr -d ' ')"
echo ""
echo "=========================================="
echo "Required E2E Tests for this PR"
echo "=========================================="
echo ""
echo "## Core tests (always required):"
for test in "${CORE_TESTS[@]}"; do
    tc="${test%%:*}"
    name="${test#*:}"
    echo "  - $tc: $name"
done

ADDITIONAL_TESTS=()

if $HAS_AUTH_CHANGES; then
    echo ""
    echo "## Auth/Lambda@Edge changes detected:"
    for test in "${AUTH_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

if $HAS_RUNTIME_CHANGES; then
    echo ""
    echo "## Docker/Runtime changes detected:"
    for test in "${RUNTIME_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

if $HAS_EC2_CHANGES; then
    echo ""
    echo "## EC2/Persistence changes detected:"
    for test in "${EC2_PERSISTENCE_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

if $HAS_SANDBOX_AWS_CHANGES; then
    echo ""
    echo "## Sandbox AWS changes detected:"
    for test in "${SANDBOX_AWS_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

if $HAS_MCP_CHANGES; then
    echo ""
    echo "## MCP config changes detected:"
    for test in "${MCP_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

if $HAS_USER_CONFIG_CHANGES; then
    echo ""
    echo "## User config changes detected:"
    for test in "${USER_CONFIG_TESTS[@]}"; do
        tc="${test%%:*}"
        name="${test#*:}"
        echo "  - $tc: $name"
        ADDITIONAL_TESTS+=("$test")
    done
fi

# Summary
echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
TOTAL_TESTS=$((${#CORE_TESTS[@]} + ${#ADDITIONAL_TESTS[@]}))
echo "Total tests to run: $TOTAL_TESTS"
echo ""

# Generate PR checklist format
echo "## PR Checklist Format (copy to PR description):"
echo ""
echo '```markdown'
echo "- [ ] **E2E tests pass** (see test/E2E_TEST_CASES.md)"
for test in "${CORE_TESTS[@]}"; do
    tc="${test%%:*}"
    name="${test#*:}"
    echo "  - [ ] $tc: $name"
done
for test in "${ADDITIONAL_TESTS[@]}"; do
    tc="${test%%:*}"
    name="${test#*:}"
    echo "  - [ ] $tc: $name"
done
echo '```'
