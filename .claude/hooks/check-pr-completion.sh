#!/bin/bash
# PR Completion Check Script
# Verifies that a PR is ready for merge:
# 1. All CI checks have completed and passed
# 2. All review comments from reviewer bots are resolved
#
# Usage: ./check-pr-completion.sh <pr-number>
#
# Exit codes:
#   0 - All checks passed, PR is ready
#   1 - Checks failed or incomplete
#   2 - Review comments not resolved

set -e

# Check for required dependencies
for cmd in gh jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed" >&2
        exit 1
    fi
done

PR_NUMBER="${1:-}"

if [ -z "$PR_NUMBER" ]; then
    # Try to get PR number from current branch
    CURRENT_BRANCH=$(git branch --show-current 2>/dev/null)
    if [ -n "$CURRENT_BRANCH" ] && [ "$CURRENT_BRANCH" != "main" ]; then
        PR_NUMBER=$(gh pr view "$CURRENT_BRANCH" --json number -q '.number' 2>/dev/null || echo "")
    fi
fi

if [ -z "$PR_NUMBER" ]; then
    echo "Usage: $0 <pr-number>"
    echo "Or run from a branch with an open PR"
    exit 1
fi

echo "Checking PR #$PR_NUMBER completion status..."
echo ""

# Get repository info
REPO=$(gh repo view --json nameWithOwner -q '.nameWithOwner')

#########################################
# 1. Check CI Status
#########################################
echo "=== CI Checks Status ==="

# Get all check runs for the PR using statusCheckRollup
CHECKS=$(gh pr view "$PR_NUMBER" --json statusCheckRollup -q '.statusCheckRollup' 2>/dev/null || echo "[]")

if [ "$CHECKS" = "[]" ] || [ -z "$CHECKS" ] || [ "$CHECKS" = "null" ]; then
    echo "⏳ No CI checks found yet. Waiting for checks to start..."
    CI_READY=false
else
    # Count check statuses
    TOTAL=$(echo "$CHECKS" | jq 'length')
    PENDING=$(echo "$CHECKS" | jq '[.[] | select(.status == "PENDING" or .status == "QUEUED" or .status == "IN_PROGRESS")] | length')
    PASSED=$(echo "$CHECKS" | jq '[.[] | select(.conclusion == "SUCCESS" or .conclusion == "SKIPPED")] | length')
    FAILED=$(echo "$CHECKS" | jq '[.[] | select(.conclusion == "FAILURE" or .conclusion == "CANCELLED" or .conclusion == "TIMED_OUT")] | length')

    echo "Total checks: $TOTAL"
    echo "  ✅ Passed/Skipped: $PASSED"
    echo "  ⏳ Pending: $PENDING"
    echo "  ❌ Failed: $FAILED"
    echo ""

    # List failed checks
    if [ "$FAILED" -gt 0 ]; then
        echo "Failed checks:"
        echo "$CHECKS" | jq -r '.[] | select(.conclusion == "FAILURE" or .conclusion == "CANCELLED" or .conclusion == "TIMED_OUT") | "  - \(.name): \(.conclusion)"'
        echo ""
    fi

    # List pending checks
    if [ "$PENDING" -gt 0 ]; then
        echo "Pending checks:"
        echo "$CHECKS" | jq -r '.[] | select(.status == "PENDING" or .status == "QUEUED" or .status == "IN_PROGRESS") | "  - \(.name): \(.status)"'
        echo ""
    fi

    if [ "$PENDING" -gt 0 ]; then
        echo "⏳ CI checks still running..."
        CI_READY=false
    elif [ "$FAILED" -gt 0 ]; then
        echo "❌ CI checks failed!"
        CI_READY=false
    else
        echo "✅ All CI checks passed!"
        CI_READY=true
    fi
fi

echo ""

#########################################
# 2. Check Review Comments
#########################################
echo "=== Review Comments Status ==="

# Get review threads using GraphQL
REVIEW_THREADS=$(gh api graphql -f query='
query($owner: String!, $repo: String!, $pr: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      reviewThreads(first: 100) {
        nodes {
          id
          isResolved
          isOutdated
          comments(first: 1) {
            nodes {
              author {
                login
              }
              body
            }
          }
        }
      }
    }
  }
}' -f owner="${REPO%%/*}" -f repo="${REPO##*/}" -F pr="$PR_NUMBER" 2>/dev/null || echo "{}")

# Parse thread data
THREADS=$(echo "$REVIEW_THREADS" | jq '.data.repository.pullRequest.reviewThreads.nodes // []')
TOTAL_THREADS=$(echo "$THREADS" | jq 'length')
UNRESOLVED_THREADS=$(echo "$THREADS" | jq '[.[] | select(.isResolved == false and .isOutdated == false)] | length')
RESOLVED_THREADS=$(echo "$THREADS" | jq '[.[] | select(.isResolved == true)] | length')
OUTDATED_THREADS=$(echo "$THREADS" | jq '[.[] | select(.isOutdated == true)] | length')

echo "Total review threads: $TOTAL_THREADS"
echo "  ✅ Resolved: $RESOLVED_THREADS"
echo "  ⏳ Unresolved: $UNRESOLVED_THREADS"
echo "  📝 Outdated: $OUTDATED_THREADS"
echo ""

# List unresolved threads with details
if [ "$UNRESOLVED_THREADS" -gt 0 ]; then
    echo "Unresolved review threads:"
    echo "$THREADS" | jq -r '
        .[] |
        select(.isResolved == false and .isOutdated == false) |
        "  - Thread ID: \(.id)\n    Author: \(.comments.nodes[0].author.login // "unknown")\n    Comment: \(.comments.nodes[0].body[:100] // "")..."
    '
    echo ""
    REVIEWS_READY=false
else
    echo "✅ All review threads resolved!"
    REVIEWS_READY=true
fi

echo ""

#########################################
# 3. Summary and Exit
#########################################
echo "=== Summary ==="

EXIT_CODE=0

if [ "$CI_READY" = true ]; then
    echo "✅ CI Checks: PASSED"
else
    echo "❌ CI Checks: NOT READY"
    EXIT_CODE=1
fi

if [ "$REVIEWS_READY" = true ]; then
    echo "✅ Review Comments: RESOLVED"
else
    echo "❌ Review Comments: UNRESOLVED"
    if [ $EXIT_CODE -eq 0 ]; then
        EXIT_CODE=2
    fi
fi

echo ""

if [ $EXIT_CODE -eq 0 ]; then
    echo "🎉 PR #$PR_NUMBER is ready for merge!"
else
    echo "⚠️  PR #$PR_NUMBER is NOT ready for merge."
    echo ""
    echo "To resolve review threads, use:"
    echo "  gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: \"<thread_id>\"}) { thread { isResolved } } }'"
fi

exit $EXIT_CODE
