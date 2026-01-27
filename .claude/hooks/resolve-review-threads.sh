#!/bin/bash
# Resolve Review Threads Script
# Resolves all unresolved review threads on a PR
#
# Usage: ./resolve-review-threads.sh <pr-number> [--dry-run]
#
# Options:
#   --dry-run   Show what would be resolved without actually resolving

set -e

# Check for required dependencies
for cmd in gh jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed" >&2
        exit 1
    fi
done

PR_NUMBER="${1:-}"
DRY_RUN=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
    esac
done

if [ -z "$PR_NUMBER" ]; then
    # Try to get PR number from current branch
    CURRENT_BRANCH=$(git branch --show-current 2>/dev/null)
    if [ -n "$CURRENT_BRANCH" ] && [ "$CURRENT_BRANCH" != "main" ]; then
        PR_NUMBER=$(gh pr view "$CURRENT_BRANCH" --json number -q '.number' 2>/dev/null || echo "")
    fi
fi

if [ -z "$PR_NUMBER" ]; then
    echo "Usage: $0 <pr-number> [--dry-run]"
    echo "Or run from a branch with an open PR"
    exit 1
fi

echo "Checking review threads for PR #$PR_NUMBER..."
echo ""

# Get repository info
REPO=$(gh repo view --json nameWithOwner -q '.nameWithOwner')

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

# Parse unresolved threads
UNRESOLVED=$(echo "$REVIEW_THREADS" | jq -r '
    .data.repository.pullRequest.reviewThreads.nodes[] |
    select(.isResolved == false and .isOutdated == false) |
    .id
')

if [ -z "$UNRESOLVED" ]; then
    echo "✅ No unresolved review threads found!"
    exit 0
fi

# Count unresolved
UNRESOLVED_COUNT=$(echo "$UNRESOLVED" | wc -l)
echo "Found $UNRESOLVED_COUNT unresolved review thread(s)"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would resolve the following threads:"
    echo "$UNRESOLVED" | while read -r thread_id; do
        echo "  - $thread_id"
    done
    exit 0
fi

# Resolve each thread
RESOLVED_COUNT=0
FAILED_COUNT=0

echo "Resolving threads..."
echo ""

echo "$UNRESOLVED" | while read -r thread_id; do
    if [ -n "$thread_id" ]; then
        echo -n "  Resolving $thread_id... "

        RESULT=$(gh api graphql -f query='
            mutation($threadId: ID!) {
                resolveReviewThread(input: {threadId: $threadId}) {
                    thread {
                        isResolved
                    }
                }
            }
        ' -f threadId="$thread_id" 2>&1)

        if echo "$RESULT" | jq -e '.data.resolveReviewThread.thread.isResolved' > /dev/null 2>&1; then
            echo "✅"
            RESOLVED_COUNT=$((RESOLVED_COUNT + 1))
        else
            echo "❌ Failed"
            echo "    Error: $RESULT"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    fi
done

echo ""
echo "Summary:"
echo "  Resolved: $RESOLVED_COUNT"
echo "  Failed: $FAILED_COUNT"

if [ "$FAILED_COUNT" -gt 0 ]; then
    exit 1
fi

echo ""
echo "✅ All review threads resolved!"
