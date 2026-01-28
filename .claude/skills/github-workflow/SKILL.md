---
name: github-workflow
description: This skill should be used when the user asks to "create a PR", "address review comments", "resolve review threads", "retrigger Q review", "/q review", "respond to Amazon Q", "handle reviewer findings", "merge PR", "push changes", "check CI status", or mentions PR workflow, code review, or GitHub Actions checks.
---

# GitHub Development Workflow

This skill provides standardized guidance for the complete GitHub development workflow, including branch management, PR creation, CI monitoring, and reviewer bot interaction.

## Development Workflow Overview

Follow this 7-step workflow for all feature development and bug fixes:

```
Step 1: CREATE BRANCH
  git checkout -b feat/<name> or fix/<name>
       ↓
Step 2: IMPLEMENT CHANGES
  - Write code
  - Update unit tests (npm run test)
  - Update E2E test cases if needed
       ↓
Step 3: LOCAL VERIFICATION
  - npm run build
  - npm run test
  - Deploy and verify (if applicable)
       ↓
Step 4: COMMIT AND CREATE PR
  - git add && git commit -m "type(scope): description"
  - git push -u origin <branch-name>
  - Create PR via GitHub MCP or gh CLI
       ↓
Step 5: WAIT FOR PR CHECKS
  - Monitor GitHub Actions checks
  - If FAIL → Return to Step 2
  - If PASS → Proceed to Step 6
       ↓
Step 6: ADDRESS REVIEWER BOT FINDINGS
  - Review Amazon Q Developer comments
  - Fix issues or document design decisions
  - Reply DIRECTLY to each comment thread
  - RESOLVE each conversation
       ↓
Step 7: READY FOR MERGE
  - All checks passed
  - All comments addressed
```

## PR Check Monitoring

### Monitor CI Status

```bash
# Watch all checks until completion
gh pr checks {pr_number} --watch --interval 30

# Quick status check
gh pr checks {pr_number}
```

### Checks to Monitor

| Check | Description | Action if Failed |
|-------|-------------|------------------|
| CI / build-and-test | Build + unit tests | Fix code or update snapshots |
| Security Scan | SAST, npm audit | Fix security issues |
| Amazon Q Developer | Security review | Address findings or document decisions |

## Amazon Q Developer Workflow

Amazon Q Developer provides automated security and code review findings on PRs.

### Handling Q Review Findings

1. **Review all comments** - Read each finding carefully
2. **Determine action**:
   - If valid issue → Fix the code and push
   - If false positive → Reply explaining the design decision
3. **Reply to each thread** - Use direct reply, not general PR comment
4. **Resolve each thread** - Mark conversation as resolved
5. **Retrigger review** - Comment `/q review` to scan again

### Retrigger Amazon Q Review

After addressing findings, trigger a new scan:

```bash
gh pr comment {pr_number} --body "/q review"
```

Wait 60-90 seconds for the review to complete, then check for new comments.

### Iteration Loop

Repeat until Q review finds no more issues:

1. Address findings (fix code or explain design)
2. Reply to each comment thread
3. Resolve all threads
4. Trigger `/q review`
5. Check for new findings
6. If new findings → repeat from step 1

## Review Thread Management

### Critical Rules

- **Reply DIRECTLY to each comment thread** - NOT a single general PR comment
- **Resolve each conversation after replying**
- **Wrong approach**: `gh pr comment {pr} --body "Fixed all issues"` (doesn't close threads)

### Reply to Review Comments

```bash
# Get comment IDs
gh api repos/{owner}/{repo}/pulls/{pr}/comments \
  --jq '.[] | {id: .id, path: .path, body: .body[:50]}'

# Reply to specific comment
gh api repos/{owner}/{repo}/pulls/{pr}/comments \
  -X POST \
  -f body="Addressed in commit abc123 - <description of fix>" \
  -F in_reply_to=<comment_id>
```

### Resolve Review Threads

```bash
# Get unresolved thread IDs
gh api graphql -f query='
query {
  repository(owner: "{owner}", name: "{repo}") {
    pullRequest(number: {pr}) {
      reviewThreads(first: 50) {
        nodes {
          id
          isResolved
          comments(first: 1) {
            nodes { body }
          }
        }
      }
    }
  }
}' --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved == false) | .id'

# Resolve a thread
gh api graphql -f query='
mutation {
  resolveReviewThread(input: {threadId: "<thread_id>"}) {
    thread { isResolved }
  }
}'
```

### Batch Resolve All Threads

Use the `scripts/resolve-threads.sh` script to resolve all unresolved threads at once:

```bash
./skills/github-workflow/scripts/resolve-threads.sh {owner} {repo} {pr_number}
```

## Common Response Patterns

### For Valid Issues

```
Addressed in commit {hash} - {description of fix}
```

Example:
```
Addressed in commit abc123 - Updated Lambda@Edge handler to use external file pattern
```

### For False Positives

```
This is by design because {explanation}. The {feature} requires {justification}.
```

Example:
```
This is documentation for authorized operators. The commands require IAM permissions that only administrators have. IAM access controls prevent unauthorized access, not documentation obscurity.
```

### For Documentation Concerns

```
The referenced file {filename} exists in the repository at {path}. This is a reference document, not executable code.
```

## Quick Reference

| Task | Command |
|------|---------|
| Create PR | `gh pr create --title "..." --body "..."` |
| Watch checks | `gh pr checks {pr} --watch` |
| Get comments | `gh api repos/{o}/{r}/pulls/{pr}/comments` |
| Reply to comment | `gh api ... -X POST -F in_reply_to=<id>` |
| Resolve thread | GraphQL `resolveReviewThread` mutation |
| Trigger Q review | `gh pr comment {pr} --body "/q review"` |
| Check thread status | GraphQL query for `reviewThreads` |

## Additional Resources

### Reference Files

For detailed commands and conventions, consult:
- **`references/review-commands.md`** - Complete gh CLI and GraphQL command reference
- **`references/commit-conventions.md`** - Branch naming and commit message conventions

### Scripts

Utility scripts in `scripts/`:
- **`reply-to-comments.sh`** - Reply to a specific review comment
- **`resolve-threads.sh`** - Batch resolve all unresolved threads
