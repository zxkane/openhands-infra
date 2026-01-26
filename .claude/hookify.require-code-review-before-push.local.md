---
name: require-code-review-before-push
enabled: false
event: bash
pattern: git\s+push
action: warn
---

## Code Review Reminder

**Note:** This rule is disabled. Blocking is handled by native hooks in `.claude/settings.local.json`.

Before pushing, run `/pr-review-toolkit:review-pr` to ensure code quality.
