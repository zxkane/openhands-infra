---
name: run-code-simplifier-before-commit
enabled: false
event: bash
pattern: git\s+commit
action: warn
---

## Code Simplifier Reminder

**Note:** This rule is disabled. Blocking is handled by native hooks in `.claude/settings.local.json`.

Before committing, consider running the code-simplifier agent to clean up your changes.
