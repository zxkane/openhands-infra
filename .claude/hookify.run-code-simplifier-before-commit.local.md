---
name: run-code-simplifier-before-commit
enabled: true
event: bash
pattern: git\s+commit
action: warn
---

## Code Simplifier Reminder

Before committing, consider running the code-simplifier agent to clean up your changes:

### Run Code Simplifier
Use the Task tool to launch the code-simplifier agent:
```
Task tool with subagent_type: code-simplifier:code-simplifier
```

The agent will:
1. Review recently modified files (staged or unstaged)
2. Remove redundant code and improve consistency
3. Ensure changes follow existing patterns
4. Standardize formatting (remove emojis, fix headers, etc.)

### When to Use
- After completing a feature implementation
- After a large bug fix
- Before creating a pull request
- When you have multiple files with similar changes

### Skip If
- This is a minor documentation-only change
- You just ran the simplifier and are committing the results
- The changes are auto-generated or configuration files only

**Clean code is maintainable code.**
