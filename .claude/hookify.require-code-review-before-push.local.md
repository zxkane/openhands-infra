---
name: require-code-review-before-push
enabled: true
event: bash
pattern: git\s+push
action: warn
---

## Code Review Required Before Push

Before pushing code, ensure you have completed a thorough code review:

### Required Step
Run the comprehensive PR review command:
```
/pr-review-toolkit:review-pr
```

This command will:
1. **Code Review** - Check for style violations, potential issues, and adherence to project patterns
2. **Silent Failure Analysis** - Identify inadequate error handling and inappropriate fallback behavior
3. **Type Design Analysis** - Review type invariants and encapsulation
4. **Test Coverage Analysis** - Identify gaps in test coverage

### Review Checklist
- [ ] Ran `/pr-review-toolkit:review-pr` command
- [ ] Resolved all Critical/High severity findings
- [ ] Addressed Medium severity findings (or documented why deferred)
- [ ] Verified no new security vulnerabilities introduced

### If this is a follow-up push after review
If you have already completed the code review and are pushing fixes, you may proceed.

**Quality gates protect the codebase - do not skip reviews.**
