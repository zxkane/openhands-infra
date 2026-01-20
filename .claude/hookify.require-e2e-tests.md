---
name: require-e2e-tests
enabled: true
event: stop
action: block
pattern: .*
---

## ⛔ STOP - E2E Tests Required Before Completion

**You cannot complete this task yet.**

### Did you modify infrastructure code?

If you modified any of these files, E2E testing is **MANDATORY**:
- `lib/*.ts` (CDK stacks)
- `docker/*.js` or `docker/*.py` (patches, auth)
- `config/config.toml` (OpenHands config)

### Skip Conditions

You may skip E2E testing **ONLY** if your changes are:
- Pure documentation (README.md, CLAUDE.md, comments)
- Local configuration (CLAUDE.local.md, .env)
- Test files only (test/*.ts)

---

## ⚡ ACTION REQUIRED - DO NOT WAIT FOR USER

**Immediately proceed with E2E verification. Do NOT:**
- ❌ Wait for user confirmation
- ❌ Ask "should I run E2E tests?"
- ❌ Summarize and stop

**Instead, immediately:**
1. Follow **"Post-Infrastructure Change Workflow"** in CLAUDE.md
2. Run E2E tests via Chrome DevTools MCP
3. Report results only after ALL tests pass

**Start NOW:**
```javascript
mcp__chrome-devtools__navigate_page({ url: "https://openhands.test.kane.mx", type: "url" })
```

---

### Minimum E2E Verification Checklist

| # | Test | Status |
|---|------|--------|
| 1 | Login portal without error | ☐ |
| 2 | Conversations list loads | ☐ |
| 3 | New conversation reaches "Waiting for task" | ☐ |
| 4 | Agent responds to simple prompt | ☐ |

**All boxes must be ✅ before completing the task.**
