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
- `docker/*.js` or `docker/*.sh` (patches, scripts)
- `docker/openresty/*` (OpenResty proxy config)
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
1. Read `CLAUDE.local.md` to get the deployment URL (`FULL_DOMAIN`) and test credentials
2. Follow the test cases in `test/E2E_TEST_CASES.md`
3. Run E2E tests via Chrome DevTools MCP
4. **Take screenshots for EACH verification step** (for audit purposes)
5. Report results only after ALL tests pass

---

## 📋 Required Test Cases (from test/E2E_TEST_CASES.md)

Execute these test cases in order. **Screenshot each step.**

| TC# | Test Case | Screenshot Required |
|-----|-----------|---------------------|
| TC-003 | Login via Chrome DevTools | ✅ Login page, ✅ After login |
| TC-004 | Verify Conversation List Loads | ✅ Home page with conversations |
| TC-005 | Start New Conversation | ✅ "Waiting for task" status |
| TC-006 | Execute Flask App Prompt | ✅ Agent running, ✅ Runtime URL displayed |
| TC-007 | Verify Runtime App Accessible | ✅ Flask app page content |

---

## 📸 Screenshot Requirements (for Audit)

For each test step, save screenshots using:

```javascript
mcp__chrome-devtools__take_screenshot({
  filePath: "/tmp/e2e-tc<number>-<step>.png"
})
```

**Naming Convention:**
- `/tmp/e2e-tc003-login-page.png` - Cognito login page
- `/tmp/e2e-tc003-after-login.png` - After successful login
- `/tmp/e2e-tc005-waiting-for-task.png` - Agent ready state
- `/tmp/e2e-tc006-flask-running.png` - Flask app URL in chat
- `/tmp/e2e-tc007-flask-app.png` - Flask app rendered

**After all tests pass, display screenshots using Read tool.**

---

## ✅ E2E Test Report Template

After completing all tests, provide this report:

```markdown
## E2E Test Results

**Environment:** <FULL_DOMAIN from CLAUDE.local.md>
**Date:** <timestamp>
**Conversation ID:** <conv-id>

| TC# | Test Case | Result | Screenshot |
|-----|-----------|--------|------------|
| TC-003 | Login | ✅/❌ | /tmp/e2e-tc003-*.png |
| TC-004 | Conversation List | ✅/❌ | /tmp/e2e-tc004-*.png |
| TC-005 | New Conversation | ✅/❌ | /tmp/e2e-tc005-*.png |
| TC-006 | Flask App Prompt | ✅/❌ | /tmp/e2e-tc006-*.png |
| TC-007 | Runtime Accessible | ✅/❌ | /tmp/e2e-tc007-*.png |

**Overall:** ✅ PASS / ❌ FAIL

### Screenshots
<Display each screenshot using Read tool>
```

---

## 🚀 Start NOW

```javascript
// 1. Get deployment URL from CLAUDE.local.md (FULL_DOMAIN variable)
// 2. Navigate to the application:
mcp__chrome-devtools__navigate_page({ url: "https://<FULL_DOMAIN>", type: "url" })
// 3. Follow test/E2E_TEST_CASES.md steps
// 4. Screenshot each verification step
```

**All tests must pass with screenshots before completing the task.**
