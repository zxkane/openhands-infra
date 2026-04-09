# CLAUDE.md

@AGENTS.md

## Development Workflow (MANDATORY)

**CRITICAL**: All feature development, bug fixes, and dependency updates MUST strictly follow the `autonomous-dev` skill.

### Mandatory Rules (Hook Enforced)

1. **All code changes must be developed in a Git Worktree** — commits outside worktrees are automatically blocked by `block-commit-outside-worktree.sh`
2. **All changes must go through Pull Requests** — direct pushes to `main` are automatically blocked by `block-push-to-main.sh`
3. **Code review before commit** — code-simplifier must run before committing
4. **PR review before push** — pr-review agent must run before pushing

### Rule 1: ALWAYS Invoke the Skill First

Before ANY code changes — features, fixes, refactors, dependency bumps — you MUST:
1. **Invoke skill**: Use `/autonomous-dev` or read `.claude/skills/autonomous-dev/SKILL.md`
2. **Follow ALL steps** in order — NO shortcuts, NO skipping steps
3. **Do NOT merge** - Report status and wait for user decision

**Common violation**: Skipping skill invocation and jumping straight to coding. This causes missed steps (reviewer bot iteration, PR templates, E2E test selection). The skill is not optional guidance — it is the required process.

### Rule 2: ALWAYS Use Git Worktrees for Code Changes (Hook Enforced)

**Every** branch that changes code MUST use a worktree for isolation.
This is enforced by `block-commit-outside-worktree.sh` — commits outside worktrees are automatically blocked.
Direct pushes to main are also blocked by `block-push-to-main.sh`.
```bash
git fetch origin main
git worktree add .worktrees/<name> -b <type>/<name> origin/main
cd .worktrees/<name>
npm install   # worktrees don't share node_modules
# ... do all work here ...
```

After merge, clean up:
```bash
git worktree remove .worktrees/<name>
git branch -d <type>/<name>
```

**Common violation**: Using `git checkout -b` on the main working tree. This pollutes the workspace and risks uncommitted changes interfering with the feature branch.

**Only exception**: Trivial docs-only changes (README typos) with zero code impact.

### Rule 3: Complete ALL Workflow Steps

The 10-step workflow is not a suggestion — every step must be completed:
- Step 1: Create **worktree** + branch (not `git checkout -b`)
- Step 2: Implement + write/update tests
- Step 3: Build + test locally
- Step 4: Commit + create PR with checklist template
- Steps 5-7: CI checks + address ALL reviewer bot findings + iterate until clean
- Steps 8-9: Deploy to staging + run E2E tests (use `test/select-e2e-tests.sh`)
- Step 10: Report ready status (DO NOT MERGE unless user explicitly says to)

## Quick Reference

- **Development workflow**: Use `.claude/skills/autonomous-dev/` for PR creation, review comments, reviewer bots
- **Code review**: Use `.claude/skills/autonomous-review/` for PR review, acceptance verification, merge decisions
- **Issue creation**: Use `.claude/skills/create-issue/` for creating structured GitHub issues
