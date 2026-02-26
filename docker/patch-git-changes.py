"""Patch 33: Fix git changes API returning 500 on broken git repos.

After sandbox stop/resume, the git object database inside the sandbox may be
corrupted or incomplete. The empty tree hash (4b825dc642cb6eb9a060e54bf8d69288fbee4904)
resolves via `rev-parse --verify` but the subsequent `git diff --name-status` fails,
causing an unhandled RuntimeError that surfaces as HTTP 500.

Fix: Wrap the git diff command in get_changes_in_repo() with a try/except so that
a failed diff returns an empty list instead of crashing the API.
"""
import sys

GIT_CHANGES_FILE = "/app/openhands/runtime/utils/git_changes.py"

try:
    with open(GIT_CHANGES_FILE, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("Patch 33: git_changes.py not found, skipping")
    sys.exit(0)

# The vulnerable pattern: run() can raise RuntimeError when git diff fails
# on a corrupted/incomplete git object database
OLD_PATTERN = """\
    # Get changed files
    changed_files = run(
        f'git --no-pager diff --name-status {ref}', repo_dir
    ).splitlines()"""

NEW_PATTERN = """\
    # Get changed files — wrapped in try/except because after sandbox
    # stop/resume, git object database may be corrupted (Patch 33)
    try:
        changed_files = run(
            f'git --no-pager diff --name-status {ref}', repo_dir
        ).splitlines()
    except RuntimeError as e:
        import logging
        logging.warning(f'Git diff failed in get_changes_in_repo(): {e}')
        return []"""

if OLD_PATTERN in content:
    content = content.replace(OLD_PATTERN, NEW_PATTERN)
    with open(GIT_CHANGES_FILE, "w") as f:
        f.write(content)
    print("Patch 33: Added error handling for git diff in get_changes_in_repo()")
elif "# stop/resume, git object database may be corrupted (Patch 33)" in content:
    print("Patch 33: Already applied (clean)")
else:
    print("WARNING: Patch 33: Could not find expected pattern in git_changes.py")
    # Print context for debugging
    if "git --no-pager diff --name-status" in content:
        print("  (git diff command found but surrounding code differs)")
    else:
        print("  (git diff command NOT found - file may have changed significantly)")
