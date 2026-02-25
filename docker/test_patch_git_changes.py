"""
Unit tests for Patch 33: Fix git changes API 500 on broken git repos.

Tests verify that patch-git-changes.py correctly modifies git_changes.py
to handle RuntimeError from git diff commands gracefully.

Run with: pytest docker/test_patch_git_changes.py -v
"""

import os
import tempfile
import subprocess
import sys

import pytest


# The exact content pattern from upstream git_changes.py that the patch targets
UPSTREAM_GIT_CHANGES_SNIPPET = '''\
def get_changes_in_repo(repo_dir: str) -> list[dict[str, str]]:
    # Gets the status relative to the origin default branch - not the same as `git status`

    ref = get_valid_ref(repo_dir)
    if not ref:
        return []

    # Get changed files
    changed_files = run(
        f'git --no-pager diff --name-status {ref}', repo_dir
    ).splitlines()
    changes = []
'''

# What the patch should produce
PATCHED_GIT_CHANGES_SNIPPET = '''\
    # Get changed files — wrapped in try/except because after sandbox
    # stop/resume, git object database may be corrupted (Patch 33)
    try:
        changed_files = run(
            f'git --no-pager diff --name-status {ref}', repo_dir
        ).splitlines()
    except RuntimeError:
        return []
'''


@pytest.fixture
def patch_script_path():
    """Return path to the patch script."""
    return os.path.join(os.path.dirname(__file__), 'patch-git-changes.py')


@pytest.fixture
def fake_git_changes(tmp_path):
    """Create a fake git_changes.py with the upstream content."""
    target = tmp_path / "git_changes.py"
    target.write_text(UPSTREAM_GIT_CHANGES_SNIPPET)
    return str(target)


def run_patch(patch_script_path, target_file):
    """Run the patch script with the target file path overridden."""
    # Read patch script and replace the target file path
    with open(patch_script_path, 'r') as f:
        script = f.read()

    script = script.replace(
        '/app/openhands/runtime/utils/git_changes.py',
        target_file,
    )

    result = subprocess.run(
        [sys.executable, '-c', script],
        capture_output=True,
        text=True,
    )
    return result


class TestPatchGitChanges:
    """Tests for patch-git-changes.py."""

    def test_patch_applies_successfully(self, patch_script_path, fake_git_changes):
        """Patch should wrap git diff in try/except."""
        result = run_patch(patch_script_path, fake_git_changes)

        assert result.returncode == 0
        assert "Added error handling for git diff" in result.stdout

        with open(fake_git_changes, 'r') as f:
            content = f.read()

        assert "except RuntimeError:" in content
        assert "return []" in content
        assert "git object database may be corrupted (Patch 33)" in content

    def test_patch_is_idempotent(self, patch_script_path, fake_git_changes):
        """Running patch twice should not fail or double-apply."""
        # Apply first time
        result1 = run_patch(patch_script_path, fake_git_changes)
        assert result1.returncode == 0

        with open(fake_git_changes, 'r') as f:
            content_after_first = f.read()

        # Apply second time
        result2 = run_patch(patch_script_path, fake_git_changes)
        assert result2.returncode == 0
        assert "Already applied" in result2.stdout

        with open(fake_git_changes, 'r') as f:
            content_after_second = f.read()

        assert content_after_first == content_after_second

    def test_patch_skips_missing_file(self, patch_script_path):
        """Patch should skip gracefully if git_changes.py doesn't exist."""
        result = run_patch(patch_script_path, '/nonexistent/path/git_changes.py')

        assert result.returncode == 0
        assert "not found, skipping" in result.stdout

    def test_patch_warns_on_unexpected_content(self, patch_script_path, tmp_path):
        """Patch should warn if file content doesn't match expected pattern."""
        target = tmp_path / "git_changes.py"
        target.write_text("# completely different content\nprint('hello')\n")

        result = run_patch(patch_script_path, str(target))

        assert result.returncode == 0
        assert "Could not find expected pattern" in result.stdout

    def test_patched_content_has_correct_structure(self, patch_script_path, fake_git_changes):
        """Verify the patched code has proper try/except structure."""
        run_patch(patch_script_path, fake_git_changes)

        with open(fake_git_changes, 'r') as f:
            content = f.read()

        # The try block should wrap the run() call
        assert "    try:\n        changed_files = run(" in content
        # The except should return empty list
        assert "    except RuntimeError:\n        return []" in content
