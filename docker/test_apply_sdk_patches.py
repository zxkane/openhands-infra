"""
Unit tests for apply-sdk-patches.py.

These tests verify build-time SDK patches that apply-sdk-patches.py applies to
the OpenHands SDK source tree before PyInstaller bundles it.

Patch 33 specifically: rewrite the LLM Pydantic model's `model` field default
from upstream's `claude-sonnet-4-20250514` (Anthropic direct API) to
`bedrock/global.anthropic.claude-sonnet-4-6` (Bedrock cross-region inference
profile). Without this patch, a brand-new conversation that has no
`agent_settings.llm.model` falls back to the SDK default, litellm routes to
Anthropic direct, and the call fails because no ANTHROPIC_API_KEY is set.
The bad default also gets frozen into base_state.json on EFS, permanently
breaking that conversation.

Run with: pytest docker/test_apply_sdk_patches.py -v
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PATCH_SCRIPT = (
    REPO_ROOT / "docker" / "agent-server-custom" / "apply-sdk-patches.py"
)


def _load_patch_module():
    """Load apply-sdk-patches.py as a module despite the hyphenated filename."""
    spec = importlib.util.spec_from_file_location(
        "apply_sdk_patches", PATCH_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_sdk_patches"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fake_sdk_tree(tmp_path: Path) -> Path:
    """
    Build a minimal fake SDK source tree with just the file Patch 33 targets.

    Mirrors the upstream v1.19.1 layout enough for the patch to find its
    insertion point.
    """
    llm_file = tmp_path / "openhands-sdk" / "openhands" / "sdk" / "llm" / "llm.py"
    llm_file.parent.mkdir(parents=True)

    # A trimmed-down replica of the relevant chunk of upstream
    # openhands-sdk/openhands/sdk/llm/llm.py (v1.19.1, around line 167).
    llm_file.write_text(
        '''"""Stub of upstream LLM model for patch tests."""

from pydantic import BaseModel, Field


class LLM(BaseModel):
    """Trimmed copy of LLM for patch tests."""

    # =========================================================================
    # Config fields
    # =========================================================================

    model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Model name.",
    )
    api_key: str | None = Field(
        default=None,
        description="API key.",
    )
'''
    )
    return tmp_path


class TestPatch33DefaultBedrockSonnet:
    """Patch 33 must rewrite the default value, not just monkey-patch it."""

    def test_patch_changes_default_to_bedrock_sonnet_4_6(
        self, fake_sdk_tree: Path
    ) -> None:
        module = _load_patch_module()

        result = module.patch_33_default_bedrock_model(fake_sdk_tree)

        assert result is True, "patch_33 must report success on a valid tree"

        patched = (
            fake_sdk_tree
            / "openhands-sdk"
            / "openhands"
            / "sdk"
            / "llm"
            / "llm.py"
        ).read_text()

        assert (
            'default="bedrock/global.anthropic.claude-sonnet-4-6"' in patched
        ), "default must be the Bedrock global cross-region inference profile"
        assert (
            "claude-sonnet-4-20250514" not in patched
        ), "old Anthropic-direct default must be removed"

    def test_patch_is_idempotent(self, fake_sdk_tree: Path) -> None:
        """Re-running the patch on already-patched content must succeed (no-op)."""
        module = _load_patch_module()

        assert module.patch_33_default_bedrock_model(fake_sdk_tree) is True
        # Second run hits the "already applied" short-circuit.
        assert module.patch_33_default_bedrock_model(fake_sdk_tree) is True

    def test_patch_fails_when_target_file_missing(self, tmp_path: Path) -> None:
        module = _load_patch_module()

        result = module.patch_33_default_bedrock_model(tmp_path)

        assert result is False, "patch_33 must fail loudly if llm.py is absent"

    def test_main_runs_patch_33(self, fake_sdk_tree: Path, monkeypatch) -> None:
        """main() must include Patch 33 in its results so a failure aborts the build."""
        module = _load_patch_module()

        called: list[str] = []
        original = module.patch_33_default_bedrock_model

        def spy(build_dir: Path) -> bool:
            called.append("patch_33")
            return original(build_dir)

        monkeypatch.setattr(module, "patch_33_default_bedrock_model", spy)
        # Stub all other patches to no-ops so we don't need a full SDK tree.
        for name in (
            "patch_23_agent_context",
            "patch_25_json_preprocessing",
            "patch_26_conversation_state",
            "patch_28_29_32_bedrock_listing",
            "patch_30_model_info_region_prefix",
            "patch_31_aws_default_region",
        ):
            monkeypatch.setattr(module, name, lambda _bd, _n=name: True)

        monkeypatch.setattr(sys, "argv", ["apply-sdk-patches.py", str(fake_sdk_tree)])

        module.main()

        assert "patch_33" in called, "main() must invoke patch_33"
