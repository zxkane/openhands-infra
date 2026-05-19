"""
Unit tests for apply-sdk-patches.py.

These tests verify build-time SDK patches that apply-sdk-patches.py applies to
the OpenHands SDK source tree before PyInstaller bundles it.

Patch 33: rewrite the LLM Pydantic model's `model` field default from
upstream's `claude-sonnet-4-20250514` (Anthropic direct API) to
`bedrock/global.anthropic.claude-sonnet-4-6` (Bedrock cross-region inference
profile). Without this patch, a brand-new conversation that has no
`agent_settings.llm.model` falls back to the SDK default, litellm routes to
Anthropic direct, and the call fails because no ANTHROPIC_API_KEY is set.
The bad default also gets frozen into base_state.json on EFS, permanently
breaking that conversation.

Patch 34: rewrite chat-options kwargs for Claude Opus 4.7 family so the
Bedrock request uses adaptive thinking. Bedrock returns HTTP 400 for the
legacy `thinking.type="enabled"` shape on Opus 4.7; only `"adaptive"` is
accepted. Upstream litellm still translates `reasoning_effort` to
`thinking={"type":"enabled",...}` for any `claude-opus-4*` model.

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
            "patch_34_opus_47_adaptive_thinking",
        ):
            monkeypatch.setattr(module, name, lambda _bd, _n=name: True)

        monkeypatch.setattr(sys, "argv", ["apply-sdk-patches.py", str(fake_sdk_tree)])

        module.main()

        assert "patch_33" in called, "main() must invoke patch_33"


# ---------------------------------------------------------------------------
# Patch 34: Opus 4.7 adaptive-thinking rewrite in chat_options.py
# ---------------------------------------------------------------------------


# Trimmed copy of upstream openhands-sdk/openhands/sdk/llm/options/chat_options.py
# (SDK v1.19.1). The patch's anchor is the `return out` line; everything above
# stays as-is.
_CHAT_OPTIONS_STUB = '''from __future__ import annotations

from typing import Any

from openhands.sdk.llm.options.common import apply_defaults_if_absent
from openhands.sdk.llm.utils.model_features import get_features


def select_chat_options(
    llm, user_kwargs: dict[str, Any], has_tools: bool
) -> dict[str, Any]:
    """Behavior-preserving extraction of _normalize_call_kwargs."""
    defaults: dict[str, Any] = {
        "top_k": llm.top_k,
        "top_p": llm.top_p,
        "temperature": llm.temperature,
        "max_completion_tokens": llm.max_output_tokens,
    }
    out = apply_defaults_if_absent(user_kwargs, defaults)

    # If user didn't set extra_headers, propagate from llm config
    if llm.extra_headers is not None and "extra_headers" not in out:
        out["extra_headers"] = dict(llm.extra_headers)

    supports_reasoning_effort = get_features(llm.model).supports_reasoning_effort
    if supports_reasoning_effort:
        if llm.reasoning_effort is not None:
            out["reasoning_effort"] = llm.reasoning_effort
        if "gemini" not in llm.model.lower():
            out.pop("temperature", None)
            out.pop("top_p", None)

    if get_features(llm.model).supports_extended_thinking:
        if llm.extended_thinking_budget:
            budget_tokens = min(llm.extended_thinking_budget, llm.max_output_tokens - 1)
            out["thinking"] = {
                "type": "enabled",
                "budget_tokens": budget_tokens,
            }
            existing = out.get("extra_headers") or {}
            out["extra_headers"] = {
                "anthropic-beta": "interleaved-thinking-2025-05-14",
                **existing,
            }
            out["max_tokens"] = llm.max_output_tokens
        out.pop("temperature", None)
        out.pop("top_p", None)

    return out
'''


# Stub source for openhands.sdk.llm.options.common — written to disk so the
# real module loader resolves it without needing the OpenHands SDK install.
_COMMON_STUB = '''def apply_defaults_if_absent(user_kwargs, defaults):
    out = dict(user_kwargs) if user_kwargs else {}
    for k, v in defaults.items():
        if v is not None and k not in out:
            out[k] = v
    return out
'''


# Stub source for openhands.sdk.llm.utils.model_features — drives just enough
# behavior for select_chat_options to take each Anthropic branch.
_MODEL_FEATURES_STUB = '''from dataclasses import dataclass


@dataclass
class _F:
    supports_reasoning_effort: bool = False
    supports_extended_thinking: bool = False
    supports_prompt_cache: bool = False
    supports_stop_words: bool = True
    supports_responses_api: bool = False
    force_string_serializer: bool = False
    send_reasoning_content: bool = False
    supports_prompt_cache_retention: bool = False


def get_features(model):
    m = (model or "").lower()
    if "claude-opus-4-7" in m or "mythos-preview" in m:
        return _F(supports_reasoning_effort=True)
    if "claude-sonnet-4-6" in m or "claude-sonnet-4-5" in m:
        return _F(
            supports_reasoning_effort=True,
            supports_extended_thinking=True,
        )
    return _F()
'''


@pytest.fixture
def fake_chat_options_tree(tmp_path: Path) -> Path:
    """Build a minimal SDK tree with chat_options.py + dependency stubs."""
    sdk_root = tmp_path / "openhands-sdk" / "openhands" / "sdk"
    options_dir = sdk_root / "llm" / "options"
    utils_dir = sdk_root / "llm" / "utils"
    options_dir.mkdir(parents=True)
    utils_dir.mkdir(parents=True)

    # Init files so importlib treats these as packages
    for pkg_dir in (
        sdk_root.parent,
        sdk_root,
        sdk_root / "llm",
        options_dir,
        utils_dir,
    ):
        (pkg_dir / "__init__.py").write_text("")

    (options_dir / "chat_options.py").write_text(_CHAT_OPTIONS_STUB)
    (options_dir / "common.py").write_text(_COMMON_STUB)
    (utils_dir / "model_features.py").write_text(_MODEL_FEATURES_STUB)
    return tmp_path


def _load_patched_select_chat_options(build_dir: Path):
    """
    Import the patched chat_options.py from build_dir using importlib.

    Uses spec_from_file_location with explicit submodule_search_locations so
    the patched chat_options.py and its sibling stub modules resolve without
    polluting sys.modules with `openhands.*` entries that other tests rely on.
    """
    base = build_dir / "openhands-sdk" / "openhands" / "sdk" / "llm"

    # Load common.py and model_features.py under unique synthetic names so we
    # don't clobber any real openhands.sdk.* modules already in sys.modules.
    common_spec = importlib.util.spec_from_file_location(
        "_patch34_test_common", base / "options" / "common.py"
    )
    common_mod = importlib.util.module_from_spec(common_spec)
    common_spec.loader.exec_module(common_mod)

    features_spec = importlib.util.spec_from_file_location(
        "_patch34_test_model_features", base / "utils" / "model_features.py"
    )
    features_mod = importlib.util.module_from_spec(features_spec)
    features_spec.loader.exec_module(features_mod)

    # Insert under the names chat_options.py imports from, but save and restore
    # any pre-existing entries to keep this test isolated.
    sentinel = object()
    saved = {
        "openhands.sdk.llm.options.common": sys.modules.get(
            "openhands.sdk.llm.options.common", sentinel
        ),
        "openhands.sdk.llm.utils.model_features": sys.modules.get(
            "openhands.sdk.llm.utils.model_features", sentinel
        ),
    }
    sys.modules["openhands.sdk.llm.options.common"] = common_mod
    sys.modules["openhands.sdk.llm.utils.model_features"] = features_mod
    try:
        chat_spec = importlib.util.spec_from_file_location(
            "_patch34_test_chat_options", base / "options" / "chat_options.py"
        )
        chat_mod = importlib.util.module_from_spec(chat_spec)
        chat_spec.loader.exec_module(chat_mod)
        return chat_mod.select_chat_options
    finally:
        for key, prev in saved.items():
            if prev is sentinel:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = prev


class _FakeLLM:
    """Minimal stand-in for the SDK LLM model used by select_chat_options."""

    def __init__(self, model: str, **overrides) -> None:
        self.model = model
        self.top_k = None
        self.top_p = 0.95
        self.temperature = 0.0
        self.max_output_tokens = 16000
        self.reasoning_effort = "high"
        self.extended_thinking_budget = 200_000
        self.extra_headers = None
        for k, v in overrides.items():
            setattr(self, k, v)


class TestPatch34Opus47AdaptiveThinking:
    """Patch 34 must rewrite kwargs into the Bedrock-required adaptive shape."""

    def test_patch_inserts_rewrite_block(
        self, fake_chat_options_tree: Path
    ) -> None:
        module = _load_patch_module()

        result = module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree)

        assert result is True
        patched = (
            fake_chat_options_tree
            / "openhands-sdk"
            / "openhands"
            / "sdk"
            / "llm"
            / "options"
            / "chat_options.py"
        ).read_text()

        assert "OPUS_47_ADAPTIVE_THINKING_MODELS" in patched
        assert '"claude-opus-4-7"' in patched
        assert '"claude-mythos-preview"' in patched
        assert '"adaptive"' in patched

    def test_patch_is_idempotent(self, fake_chat_options_tree: Path) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

    def test_patch_fails_when_target_file_missing(self, tmp_path: Path) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(tmp_path) is False

    def test_opus_4_7_emits_adaptive_thinking_and_strips_reasoning_effort(
        self, fake_chat_options_tree: Path
    ) -> None:
        """Core fix: Opus 4.7 must NOT carry thinking.type=enabled or reasoning_effort."""
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM("bedrock/global.anthropic.claude-opus-4-7")

        out = select(llm, {}, has_tools=False)

        assert out.get("thinking") == {"type": "adaptive"}
        assert "reasoning_effort" not in out, (
            "reasoning_effort must be stripped so litellm doesn't translate "
            "it into thinking.type=enabled"
        )
        assert out.get("output_config") == {"effort": "high"}
        assert "temperature" not in out
        assert "top_p" not in out

    def test_mythos_preview_also_uses_adaptive(
        self, fake_chat_options_tree: Path
    ) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM("bedrock/anthropic.claude-mythos-preview")

        out = select(llm, {}, has_tools=False)
        assert out.get("thinking") == {"type": "adaptive"}

    def test_effort_none_omits_output_config(
        self, fake_chat_options_tree: Path
    ) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM(
            "bedrock/global.anthropic.claude-opus-4-7", reasoning_effort="none"
        )

        out = select(llm, {}, has_tools=False)
        assert out.get("thinking") == {"type": "adaptive"}
        assert "output_config" not in out

    def test_legacy_anthropic_beta_header_stripped(
        self, fake_chat_options_tree: Path
    ) -> None:
        """Adaptive thinking enables interleaved thinking implicitly."""
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM(
            "bedrock/global.anthropic.claude-opus-4-7",
            extra_headers={
                "anthropic-beta": "interleaved-thinking-2025-05-14",
                "X-Custom": "keep-me",
            },
        )

        out = select(llm, {}, has_tools=False)
        assert out.get("extra_headers") == {"X-Custom": "keep-me"}

    def test_only_legacy_beta_header_removes_dict_entirely(
        self, fake_chat_options_tree: Path
    ) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM(
            "bedrock/global.anthropic.claude-opus-4-7",
            extra_headers={"anthropic-beta": "interleaved-thinking-2025-05-14"},
        )

        out = select(llm, {}, has_tools=False)
        assert "extra_headers" not in out

    def test_case_insensitive_model_match(
        self, fake_chat_options_tree: Path
    ) -> None:
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM("Bedrock/Global.Anthropic.CLAUDE-OPUS-4-7")

        out = select(llm, {}, has_tools=False)
        assert out.get("thinking") == {"type": "adaptive"}

    def test_sonnet_4_6_still_uses_extended_thinking(
        self, fake_chat_options_tree: Path
    ) -> None:
        """Patch 34 must NOT regress sonnet-4-6, which is currently working."""
        module = _load_patch_module()
        assert module.patch_34_opus_47_adaptive_thinking(fake_chat_options_tree) is True

        select = _load_patched_select_chat_options(fake_chat_options_tree)
        llm = _FakeLLM("bedrock/global.anthropic.claude-sonnet-4-6")

        out = select(llm, {}, has_tools=False)
        assert out.get("thinking", {}).get("type") == "enabled"
        assert "output_config" not in out

    def test_main_runs_patch_34(
        self, fake_chat_options_tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() must include patch_34 so a failure aborts the build."""
        module = _load_patch_module()

        called: list[str] = []
        original = module.patch_34_opus_47_adaptive_thinking

        def spy(build_dir: Path) -> bool:
            called.append("patch_34")
            return original(build_dir)

        monkeypatch.setattr(module, "patch_34_opus_47_adaptive_thinking", spy)
        for name in (
            "patch_23_agent_context",
            "patch_25_json_preprocessing",
            "patch_26_conversation_state",
            "patch_28_29_32_bedrock_listing",
            "patch_30_model_info_region_prefix",
            "patch_31_aws_default_region",
            "patch_33_default_bedrock_model",
        ):
            monkeypatch.setattr(module, name, lambda _bd, _n=name: True)

        monkeypatch.setattr(
            sys, "argv", ["apply-sdk-patches.py", str(fake_chat_options_tree)]
        )

        module.main()

        assert "patch_34" in called, "main() must invoke patch_34"
