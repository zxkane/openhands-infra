#!/usr/bin/env python3
"""
SDK Patches for OpenHands Agent Server Build

This script applies patches to the OpenHands SDK source code before PyInstaller
bundles it into a binary. These patches MUST be applied at build time because
the final binary is immutable.

Patches (active):
  - Patch 23: Skip invalid/masked secrets during conversation resume (AgentContext)
  - Patch 25: Filter invalid secrets from JSON before model_validate_json
  - Patch 26: Filter invalid secret_sources from ConversationState
  - Patch 28: Default credential chain for _list_bedrock_foundation_models
              (allows IAM-role / IRSA / AWS_PROFILE Bedrock listing without explicit creds)
  - Patch 29: Cross-region inference profile listing
              (adds bedrock/us. / bedrock/eu. / bedrock/apac. / bedrock/global. model IDs)
  - Patch 30: Cross-region prefix stripping in get_litellm_model_info
              (lets bedrock/us.anthropic.claude-* find its model_cost entry)
  - Patch 31: AWS_DEFAULT_REGION setdefault in _set_env_side_effects
              (boto3 prefers AWS_DEFAULT_REGION over AWS_REGION_NAME for some auth modes)
  - Patch 32: Env-hint trigger for Bedrock listing in get_supported_llm_models
              (AWS_PROFILE / AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE → list Bedrock too)

Removed (absorbed in upstream / obsolete):
  - Patch 24: SDK uses model_dump(mode="json") since v1.15.0
  - Patch 27: SDK v1.19.1 caps max_output_tokens to half the context window when
              max_output_tokens >= context_window (llm.py:1273-1287). Same outcome
              as the fork patch with a different mechanism.

Usage:
  python3 apply-sdk-patches.py /path/to/build/directory

Note: This is separate from docker/apply-patch.sh which applies runtime patches
to the OpenHands container. These build-time patches are required because
PyInstaller creates an immutable binary.
"""

import sys
import re
import os
from pathlib import Path


def patch_23_agent_context(build_dir: Path) -> bool:
    """
    Patch 23: Skip invalid/masked secrets during conversation resume.

    When base_state.json has secrets with null values (masked), Pydantic
    validation fails. This patch adds a model_validator to filter them out.
    """
    agent_context_file = build_dir / "openhands-sdk/openhands/sdk/context/agent_context.py"

    if not agent_context_file.exists():
        print(f"ERROR: Patch 23 - File not found: {agent_context_file}")
        return False

    content = agent_context_file.read_text()

    # Ensure model_validator is imported from pydantic
    if 'model_validator' not in content:
        if re.search(r'from pydantic import \(', content):
            # Multi-line import
            content = re.sub(
                r'(from pydantic import \(\s*\n)',
                r'\1    model_validator,\n',
                content,
                count=1
            )
            print("Patch 23: Added model_validator to multi-line pydantic imports")
        elif 'from pydantic import' in content:
            # Single-line import
            content = re.sub(
                r'(from pydantic import [^\n(]+)(\n)',
                r'\1, model_validator\2',
                content,
                count=1
            )
            print("Patch 23: Added model_validator to pydantic imports")
        else:
            print("WARNING: No pydantic import found, model_validator may not be available")

    # Add model_validator to filter out invalid secrets
    patch_code = '''
    @model_validator(mode="before")
    @classmethod
    def _filter_invalid_secrets(cls, data):
        """Filter out invalid/masked secrets during deserialization.

        Patch 23 (openhands-infra): When resuming a conversation after EC2 replacement,
        base_state.json may contain secrets with null/masked values. These cause
        Pydantic validation errors. This validator filters them out.
        """
        import logging
        logger = logging.getLogger(__name__)

        if not isinstance(data, dict):
            return data

        secrets = data.get("secrets")
        if not secrets or not isinstance(secrets, dict):
            return data

        filtered_secrets = {}
        for key, value in secrets.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 23: Skipping None secret '{key}'")
                continue
            # Skip dict values with missing or null 'value' field (masked SecretSource)
            # After exclude_none=True serialization, 'value' key may be missing entirely
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 23: Skipping masked secret '{key}'")
                continue
            # Keep valid secrets
            filtered_secrets[key] = value

        if len(filtered_secrets) < len(secrets):
            logger.info(f"Patch 23: Filtered {len(secrets) - len(filtered_secrets)} invalid secrets")

        data["secrets"] = filtered_secrets if filtered_secrets else None
        return data

'''

    # Insert immediately before the first @field_validator inside AgentContext.
    # In SDK v1.19.1 the order is: secrets → current_datetime → @field_validator("skills"),
    # so anchoring on @field_validator (rather than on the secrets Field's closing paren)
    # is the stable choice.
    insert_pattern = r'(\n    @field_validator\("skills"\))'
    insert_match = re.search(insert_pattern, content)
    if insert_match:
        insert_pos = insert_match.start()
        content = content[:insert_pos] + patch_code + content[insert_pos:]
        print("Patch 23: Added secret filter validator before @field_validator(\"skills\")")
    else:
        print("ERROR: Could not find insertion point for Patch 23 "
              "(no @field_validator(\"skills\") in AgentContext — "
              "SDK structure may have changed again)")
        return False

    agent_context_file.write_text(content)
    print("Patch 23: Successfully patched agent_context.py")
    return True



def patch_25_json_preprocessing(build_dir: Path) -> bool:
    """
    Patch 25: Filter invalid secrets from JSON before model_validate_json.

    When loading StoredConversation from stored.json, Pydantic fails if
    secrets have None values.
    """
    conv_service_file = build_dir / "openhands-agent-server/openhands/agent_server/conversation_service.py"

    if not conv_service_file.exists():
        print(f"ERROR: Patch 25 - File not found: {conv_service_file}")
        return False

    content = conv_service_file.read_text()

    # Add helper function after imports
    helper_function = '''
import json as _json_module

def _filter_invalid_secrets_from_json(json_str: str) -> str:
    """Preprocess JSON to filter out secrets with null values.

    Patch 25 (openhands-infra): When loading StoredConversation, secrets with
    null values (masked after EC2 replacement) cause Pydantic validation errors.
    This filters them out before validation.
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        data = _json_module.loads(json_str)
    except _json_module.JSONDecodeError:
        return json_str  # Return as-is if not valid JSON

    if not isinstance(data, dict):
        return json_str

    secrets = data.get("secrets")
    if secrets and isinstance(secrets, dict):
        filtered_secrets = {}
        skipped = 0
        for key, value in secrets.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 25: Skipping None secret '{key}'")
                skipped += 1
                continue
            # Skip dict values with missing or null 'value' field (masked SecretSource)
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 25: Skipping masked secret '{key}'")
                skipped += 1
                continue
            filtered_secrets[key] = value

        if skipped > 0:
            logger.info(f"Patch 25: Filtered {skipped} invalid secrets from StoredConversation")
            data["secrets"] = filtered_secrets if filtered_secrets else {}
            return _json_module.dumps(data)

    return json_str

'''

    # Insert helper function after the last import statement
    import_section_end = 0
    for match in re.finditer(r'^(from .+|import .+)\n', content, re.MULTILINE):
        import_section_end = match.end()

    if import_section_end > 0:
        content = content[:import_section_end] + helper_function + content[import_section_end:]
        print("Patch 25: Added _filter_invalid_secrets_from_json helper function")

    # Wrap the model_validate_json call
    old_pattern = r'(StoredConversation\.model_validate_json\(\s*\n\s+)(json_str)(,)'
    new_replacement = r'\1_filter_invalid_secrets_from_json(json_str)\3'

    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_replacement, content)
        print("Patch 25: Wrapped json_str with _filter_invalid_secrets_from_json()")
    else:
        if "StoredConversation.model_validate_json" in content:
            print("WARNING: Patch 25 - Found model_validate_json but pattern didn't match")
        else:
            print("WARNING: Patch 25 - StoredConversation.model_validate_json not found")

    conv_service_file.write_text(content)
    print("Patch 25: Successfully patched conversation_service.py for JSON preprocessing")
    return True


def patch_26_conversation_state(build_dir: Path) -> bool:
    """
    Patch 26: Filter invalid secret_sources from ConversationState.

    ConversationState loads from base_state.json which may have secrets
    with missing 'value' field.
    """
    state_file = build_dir / "openhands-sdk/openhands/sdk/conversation/state.py"

    if not state_file.exists():
        print(f"ERROR: Patch 26 - File not found: {state_file}")
        return False

    content = state_file.read_text()

    # Verify model_validator is imported
    if 'model_validator' not in content:
        print("WARNING: Patch 26 - model_validator not found, attempting to add")
        if 'from pydantic import' in content:
            content = re.sub(
                r'(from pydantic import [^\n]+)',
                r'\1, model_validator',
                content,
                count=1
            )
            print("Patch 26: Added model_validator to pydantic imports")
    else:
        print("Patch 26: model_validator already imported")

    # Add validator to filter invalid secret_registry entries
    patch_code = '''
    @model_validator(mode="before")
    @classmethod
    def _filter_invalid_secret_sources(cls, data):
        """Filter out invalid/masked secrets from secret_registry during deserialization.

        Patch 26 (openhands-infra): When resuming a conversation after EC2 replacement,
        base_state.json may contain secret_registry.secret_sources with missing 'value' fields.
        This happens because exclude_none=True removes null values during serialization.
        This validator filters them out to prevent ValidationError.
        """
        import logging
        logger = logging.getLogger(__name__)

        if not isinstance(data, dict):
            return data

        secret_registry = data.get("secret_registry")
        if not secret_registry or not isinstance(secret_registry, dict):
            return data

        secret_sources = secret_registry.get("secret_sources")
        if not secret_sources or not isinstance(secret_sources, dict):
            return data

        filtered_sources = {}
        skipped = 0
        for key, value in secret_sources.items():
            # Skip None values
            if value is None:
                logger.warning(f"Patch 26: Skipping None secret_source '{key}'")
                skipped += 1
                continue
            # Skip dict values with missing or null 'value' field
            if isinstance(value, dict) and ("value" not in value or value.get("value") is None):
                logger.warning(f"Patch 26: Skipping masked secret_source '{key}'")
                skipped += 1
                continue
            filtered_sources[key] = value

        if skipped > 0:
            logger.info(f"Patch 26: Filtered {skipped} invalid secret_sources from ConversationState")
            secret_registry["secret_sources"] = filtered_sources
            data["secret_registry"] = secret_registry

        return data

'''

    # Insert BEFORE existing model_validator or first @property in ConversationState
    # v1.8.x: _handle_secrets_manager_alias, v1.11.x+: _handle_legacy_fields, v1.15: none
    existing_validator_pattern = r'(\s+@model_validator\(mode="before"\)\s+@classmethod\s+def _handle_(?:secrets_manager_alias|legacy_fields))'
    match = re.search(existing_validator_pattern, content)
    if match:
        insert_pos = match.start()
        content = content[:insert_pos] + patch_code + content[insert_pos:]
        print("Patch 26: Added _filter_invalid_secret_sources validator (before existing validator)")
    else:
        # v1.15.0+: no existing model_validator, insert before first @property
        property_pattern = r'(\n    @property\n    def events\b)'
        prop_match = re.search(property_pattern, content)
        if prop_match:
            insert_pos = prop_match.start()
            content = content[:insert_pos] + patch_code + content[insert_pos:]
            print("Patch 26: Added _filter_invalid_secret_sources validator (before first property)")
        else:
            print("ERROR: Patch 26 - Could not find insertion point in ConversationState")
            return False

    state_file.write_text(content)
    print("Patch 26: Successfully patched conversation/state.py")
    return True


def patch_28_29_32_bedrock_listing(build_dir: Path) -> bool:
    """
    Replaces SDK ``_list_bedrock_foundation_models`` and ``get_supported_llm_models``
    in ``unverified_models.py`` with fork variants that:

    * Patch 28: drop the requirement that all three creds (region / access_key /
      secret_key) be present. Pass them only when truthy so boto3 falls through to
      the default credential chain (IAM role, IRSA, AWS_PROFILE, EC2 metadata).
    * Patch 29: enumerate cross-region inference profiles via
      ``list_inference_profiles(typeEquals="SYSTEM_DEFINED")`` and merge the
      ``bedrock/us.``, ``bedrock/eu.``, ``bedrock/apac.``, ``bedrock/global.``
      model IDs into the returned list.
    * Patch 32: trigger ``_list_bedrock_foundation_models`` when
      ``AWS_PROFILE`` / ``AWS_ROLE_ARN`` / ``AWS_WEB_IDENTITY_TOKEN_FILE`` is set
      (env-hint mode), even without explicit static creds. Required for IRSA
      and Cognito-federated EC2 IAM workflows where there are no AWS_* keys.

    These three patches are wired together (sharing a rewritten
    ``_list_bedrock_foundation_models`` signature), so they ship as one atomic
    rewrite of the file. We rewrite by replacing function bodies via regex
    rather than full-file replacement so that re-anchoring on future SDK bumps
    stays mechanical.
    """
    target = build_dir / "openhands-sdk/openhands/sdk/llm/utils/unverified_models.py"
    if not target.exists():
        print(f"ERROR: Patch 28/29/32 - File not found: {target}")
        return False

    content = target.read_text()

    # Replace the entire _list_bedrock_foundation_models function body.
    list_pattern = re.compile(
        r"def _list_bedrock_foundation_models\([^)]*\) -> list\[str\]:\n"
        r"(?:.*\n)+?(?=\n\ndef get_supported_llm_models)",
        re.MULTILINE,
    )
    list_replacement = (
        'def _list_bedrock_foundation_models(\n'
        '    aws_region_name: str | None = None,\n'
        '    aws_access_key_id: str | None = None,\n'
        '    aws_secret_access_key: str | None = None,\n'
        ') -> list[str]:\n'
        '    """List Bedrock foundation models + cross-region inference profiles.\n'
        '\n'
        '    Patch 28 (openhands-infra): all three creds are now optional. boto3\n'
        '    falls through to the default credential chain when they are omitted,\n'
        '    which lets IAM-role / IRSA / AWS_PROFILE workflows list Bedrock\n'
        '    models without explicit access keys.\n'
        '\n'
        '    Patch 29 (openhands-infra): also enumerate SYSTEM_DEFINED inference\n'
        '    profiles (cross-region routing) and surface them as bedrock/<prefix>\n'
        '    model IDs alongside the foundation models.\n'
        '    """\n'
        '    boto3 = _get_boto3()\n'
        '    if boto3 is None:\n'
        '        logger.warning(\n'
        '            "boto3 is not installed. To use Bedrock models,"\n'
        '            "install with: openhands-sdk[boto3]"\n'
        '        )\n'
        '        return []\n'
        '\n'
        '    client_kwargs: dict[str, str] = {"service_name": "bedrock"}\n'
        '    if aws_region_name:\n'
        '        client_kwargs["region_name"] = aws_region_name\n'
        '    if aws_access_key_id:\n'
        '        client_kwargs["aws_access_key_id"] = aws_access_key_id\n'
        '    if aws_secret_access_key:\n'
        '        client_kwargs["aws_secret_access_key"] = aws_secret_access_key\n'
        '\n'
        '    try:\n'
        '        client = boto3.client(**client_kwargs)\n'
        '        foundation_models_list = client.list_foundation_models(\n'
        '            byOutputModality="TEXT", byInferenceType="ON_DEMAND"\n'
        '        )\n'
        '        model_summaries = foundation_models_list["modelSummaries"]\n'
        '        result = ["bedrock/" + model["modelId"] for model in model_summaries]\n'
        '\n'
        '        try:\n'
        '            paginator = client.get_paginator("list_inference_profiles")\n'
        '            for page in paginator.paginate(typeEquals="SYSTEM_DEFINED"):\n'
        '                for profile in page.get("inferenceProfileSummaries", []):\n'
        '                    profile_id = profile.get("inferenceProfileId")\n'
        '                    if profile_id:\n'
        '                        result.append("bedrock/" + profile_id)\n'
        '        except Exception as profile_err:\n'
        '            logger.debug(\n'
        '                "Patch 29: list_inference_profiles failed (%s); "\n'
        '                "skipping cross-region IDs.",\n'
        '                profile_err,\n'
        '            )\n'
        '\n'
        '        return result\n'
        '    except Exception as err:\n'
        '        logger.warning(\n'
        '            "%s. Configure AWS_REGION_NAME and either AWS_ACCESS_KEY_ID/"\n'
        '            "AWS_SECRET_ACCESS_KEY or an IAM-role / AWS_PROFILE if you "\n'
        '            "want to use Bedrock models.",\n'
        '            err,\n'
        '        )\n'
        '        return []\n'
    )
    if not list_pattern.search(content):
        print("ERROR: Patch 28/29 - Could not locate _list_bedrock_foundation_models")
        return False
    content = list_pattern.sub(list_replacement, content, count=1)
    print("Patch 28/29: Rewrote _list_bedrock_foundation_models (default cred chain + inference profiles)")

    # Replace the gating block inside get_supported_llm_models (Patch 32).
    gate_pattern = re.compile(
        r"    bedrock_model_list = \[\]\n"
        r"    if aws_region_name and aws_access_key_id and aws_secret_access_key:\n"
        r"        bedrock_model_list = _list_bedrock_foundation_models\(\n"
        r"            aws_region_name,\n"
        r"            aws_access_key_id\.get_secret_value\(\),\n"
        r"            aws_secret_access_key\.get_secret_value\(\),\n"
        r"        \)\n"
    )
    gate_replacement = (
        '    bedrock_model_list = []\n'
        '    # Patch 32 (openhands-infra): trigger Bedrock listing when explicit creds\n'
        '    # are present OR when env hints (AWS_PROFILE / AWS_ROLE_ARN /\n'
        '    # AWS_WEB_IDENTITY_TOKEN_FILE) suggest the default credential chain can\n'
        '    # resolve a session — paired with Patch 28 default-cred-chain support.\n'
        '    _has_static_creds = bool(\n'
        '        aws_region_name and aws_access_key_id and aws_secret_access_key\n'
        '    )\n'
        '    _has_env_hint = bool(\n'
        '        os.environ.get("AWS_PROFILE")\n'
        '        or os.environ.get("AWS_ROLE_ARN")\n'
        '        or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")\n'
        '    )\n'
        '    if _has_static_creds or _has_env_hint:\n'
        '        bedrock_model_list = _list_bedrock_foundation_models(\n'
        '            aws_region_name,\n'
        '            aws_access_key_id.get_secret_value() if aws_access_key_id else None,\n'
        '            aws_secret_access_key.get_secret_value() if aws_secret_access_key else None,\n'
        '        )\n'
    )
    if not gate_pattern.search(content):
        print("ERROR: Patch 32 - Could not locate Bedrock gating block in get_supported_llm_models")
        return False
    content = gate_pattern.sub(gate_replacement, content, count=1)
    print("Patch 32: Added env-hint trigger for Bedrock listing")

    # Add `import os` if not already present (used by Patch 32 env-hint check).
    if not re.search(r"^import os\b", content, re.MULTILINE):
        content = re.sub(
            r"^import importlib\n",
            "import importlib\nimport os\n",
            content,
            count=1,
        )
        print("Patch 32: Added 'import os' to unverified_models.py")

    target.write_text(content)
    print("Patch 28/29/32: Successfully rewrote unverified_models.py")
    return True


def patch_30_model_info_region_prefix(build_dir: Path) -> bool:
    """
    Patch 30: Strip cross-region prefix in get_litellm_model_info fallback.

    bedrock/us.anthropic.claude-3-7-sonnet-20250219-v1:0 doesn't have a litellm
    model_cost entry, but bedrock/anthropic.claude-3-7-sonnet-20250219-v1:0 does.
    Add a 3rd fallback that re.subs ``bedrock/(us|eu|apac|global)\\.`` →
    ``bedrock/`` so cross-region inference profile IDs resolve their cost / context
    window metadata.
    """
    target = build_dir / "openhands-sdk/openhands/sdk/llm/utils/model_info.py"
    if not target.exists():
        print(f"ERROR: Patch 30 - File not found: {target}")
        return False

    content = target.read_text()

    if "bedrock/(us|eu|apac|global)" in content:
        print("Patch 30: Already applied (skipping)")
        return True

    # Insert a 3rd fallback before `return None` at the end of get_litellm_model_info.
    anchor = (
        "    try:\n"
        "        model_info = get_model_info(model.split(\"/\")[-1])\n"
        "        if model_info:\n"
        "            return model_info\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "    return None"
    )
    if anchor not in content:
        print("ERROR: Patch 30 - Could not find tail anchor in get_litellm_model_info")
        return False

    new_block = (
        "    try:\n"
        "        model_info = get_model_info(model.split(\"/\")[-1])\n"
        "        if model_info:\n"
        "            return model_info\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "    # Patch 30 (openhands-infra): strip cross-region inference profile prefix\n"
        "    # (us. / eu. / apac. / global.) so bedrock/us.anthropic.* resolves to the\n"
        "    # underlying bedrock/anthropic.* model_cost entry.\n"
        "    try:\n"
        "        import re as _re\n"
        "        stripped = _re.sub(r'^bedrock/(us|eu|apac|global)\\.', 'bedrock/', model)\n"
        "        if stripped != model:\n"
        "            model_info = get_model_info(stripped)\n"
        "            if model_info:\n"
        "                return model_info\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "    return None"
    )

    content = content.replace(anchor, new_block, 1)
    target.write_text(content)
    print("Patch 30: Added cross-region prefix stripping fallback to get_litellm_model_info")
    return True


def patch_31_aws_default_region(build_dir: Path) -> bool:
    """
    Patch 31: Set AWS_DEFAULT_REGION alongside AWS_REGION_NAME.

    boto3 prefers AWS_DEFAULT_REGION for some auth modes (notably IAM Identity
    Center / SSO and certain metadata-service paths). The SDK only sets
    AWS_REGION_NAME, leaving boto3 unable to resolve a region in those modes.
    """
    target = build_dir / "openhands-sdk/openhands/sdk/llm/llm.py"
    if not target.exists():
        print(f"ERROR: Patch 31 - File not found: {target}")
        return False

    content = target.read_text()

    if 'os.environ.setdefault("AWS_DEFAULT_REGION"' in content:
        print("Patch 31: Already applied (skipping)")
        return True

    anchor = (
        '        if self.aws_region_name:\n'
        '            os.environ["AWS_REGION_NAME"] = self.aws_region_name\n'
    )
    if anchor not in content:
        print("ERROR: Patch 31 - Could not find AWS_REGION_NAME anchor in _set_env_side_effects")
        return False

    new_block = (
        '        if self.aws_region_name:\n'
        '            os.environ["AWS_REGION_NAME"] = self.aws_region_name\n'
        '            # Patch 31 (openhands-infra): boto3 prefers AWS_DEFAULT_REGION\n'
        '            # over AWS_REGION_NAME for some auth modes (IAM Identity\n'
        '            # Center / SSO, EC2 metadata service in certain configs).\n'
        '            # Use setdefault so an explicit env var still wins.\n'
        '            os.environ.setdefault("AWS_DEFAULT_REGION", self.aws_region_name)\n'
    )
    content = content.replace(anchor, new_block, 1)
    target.write_text(content)
    print("Patch 31: Added AWS_DEFAULT_REGION setdefault in _set_env_side_effects")
    return True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/build/directory")
        sys.exit(1)

    build_dir = Path(sys.argv[1])

    if not build_dir.exists():
        print(f"ERROR: Build directory not found: {build_dir}")
        sys.exit(1)

    print("=" * 60)
    print("OpenHands SDK Patches")
    print("=" * 60)
    print(f"Build directory: {build_dir}")
    print()

    results = []

    # Apply all patches
    results.append(("Patch 23", patch_23_agent_context(build_dir)))
    # Patch 24 removed — SDK v1.15.0+ already uses model_dump(mode="json")
    results.append(("Patch 25", patch_25_json_preprocessing(build_dir)))
    results.append(("Patch 26", patch_26_conversation_state(build_dir)))
    # Patch 27 removed — SDK v1.19.1 caps max_output_tokens to half the context
    # window (llm.py:1273-1287). Same outcome via different mechanism.
    results.append(("Patch 28/29/32", patch_28_29_32_bedrock_listing(build_dir)))
    results.append(("Patch 30", patch_30_model_info_region_prefix(build_dir)))
    results.append(("Patch 31", patch_31_aws_default_region(build_dir)))

    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)

    failed = []
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {name}: {status}")
        if not success:
            failed.append(name)

    if failed:
        print()
        print(f"ERROR: {len(failed)} patch(es) failed: {', '.join(failed)}")
        sys.exit(1)

    print()
    print("All patches applied successfully!")


if __name__ == "__main__":
    main()
