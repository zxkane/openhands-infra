#!/usr/bin/env python3
"""
SDK Patches for OpenHands Agent Server Build

This script applies patches to the OpenHands SDK source code before PyInstaller
bundles it into a binary. These patches MUST be applied at build time because
the final binary is immutable.

Patches:
  - Patch 23: Skip invalid/masked secrets during conversation resume (AgentContext)
  - Patch 24: Use exclude_none=True in model_dump() (conversation_service)
  - Patch 25: Filter invalid secrets from JSON before model_validate_json
  - Patch 26: Filter invalid secret_sources from ConversationState

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

    # Find where to insert - after the secrets Field definition, before @field_validator
    insert_pattern = r'(\s+secrets:.*?\)\n)(\n\s+@field_validator)'
    insert_match = re.search(insert_pattern, content, re.DOTALL)
    if insert_match:
        insert_pos = insert_match.end(1)
        content = content[:insert_pos] + patch_code + content[insert_pos:]
        print("Patch 23: Added secret filter validator to AgentContext")
    else:
        # Try inserting after the last Field definition
        insert_pattern2 = r'(load_public_skills:.*?skills repository\..*?"\n\s+\)\n)'
        insert_match2 = re.search(insert_pattern2, content, re.DOTALL)
        if insert_match2:
            insert_pos = insert_match2.end(1)
            content = content[:insert_pos] + patch_code + content[insert_pos:]
            print("Patch 23: Added secret filter validator (alternative position)")
        else:
            print("ERROR: Could not find insertion point for Patch 23")
            return False

    agent_context_file.write_text(content)
    print("Patch 23: Successfully patched agent_context.py")
    return True


def patch_24_conversation_service_model_dump(build_dir: Path) -> bool:
    """
    Patch 24: Fix _compose_conversation_info to exclude None values.

    When the frontend polls /api/conversations, the state is dumped to dict
    and re-validated. Secrets with None values cause validation errors.
    """
    conv_service_file = build_dir / "openhands-agent-server/openhands/agent_server/conversation_service.py"

    if not conv_service_file.exists():
        print(f"ERROR: Patch 24 - File not found: {conv_service_file}")
        return False

    content = conv_service_file.read_text()

    # Fix: **state.model_dump() -> **state.model_dump(exclude_none=True)
    old_pattern = r'(\*\*state\.model_dump\(\))'
    if re.search(old_pattern, content):
        content = re.sub(
            old_pattern,
            r'**state.model_dump(exclude_none=True)',
            content
        )
        print("Patch 24: Updated _compose_conversation_info to use exclude_none=True")
    else:
        alt_pattern = r'(\*\*state\.model_dump\([^)]*\))'
        if re.search(alt_pattern, content):
            print("Patch 24: model_dump() already has arguments, skipping")
        else:
            print("WARNING: Patch 24 - Could not find model_dump pattern")

    conv_service_file.write_text(content)
    print("Patch 24: Successfully patched conversation_service.py")
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

    # Insert BEFORE existing _handle_secrets_manager_alias validator
    existing_validator_pattern = r'(\s+@model_validator\(mode="before"\)\s+@classmethod\s+def _handle_secrets_manager_alias)'
    match = re.search(existing_validator_pattern, content)
    if match:
        insert_pos = match.start()
        content = content[:insert_pos] + patch_code + content[insert_pos:]
        print("Patch 26: Added _filter_invalid_secret_sources validator")
    else:
        print("ERROR: Patch 26 - Could not find existing _handle_secrets_manager_alias validator")
        return False

    state_file.write_text(content)
    print("Patch 26: Successfully patched conversation/state.py")
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
    results.append(("Patch 24", patch_24_conversation_service_model_dump(build_dir)))
    results.append(("Patch 25", patch_25_json_preprocessing(build_dir)))
    results.append(("Patch 26", patch_26_conversation_state(build_dir)))

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
