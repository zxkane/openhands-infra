# OpenHands v1.6.0 → v1.7.0 Upgrade Feasibility Report

**Author:** zxkane (via Claude Code session)
**Date:** 2026-05-13
**Upstream release:** v1.7.0 (2026-05-01), 296 commits since v1.6.0
**SDK bump:** v1.15.0 → v1.19.1 (4 minor versions)
**Status:** ⚠️ **Higher-impact than prior upgrades.** Recommendation at the bottom.

---

## TL;DR

v1.7.0 is dominated by a **V0 → V1 cleanup**. Upstream deleted multiple legacy packages
the fork has been patching since v1.4.0:

- `openhands/llm/` — entire package removed (Bedrock + LLM module gone, logic now in SDK)
- `openhands/utils/llm.py` — moved to `openhands/app_server/utils/llm.py`
- `openhands/storage/` — `__init__.py` removed; subdirs `secrets/`, `settings/`, `conversation/` collapsed into `openhands/app_server/{secrets,settings}/`
- `openhands/storage/data_models/secrets.py` — moved to `openhands/app_server/secrets/secrets_models.py`
- `openhands/server/config/server_config.py` — kept but explicitly tagged `Legacy-V0`, scheduled for removal "April 1, 2026"; conversation_store / conversation_manager / monitoring_listener fields removed

The fork's 14-file patch set therefore breaks down as (after **verifying each LLM patch against actual SDK v1.19.1 source**, not just upstream PR titles):

| Status                | # files | Notes |
|-----------------------|---------|-------|
| ✅ Apply cleanly        | 2       | `app_conversation_service.py`, `db_session_injector.py` |
| ⚠️ Apply with conflicts | 4       | `live_status_app_conversation_service.py` (17 commits), `app_conversation_router.py`, `webhook_router.py`, `sql_event_callback_service.py`, `app_server/config.py`, `remote_sandbox_service.py` |
| 🔁 Port to V1 OpenHands paths | 4 | Cognito auth, S3 stores → `openhands/app_server/{user_auth,settings,secrets}/`; fork's `utils/llm.py` env-hint detection → `app_server/utils/llm.py` |
| 🔁 Port to SDK fork     | 3       | `llm/bedrock.py` default-cred-chain + inference-profile listing, `llm/llm.py` cross-region prefix stripping, `llm_config.py` AWS_DEFAULT_REGION — **none of these are in upstream SDK v1.19.1** |
| ❌ Drop (V0 obsolete)   | 1       | `server_config.py` (V0 store-class fields removed) |
| ❌ Drop (truly absorbed in SDK) | ~1 | The `max_output_tokens` half of `llm/llm.py` is covered by SDK PR #2264 |

**Important correction from initial draft**: I initially marked 4 LLM-related fork patches as "absorbed in SDK v1.19.1" based on closed upstream issues #2198 and #2247. Reading the actual SDK v1.19.1 source contradicts that. **Only the `max_output_tokens` cap** logic is truly absorbed. Default-credential-chain Bedrock listing, cross-region inference profile enumeration, env-hint detection, AWS_DEFAULT_REGION setdefault, and cross-region prefix stripping for model_info — **all still missing in upstream**. These features must move into the SDK fork (which the agent-server custom Dockerfile already builds from a fork branch) via `apply-sdk-patches.py`.

This shifts SDK-side patches from 4 → ~6 (one drop, four new) and OpenHands-side patches from "drop 4, port 3" to "drop 1, port 7".

---

## Section 1: Upstream changes that affect the fork

### 1.1 V0 deletions

| Path | Status in v1.7.0 | Upstream removal commit |
|------|------------------|------------------------|
| `openhands/llm/__init__.py` | DELETED | `aea611602` ("Remove openhands.llm package (legacy V0 code)") |
| `openhands/llm/bedrock.py` | DELETED | same |
| `openhands/llm/llm.py` | DELETED | same |
| `openhands/utils/llm.py` | MOVED → `openhands/app_server/utils/llm.py` | `18460a346` ("refactor: move openhands.utils to openhands.app_server.utils") |
| `openhands/core/config/llm_config.py` | DELETED | `2ed36cfa7` ("Remove legacy LLMConfig and all related code") |
| `openhands/storage/data_models/secrets.py` | DELETED | (storage package collapse) |
| `openhands/server/config/server_config.py` | PRESENT, marked `Legacy-V0` (removal Apr 1 2026); `conversation_store_class`, `conversation_manager_class`, `monitoring_listener_class` fields removed; remaining fields point to V1 (`openhands.app_server.*`) | various |

### 1.2 V1 paths the fork must now target

| V0 path (v1.6.0)                                           | V1 path (v1.7.0)                                            |
|------------------------------------------------------------|--------------------------------------------------------------|
| `openhands.storage.settings.s3_settings_store.S3SettingsStore` | port to `openhands/app_server/settings/` (extends `SettingsStore`) |
| `openhands.storage.secrets.s3_secrets_store.S3SecretsStore`     | port to `openhands/app_server/secrets/` (extends `SecretsStore`) |
| `openhands.server.user_auth.cognito_user_auth.CognitoUserAuth`  | port to `openhands/app_server/user_auth/` (extends `UserAuth`) |
| `openhands.storage.conversation.cognito_file_conversation_store.CognitoFileConversationStore` | **No direct V1 equivalent.** Fork patch on `app_server/config.py` already handles per-user conversation isolation via `CognitoSQLAppConversationInfoServiceInjector` — the V0 store override is redundant. |

### 1.3 SDK upgrades (v1.15.0 → v1.19.1) — verified against actual SDK source

I verified each fork LLM patch against `openhands-sdk` v1.19.1 source. **Initial assumption that SDK PRs #2598 / #2264 fully absorbed the fork's Bedrock work was wrong.** Updated findings:

| Fork patch | What it does | SDK v1.19.1 / upstream v1.7.0 actual status | Verdict |
|------------|--------------|---------------------------------------------|---------|
| `llm/bedrock.py:_create_bedrock_client` — default credential chain when no explicit creds | Allows `boto3.client('bedrock')` with no creds → falls through to default chain (IRSA, AWS_PROFILE, EC2 IAM, etc.) | SDK `_list_bedrock_foundation_models` (`openhands-sdk/openhands/sdk/llm/utils/unverified_models.py:34-39`) calls `client.list_foundation_models` with **all three creds passed unconditionally**. No fallback. | ❌ **NOT absorbed** — patch logic lost |
| `llm/bedrock.py` cross-region inference profile listing | Adds `bedrock/us.anthropic...` model IDs via `paginate('list_inference_profiles')` | SDK only calls `list_foundation_models`. No inference-profile enumeration. | ❌ **NOT absorbed** — patch logic lost |
| `llm/llm.py` cross-region prefix stripping for model_info lookup | Strips `bedrock/us.\|eu.\|apac.\|global.` prefix to find litellm model_cost entry | SDK `model_info.py:79-88` falls back to `model.split(":")[0]` (strips `:N` version) and `model.split("/")[-1]` (last segment). **Doesn't strip cross-region prefix.** | ⚠️ **Partial** — version stripping yes, region prefix no |
| `llm/llm.py` Bedrock `max_output_tokens` handling | (a) When `None`, pop `max_completion_tokens`; (b) when `==max_input_tokens`, set None | SDK `llm.py:1259-1304` caps via `max_output_tokens // 2` when `>= context_window`; uses `min(max_tokens, DEFAULT_MAX_OUTPUT_TOKENS_CAP)` for ambiguous case. SDK is more conservative but covers the same failure mode. | ✅ **Absorbed** (different mechanism, same outcome) |
| `utils/llm.py` env-hint detection for Bedrock listing | Triggers Bedrock listing when `AWS_PROFILE`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` set, even without explicit creds | SDK `get_supported_llm_models` (`unverified_models.py:69-71`) requires `aws_region_name and aws_access_key_id and aws_secret_access_key` — same as pre-fork V0 | ❌ **NOT absorbed** — IRSA / AWS_PROFILE workflows can't list Bedrock models |
| `core/config/llm_config.py` `os.environ.setdefault('AWS_DEFAULT_REGION', ...)` | Sets boto3-preferred env var alongside `AWS_REGION_NAME` | SDK sets `AWS_REGION_NAME` only (`llm.py:533-534`); does not set `AWS_DEFAULT_REGION`. boto3 prefers the latter. | ❌ **NOT absorbed** — boto3 may miss region in some auth modes |
| `apply-sdk-patches.py` Patch 27 "Bedrock max_output_tokens" | Same as `llm/llm.py` (b) above | Same as above row | ✅ **Absorbed** |
| `apply-sdk-patches.py` Patches 23/25/26 (secret-resume validators) | Filter invalid/masked secrets during conversation resume | No matching upstream PR found in search | 🔍 Likely **still required**; re-anchor patterns against v1.19.1 |

**Conclusion change vs initial report**: I cannot drop `llm/bedrock.py`, `llm/llm.py`, `utils/llm.py`, or `core/config/llm_config.py` patches as "absorbed". The Bedrock features the fork added (default credential chain for listing models, inference-profile enumeration, env-hint detection, AWS_DEFAULT_REGION setdefault) are **NOT in upstream v1.7.0 / SDK v1.19.1**.

The corresponding upstream **files are deleted**, but the **logic is also missing**. So these become **port required** patches, not drop patches:

- `openhands/utils/llm.py` patch → port to `openhands/app_server/utils/llm.py` (still exists; needs env-hint detection + default-cred-chain)
- `openhands/llm/bedrock.py` patch → port to SDK fork OR a new file under `openhands/app_server/utils/` (since `openhands/llm/` is deleted, this needs a home — easiest is a new fork-only `openhands/app_server/utils/bedrock_listing.py` consumed by the patched `app_server/utils/llm.py`)
- `openhands/llm/llm.py` patch → port to SDK fork (`openhands-sdk/openhands/sdk/llm/llm.py` and `openhands-sdk/openhands/sdk/llm/utils/model_info.py`); **not patchable in OpenHands repo anymore**
- `openhands/core/config/llm_config.py` patch (`AWS_DEFAULT_REGION`) → port to SDK fork (`openhands-sdk/openhands/sdk/llm/llm.py:_set_env_side_effects`); **not patchable in OpenHands repo anymore**

This expands SDK-side patches from 4 to **6**. The infra repo's `apply-sdk-patches.py` will need 2 new patches (cross-region prefix stripping + AWS_DEFAULT_REGION setdefault + default credential chain for listing).

---

## Section 2: Per-patch verdict

Each row is one of the 14 files in `docker/download-fork-patches.sh:FILES`, plus the
4 SDK build-time patches in `docker/agent-server-custom/apply-sdk-patches.py`.

### Build-time fork patches (`download-fork-patches.sh`)

| # | File | Upstream commits since 1.6.0 | Verdict | Action |
|---|------|------------------------------|---------|--------|
| 1 | `openhands/app_server/sandbox/remote_sandbox_service.py` | 2 | ✅ Apply | Cherry-pick conflicts likely trivial; re-test pod_status mapping |
| 2 | `openhands/app_server/app_conversation/app_conversation_service.py` | 0 | ✅ Apply | Should apply cleanly |
| 3 | `openhands/app_server/app_conversation/live_status_app_conversation_service.py` | **17** | ⚠️ Conflict-heavy | Highest-conflict file, as in prior upgrades. Manual merge of 8 fork commits required. |
| 4 | `openhands/app_server/app_conversation/app_conversation_router.py` | 5 | ⚠️ Conflicts | Resolvable; verify 404 auto-register flow still works |
| 5 | `openhands/app_server/event_callback/webhook_router.py` | 5 | ⚠️ Conflicts | Resolvable |
| 6 | `openhands/app_server/services/db_session_injector.py` | 1 | ✅ Apply | (Already applied cleanly in dry-run cherry-pick) |
| 7 | `openhands/server/config/server_config.py` | 7 | ❌ **Drop patch entirely** | V0 store-class fields removed upstream; V1 customization happens in `app_server/config.py`. Fork's V0 overrides are redundant. **Remove from `download-fork-patches.sh:FILES`.** |
| 8 | `openhands/storage/data_models/secrets.py` | DELETED upstream | 🔁 **Port** | Re-target to `openhands/app_server/secrets/secrets_models.py` if the patch logic is still needed. Verify what the fork actually changed (likely `secret_sources` filtering). |
| 9 | `openhands/app_server/config.py` | 5 | ⚠️ Conflicts | Resolvable; rewires Cognito injectors. |
| 10 | `openhands/app_server/event_callback/sql_event_callback_service.py` | 1 | ⚠️ Conflict (SQLAlchemy 2.0 style) | Mechanical: rewrite `Column(SQLUUID, ..., default=uuid4)` → `Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)`. Pattern verified during dry-run. |
| 11 | `openhands/llm/bedrock.py` | DELETED upstream | 🔁 **Port to SDK fork** | Logic NOT in SDK. Default-cred-chain + inference-profile listing must move to SDK fork (`openhands-sdk` patch) or a fork-only file consumed by patched `app_server/utils/llm.py`. **Remove from FILES** (V0 path gone) but **add new SDK patch**. |
| 12 | `openhands/llm/llm.py` | DELETED upstream | 🔁 **Port to SDK fork** | Cross-region prefix stripping for model_info lookup NOT in SDK. **Remove from FILES** (V0 path gone) but **add new SDK patch** in `openhands-sdk/openhands/sdk/llm/utils/model_info.py`. The `max_output_tokens` part IS absorbed — drop only that piece. |
| 13 | `openhands/utils/llm.py` | DELETED upstream (moved to `app_server/utils/llm.py`) | 🔁 **Port to V1 path** | Env-hint detection (AWS_PROFILE/AWS_ROLE_ARN/AWS_WEB_IDENTITY_TOKEN_FILE) NOT in SDK. **Re-target FILES entry** to `openhands/app_server/utils/llm.py` and reapply env-hint logic against the v1.7.0 file. |
| 14 | `openhands/core/config/llm_config.py` | DELETED upstream | 🔁 **Port to SDK fork** | `AWS_DEFAULT_REGION` setdefault NOT in SDK. **Remove from FILES** but **add new SDK patch** in `openhands-sdk/openhands/sdk/llm/llm.py:_set_env_side_effects`. |

### SDK build-time patches (`apply-sdk-patches.py`)

| Patch | Purpose | Verdict | Action |
|------|---------|---------|--------|
| 23 | Skip invalid/masked secrets in `agent_context.py` `model_validator` | 🔍 Re-verify | Run patch against SDK v1.19.1 source; insertion pattern may have shifted |
| 25 | Filter invalid secrets from JSON before `model_validate_json` | 🔍 Re-verify | Same |
| 26 | Filter invalid `secret_sources` from `ConversationState` | 🔍 Re-verify | v1.6.0 upgrade already had to relocate this anchor (`@property def events`); v1.19.1 may have moved it again |
| 27 | Fix Bedrock `max_output_tokens` when litellm reports context window | ❌ **Drop** | Absorbed in SDK PR #2264 (merged into v1.13+, present in v1.19.1) |
| **NEW** | Default credential chain for `_list_bedrock_foundation_models` (no explicit creds → boto3 default chain) | 🆕 **Add** | SDK `openhands-sdk/openhands/sdk/llm/utils/unverified_models.py:21-50` — make all three creds optional, omit when falsy |
| **NEW** | Cross-region inference profile enumeration in `_list_bedrock_foundation_models` | 🆕 **Add** | Same file — add `paginate('list_inference_profiles', typeEquals='SYSTEM_DEFINED')` |
| **NEW** | Cross-region prefix stripping for `get_litellm_model_info` | 🆕 **Add** | SDK `openhands-sdk/openhands/sdk/llm/utils/model_info.py:79-90` — add `re.sub(r'^bedrock/(us\|eu\|apac\|global)\.', 'bedrock/', model)` fallback |
| **NEW** | `AWS_DEFAULT_REGION` setdefault alongside `AWS_REGION_NAME` | 🆕 **Add** | SDK `openhands-sdk/openhands/sdk/llm/llm.py:533-534` — `os.environ.setdefault('AWS_DEFAULT_REGION', ...)` |
| **NEW** | Bedrock env-hint listing in `get_supported_llm_models` | 🆕 **Add** | SDK `unverified_models.py:69-75` — accept env hints (AWS_PROFILE/AWS_ROLE_ARN/AWS_WEB_IDENTITY_TOKEN_FILE) as trigger to call `_list_bedrock_foundation_models` |

### New V1 patches the fork must add

These are **net-new** files we'll need under `openhands/app_server/` to replace V0 customization:

| New fork file | Replaces V0 | Notes |
|---------------|-------------|-------|
| `openhands/app_server/settings/cognito_s3_settings_store.py` | `openhands/storage/settings/s3_settings_store.py` | Extend new `SettingsStore` ABC; reuse existing S3 path logic (`users/{user_id}/settings/...`) |
| `openhands/app_server/secrets/cognito_s3_secrets_store.py` | `openhands/storage/secrets/s3_secrets_store.py` | Extend new `SecretsStore` ABC; reuse KMS envelope encryption |
| `openhands/app_server/user_auth/cognito_user_auth.py` | `openhands/server/user_auth/cognito_user_auth.py` | Extend new `UserAuth` ABC; verify JWT decoding hooks still match |

The wiring then happens via the existing `openhands/app_server/config.py` patch
(commit `00130abd0` rewrites the V1 injectors for app_conversation_info; we'll add
similar overrides for settings/secrets/user_auth).

### Bedrock-listing port (OpenHands `app_server/utils/llm.py`)

The fork's env-hint detection from `openhands/utils/llm.py` re-targets to the renamed file. But the V1 file at v1.7.0 **doesn't call `_list_bedrock_foundation_models` at all** — Bedrock listing is now SDK-side via `get_supported_llm_models`, called from somewhere else. We need to either:
- Re-add the Bedrock listing trigger in `app_server/utils/llm.py` (if it ever called the SDK helper directly), OR
- Patch the SDK's `get_supported_llm_models` (more invasive but solves the problem at source).

Recommendation: patch the SDK side (covers both call sites — listing, and `_list_bedrock_foundation_models` default-cred-chain) and treat the OpenHands-side `utils/llm.py` patch as obsolete after that.

---

## Section 3: Risks

| # | Risk | Likelihood | Mitigation |
|---|------|-----------|------------|
| 1 | Cognito V1 user-auth port misses an injection point — auth quietly falls back to default | Med | Add `apply-startup.sh` verification grep that fails the container if the V1 `CognitoUserAuth` injector isn't wired. Run E2E auth flow before declaring deploy ready. |
| 2 | S3SettingsStore / S3SecretsStore lose user-scoped path on V1 port (settings written to a shared key) | High if not tested | Same hard-fail verification in `apply-startup.sh`. Run multi-tenant E2E (test1 + test2 users; assert no cross-user reads). |
| 3 | Bedrock SDK absorption misses a credential mode the fork supported (e.g., custom endpoint URL) | Med | Pre-deploy: read SDK v1.19.1 `LLM` Bedrock config code; cross-check against fork patch's full feature surface. Staging E2E with a non-trivial Bedrock setup (named profile, e.g.). |
| 4 | `live_status_app_conversation_service.py` 17-commit upstream churn breaks fork's resume / sandbox-recreation logic | High | Same as v1.6.0 upgrade — manual cherry-pick + careful re-read. E2E pause/resume + agent-replacement test. |
| 5 | `openhands/storage/data_models/secrets.py` deletion implies upstream tests for fork-patched secret-source filtering may now reside in V1 paths | Low | Trace the fork patch's *actual* logic; if it duplicates upstream behavior, drop entirely. |
| 6 | SDK v1.19.1 changes patch-anchor lines for SDK Patches 23/25/26 | Med | Run `apply-sdk-patches.py` dry-run during agent-server build; fail fast on missing pattern. |
| 7 | Existing staging data: V0 settings/secrets paths in S3 won't be read by new V1 stores | Med | Either (a) port path layout 1:1 in V1 store (preferred — `users/{user_id}/settings/...`), or (b) one-shot data migration. (a) is simpler if the V1 `SettingsStore` ABC is flexible enough. |

---

## Section 4: Effort estimate

| Phase | Effort | Notes |
|------|--------|-------|
| Fork branch (cherry-pick + V1 ports) | 1.5–2 days | 20 cherry-picks, 3 new V1 files (Cognito S3 stores + auth), conflict resolution in `live_status_app_conversation_service.py` |
| **SDK fork branch** for Bedrock features | 0.5–1 day | New step. SDK branch off v1.19.1 with: default-cred-chain in `_list_bedrock_foundation_models`, cross-region inference profile listing, cross-region prefix stripping in `model_info.py`, `AWS_DEFAULT_REGION` setdefault, env-hint trigger in `get_supported_llm_models`. |
| Infra: `download-fork-patches.sh` rewrite (drop V0-deleted files, add V1 ports), Dockerfile, compute-stack.ts, agent-server-custom SDK pin to v1.19.1 + new patches | 0.5 day | Mechanical, well-trodden |
| `apply-startup.sh` rewrite (Patch 21 verification gates new V1 paths; drop V0 verifications) | 0.5 day | Critical — wrong patterns silently disable security |
| `apply-sdk-patches.py` re-verify against v1.19.1 + add 4 new Bedrock patches | 1 day | Drop Patch 27 (absorbed); re-anchor 23/25/26; add 4 Bedrock patches |
| Local build + unit tests | 0.5 day | Expect failures from typed-tests on removed modules |
| Staging deploy + E2E (`select-e2e-tests.sh --all`) | 1 day | Major upgrade — full E2E |
| Buffer for V1-port surprises | 1 day | High likelihood of edge cases in store ports |
| **Total** | **~6.5–7 working days** | Up from initial 5-day estimate. Reason: I incorrectly assumed Bedrock patches were absorbed; verifying SDK source showed they aren't. |

---

## Section 5: Recommendation

**Proceed with the upgrade**, on the following terms (corrected after verifying SDK source):

1. **Drop 1 patch confirmed absorbed**: SDK Patch 27 (Bedrock max_output_tokens cap — covered by SDK PR #2264).
2. **Drop 1 obsolete-V0 patch**: `openhands/server/config/server_config.py` — V0 store-class fields removed.
3. **Port 4 OpenHands patches to V1 paths**: Cognito S3 stores + auth + utils/llm.py env-hint detection → `openhands/app_server/{settings,secrets,user_auth,utils}/`.
4. **Add 4 NEW SDK patches** in `apply-sdk-patches.py` for Bedrock features the fork carried that are NOT in upstream SDK v1.19.1:
   - Default credential chain in `_list_bedrock_foundation_models`
   - Cross-region inference profile enumeration
   - Cross-region prefix stripping in `get_litellm_model_info`
   - `AWS_DEFAULT_REGION` setdefault
   - Env-hint trigger for Bedrock listing in `get_supported_llm_models`
5. **Treat Patch 21 (multi-tenant verification) as security-critical** — grep patterns must be rewritten for V1 paths or it silently allows shared storage.
6. **Run full E2E** (`./test/select-e2e-tests.sh --all`) on staging; **must** include a Bedrock-with-IAM-role smoke test (the patch we're forced to keep upstream of the SDK).

Alternative (skip 1.7.0): not recommended — v1.8.x will inherit the V0→V1 cleanup already shipped here, so the same port work is unavoidable. Doing it on 1.7.0 keeps patch deltas smaller per release and keeps pace with upstream CVE / dependency fixes.

### Optional follow-up: contribute the Bedrock features upstream

While porting them as SDK patches, consider opening upstream PRs against `OpenHands/software-agent-sdk` for the four Bedrock features. They're general-purpose (not zxkane-specific) and the SDK already accepted PR #2598 for similar AWS auth work — there's a good chance maintainers would merge them. Upstreaming would let us drop these patches in v1.8.x.

---

## Appendix A: Verification plan (runs before merging the upgrade PR)

1. **Build the agent-server custom image** with new SDK v1.19.1 — confirm `apply-sdk-patches.py` reports all 3 (or 4 if Patch 27 retained) patches applied without "WARNING: pattern not found".
2. **Build the openhands custom image** — confirm `download-fork-patches.sh` 200s on every file in the new (smaller) FILES list and that `apply-startup.sh` reports every "Patch X: ... applied correctly" with no `CRITICAL PATCH FAILURE`.
3. **Unit tests**: `npm run test`. Expect ~7-8 ARM64 Docker bundling failures (memory: `feedback_deploy_qemu` — install binfmt to skip these).
4. **Staging deploy**: `./deploy-staging.local.sh`. Confirm sandbox starts, conversation creates.
5. **E2E suite**: `./test/select-e2e-tests.sh --all` — minimum gate before merge.
6. **Multi-tenant smoke test**: create two test users, verify settings/secrets are user-scoped at `users/{user_id}/...` in S3, verify one user cannot list another user's conversations.
7. **Bedrock smoke test**: with a Bedrock-only LLM profile (no API key, IAM-based auth), verify a one-shot conversation completes — covers credential-chain fallback.

---

## Appendix B: Files staying in `download-fork-patches.sh` (proposed, corrected)

```
# Down from 14 to ~12 files (minor reduction; Bedrock features move to SDK patches instead)
openhands/app_server/sandbox/remote_sandbox_service.py
openhands/app_server/app_conversation/app_conversation_service.py
openhands/app_server/app_conversation/live_status_app_conversation_service.py
openhands/app_server/app_conversation/app_conversation_router.py
openhands/app_server/event_callback/webhook_router.py
openhands/app_server/services/db_session_injector.py
openhands/app_server/config.py
openhands/app_server/event_callback/sql_event_callback_service.py
# new V1-port files added by the fork branch:
openhands/app_server/user_auth/cognito_user_auth.py
openhands/app_server/settings/cognito_s3_settings_store.py
openhands/app_server/secrets/cognito_s3_secrets_store.py
# possibly: openhands/app_server/utils/llm.py — only if env-hint detection is still required after SDK patches absorb the same logic
```

Removed (V0-deleted, no logic to port to OpenHands repo): `openhands/server/config/server_config.py`, `openhands/storage/data_models/secrets.py`, `openhands/llm/bedrock.py`, `openhands/llm/llm.py`, `openhands/core/config/llm_config.py`.

`openhands/utils/llm.py` → re-target to `openhands/app_server/utils/llm.py` only if SDK-side patches don't fully cover it.

The 3 new V1 files (Cognito S3 stores + auth) are *fork-only* (don't exist upstream) — they're added by the fork branch, then materialized into the build via `download-fork-patches.sh`.

## Appendix C: New SDK patches to add to `apply-sdk-patches.py`

```
Patch 28 (NEW): Default credential chain for _list_bedrock_foundation_models
  Target: openhands-sdk/openhands/sdk/llm/utils/unverified_models.py:21-50
  Make all three creds optional; omit from boto3.client kwargs when falsy

Patch 29 (NEW): Cross-region inference profile listing
  Target: same file
  Add paginator('list_inference_profiles', typeEquals='SYSTEM_DEFINED') after
  list_foundation_models; merge results

Patch 30 (NEW): Cross-region prefix stripping for get_litellm_model_info
  Target: openhands-sdk/openhands/sdk/llm/utils/model_info.py:79-90
  Add fallback: re.sub(r'^bedrock/(us|eu|apac|global)\.', 'bedrock/', model)

Patch 31 (NEW): AWS_DEFAULT_REGION setdefault in _set_env_side_effects
  Target: openhands-sdk/openhands/sdk/llm/llm.py:533-534
  After AWS_REGION_NAME assignment, add os.environ.setdefault('AWS_DEFAULT_REGION', ...)

Patch 32 (NEW, optional): Env-hint trigger for Bedrock listing
  Target: openhands-sdk/openhands/sdk/llm/utils/unverified_models.py:69-75
  Trigger _list_bedrock_foundation_models when AWS_PROFILE/AWS_ROLE_ARN/
  AWS_WEB_IDENTITY_TOKEN_FILE set, even without explicit creds (works with
  Patch 28). Skip if Patch 28 alone proves sufficient in staging E2E.
```
