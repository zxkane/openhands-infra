# docker/CLAUDE.md - Runtime Routing & Container Patches

This document covers the Docker container configuration, OpenResty proxy, and patch system.

## Directory Structure

| File | Purpose |
|------|---------|
| `Dockerfile` | OpenHands container with fork-based patches |
| `download-fork-patches.sh` | Build-time: downloads patched files from fork |
| `apply-startup.sh` | Runtime: JS injection, site-packages patch, DB migration |
| `patch-fix.js` | Frontend JavaScript patches |
| `cognito_user_auth.py` | CognitoUserAuth class for OpenHands |
| `cognito_file_conversation_store.py` | User-scoped conversation storage |
| `cognito_sql_conversation_info_service.py` | Multi-tenant conversation isolation |
| `s3_settings_store.py` | User-scoped settings store |
| `s3_secrets_store.py` | User-scoped secrets store |
| `user_config_loader.py` | User MCP configuration loader |
| `patched/auth_user_context.py` | Patched webhook auth for Docker internal network |
| `openresty/Dockerfile` | OpenResty proxy container |
| `openresty/nginx.conf` | Nginx configuration with Lua |
| `openresty/docker_discovery.lua` | Container discovery via Docker API |
| `agent-server-custom/Dockerfile` | Custom agent-server with boto3 |
| `agent-server-custom/apply-sdk-patches.py` | Build-time SDK patches |

## Patch System Overview

There are three types of patches in this project:

| Type | Location | Applied When | Why |
|------|----------|--------------|-----|
| **Fork patches** | `zxkane/openhands` fork | Docker build (download) | Upstream Python file modifications |
| **Runtime patches** | `apply-startup.sh`, `patch-fix.js` | Container startup | Dynamic operations (JS injection, site-packages, DB migration) |
| **SDK patches** | `agent-server-custom/apply-sdk-patches.py` | Docker build | Modify SDK before PyInstaller bundles it |

### Architecture

```
Before (old):
  Upstream Image → Container Start → apply-patch.sh (29 regex patches) → App runs

After (current):
  Upstream Image → Docker Build (download patched files from fork) → Container Start → apply-startup.sh (minimal) → App runs
```

### Fork-Based Patches (`zxkane/openhands`)

Upstream file modifications live as clean per-feature git commits in the fork:

- **Branch**: `custom/v1.3.0` (branched from tag `v1.3.0`)
- **Tag**: `custom-v1.3.0-r1` (referenced by `download-fork-patches.sh`)
- **Files**: 9 upstream Python files with ~13 feature commits

| # | Feature | Upstream Files |
|---|---------|----------------|
| 1 | Container labels for sandbox_spec_id | `docker_sandbox_service.py` |
| 2 | Per-sandbox workspace mount isolation | `docker_sandbox_service.py` |
| 3 | Retry logic for agent-server race condition | `live_status_app_conversation_service.py` |
| 4 | Pass user_id to start_sandbox for labeling | `docker_sandbox_service.py`, `live_status_app_conversation_service.py` |
| 5 | Sandbox recreation and /resume endpoint | `live_status_app_conversation_service.py`, `app_conversation_router.py` |
| 6 | SSL support for PostgreSQL (env-gated) | `db_session_injector.py` |
| 7 | conversation_id label and webhook headers | `docker_sandbox_service.py` |
| 8 | Generate conv_id before sandbox, user_id in bg task | `live_status_app_conversation_service.py` |
| 9 | Handle None user_id and preserve on update | `webhook_router.py` |
| 10 | Cognito auth and user-scoped stores | `server_config.py` |
| 11 | Skip invalid secrets during resume | `secrets.py` |
| 12 | Conversation isolation and UUID fix | `config.py`, `sql_event_callback_service.py` |
| 13 | Secrets injection and runtime env vars | `live_status_app_conversation_service.py`, `docker_sandbox_service.py` |

### Runtime Patches (`apply-startup.sh`)

Operations that must happen at container startup (not build time):

| Patch | Purpose | Critical? |
|-------|---------|-----------|
| 1 | Inject `patch-fix.js` into `index.html` | No |
| 5 | Copy `auth_user_context.py` to site-packages | No |
| 6 | Swap AuthUserContextInjector import in openhands_cloud | No |
| 27a | Database migration DDL (add user_id column) | No |
| 21 | Verify multi-tenant S3 store configuration | **Yes** |

### SDK Patches (`apply-sdk-patches.py`)

Targets `software-agent-sdk` (not OpenHands). Applied at build time in `agent-server-custom/`.

### Upgrade Workflow

When upstream releases a new version (e.g., v1.4.0):

1. In fork: `git checkout -b custom/v1.4.0 v1.4.0`
2. `git cherry-pick` each commit from `custom/v1.3.0` — conflicts isolated per feature
3. Resolve, test, tag as `custom-v1.4.0-r1`
4. In openhands-infra: update `OPENHANDS_VERSION=1.4.0` and `FORK_REF=custom-v1.4.0-r1`
5. Remove any patches accepted upstream

### Critical Patch Failure Handling

```bash
# If critical patches fail, container startup is blocked
if [ -n "$CRITICAL_PATCH_FAILURES" ]; then
  echo "CRITICAL SECURITY PATCHES FAILED" >&2
  exit 1
fi
```

## Runtime Subdomain Routing

User applications in sandbox containers are accessible via runtime subdomains:

```
https://{port}-{convId}.runtime.{subdomain}.{domain}/
```

**Example**: `https://5000-abc123.runtime.openhands.example.com/`

### Request Flow

```
Browser → CloudFront → Lambda@Edge (JWT verify) → ALB → OpenResty (verify ownership) → Container
```

### Dual Routing Approach

| Route Type | Pattern | Use Case |
|------------|---------|----------|
| Path-based | `/runtime/{convId}/{port}/...` | Agent WebSocket, API calls |
| Subdomain | `{port}-{convId}.runtime.{domain}/` | User apps (Flask, Express) |

**Why Subdomain for User Apps?**
- Apps run at domain root (`/`) instead of path prefix
- Internal routes like `/add`, `/api/users` resolve correctly
- Each runtime has isolated cookies

**Why Path-based for Agent Communication?**
- WebSocket uses same-origin cookie authentication
- API calls need session cookies from main domain

## OpenResty Proxy (`openresty/nginx.conf`)

### Container Discovery

The Lua script queries Docker API to find containers:

```lua
-- docker_discovery.lua
function _M.find_container(cid, tp)
  -- 1. Connect to Docker socket: /var/run/docker.sock
  -- 2. GET /containers/json?filters={"label":["conversation_id={cid}"]}
  -- 3. Find container with matching conversation_id label
  -- 4. Get IP from NetworkSettings.Networks
  -- 5. Return: ip, port, user_id, error_type
end
```

### Error Types

| Error Type | HTTP Status | Meaning |
|------------|-------------|---------|
| `ERR_SOCKET` | 503 | Docker socket unavailable |
| `ERR_LIST` | 503 | Failed to list containers |
| `ERR_PARSE` | 503 | Failed to parse Docker response |
| `ERR_NO_IP` | 502 | Container found but no IP |
| `ERR_NOT_FOUND` | 404 | No container with conversation_id |

### Security: Ownership Verification

```lua
-- nginx.conf access_by_lua_block
local request_user_id = headers["x-cognito-user-id"]
local container_user_id = labels["user_id"]

if request_user_id ~= container_user_id then
  ngx.exit(403)  -- Access denied
end
```

## Frontend Patches (`patch-fix.js`)

### URL Rewriting

Rewrites `localhost:port` URLs to accessible runtime URLs:

```javascript
// Input:  http://localhost:5000/api/data
// Output: https://5000-{convId}.runtime.{subdomain}.{domain}/api/data
```

**Patterns**:
- WebSocket URLs → Path-based (preserves auth cookies)
- API calls → Path-based (same-origin)
- User app URLs → Subdomain routing

### Auto-Close Settings Modal

When LLM is configured via `config.toml`:

```javascript
// 1. Check if /api/options/models returns 200
// 2. If settings don't exist, create default settings via POST /api/settings
// 3. Remove settings modal from DOM
```

### VS Code URL Rewriting

Handles VS Code Server URLs and extensions:

```javascript
// Rewrites /stable/{hash}/... to runtime subdomain
```

## Testing Runtime Routing

```bash
# 1. Start a Flask app in conversation
# Agent creates app on port 5000

# 2. Access via runtime subdomain
curl https://5000-{convId}.runtime.{subdomain}.{domain}/

# 3. Check OpenResty logs
docker logs openresty-proxy 2>&1 | grep "Routing /runtime"
```

## Debugging

```bash
# Check startup patches applied
docker logs openhands-app 2>&1 | grep -i patch

# Check container discovery
docker logs openresty-proxy 2>&1 | grep "find_container"

# List containers with labels
docker ps --format '{{.Names}} {{.Labels}}' | grep conversation_id

# Test Docker socket access from OpenResty
docker exec openresty-proxy curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```
