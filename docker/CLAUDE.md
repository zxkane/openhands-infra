# docker/CLAUDE.md - Runtime Routing & Container Patches

This document covers the Docker container configuration, OpenResty proxy, and frontend patches.

## Directory Structure

| File | Purpose |
|------|---------|
| `Dockerfile` | OpenHands container with runtime patches |
| `apply-patch.sh` | Startup script applying runtime patches |
| `patch-fix.js` | Frontend JavaScript patches |
| `cognito_user_auth.py` | CognitoUserAuth class for OpenHands |
| `cognito_file_conversation_store.py` | User-scoped conversation storage |
| `openresty/Dockerfile` | OpenResty proxy container |
| `openresty/nginx.conf` | Nginx configuration with Lua |
| `openresty/docker_discovery.lua` | Container discovery via Docker API |
| `agent-server-custom/Dockerfile` | Custom agent-server with boto3 |
| `agent-server-custom/apply-sdk-patches.py` | Build-time SDK patches |

## Patch System Overview

There are two types of patches in this project:

| Type | Location | Applied When | Why |
|------|----------|--------------|-----|
| **Runtime patches** | `apply-patch.sh`, `patch-fix.js` | Container startup | Modify upstream OpenHands container |
| **Build-time patches** | `agent-server-custom/apply-sdk-patches.py` | Docker build | Modify SDK before PyInstaller bundles it |

### Why Two Different Approaches?

**Runtime patches** (apply-patch.sh):
- We use the upstream OpenHands container image
- Source files are available in the running container
- Patches applied before application starts
- Allows customization without forking OpenHands

**Build-time patches** (apply-sdk-patches.py):
- We build agent-server from source with boto3 included
- SDK code is cloned from GitHub during build
- PyInstaller creates an **immutable binary**
- Source code modifications MUST happen before `pyinstaller` runs

```
# Runtime patches flow:
Upstream OpenHands Image → Start Container → apply-patch.sh → Application Runs

# Build-time patches flow:
Clone SDK → apply-sdk-patches.py → PyInstaller → Binary (immutable)
```

### Patch Numbering

| Patch # | Type | Purpose |
|---------|------|---------|
| 1-22 | Runtime | OpenHands container patches (apply-patch.sh) |
| 23-26 | Build-time | SDK patches for conversation resume (apply-sdk-patches.py) |

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

## Apply Patch Script (`apply-patch.sh`)

Critical patches applied at container startup:

| Patch | Purpose | Critical? |
|-------|---------|-----------|
| Patch 1 | Inject patch-fix.js into index.html | No |
| Patch 7 | Set `network_mode='host'` for runtime | No |
| Patch 16 | Add `user_id` label to containers | **Yes** |

### Critical Patch Failure Handling

```bash
# If critical patches fail, container startup is blocked
if [ -n "$CRITICAL_PATCH_FAILURES" ]; then
  echo "CRITICAL SECURITY PATCHES FAILED" >&2
  exit 1
fi
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
# Check patches applied
docker logs openhands-app 2>&1 | grep -i patch

# Check container discovery
docker logs openresty-proxy 2>&1 | grep "find_container"

# List containers with labels
docker ps --format '{{.Names}} {{.Labels}}' | grep conversation_id

# Test Docker socket access from OpenResty
docker exec openresty-proxy curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```
