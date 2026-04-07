"""Patch 32: Fix exposed_urls for Fargate sandbox mode.

In upstream 1.6.0, _build_service_url() handles path-based and subdomain-based
routing for Kubernetes. In Fargate, the subdomain mode doesn't resolve because
the service-name DNS prefix is for Kubernetes.

Fix: use localhost:{port} so the frontend (patch-fix.js) rewrites the URLs to
the correct runtime subdomain format: https://{port}-{convId}.runtime.{domain}/

Port mapping (from upstream remote_sandbox_service.py constants):
  - vscode:  60001 (VSCODE_PORT)
  - work-1:  12000 (WORKER_1_PORT)
  - work-2:  12001 (WORKER_2_PORT)
"""
import sys

SERVICE_FILE = "/app/openhands/app_server/sandbox/remote_sandbox_service.py"

try:
    with open(SERVICE_FILE, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("Patch 32: remote_sandbox_service.py not found, skipping")
    sys.exit(0)

if "Patch 32" in content:
    print("Patch 32: Already applied")
    sys.exit(0)

# Match the 1.6.0 function signature with runtime_id parameter
OLD = '''def _build_service_url(url: str, service_name: str, runtime_id: str) -> str:
    """Build a service URL for the given service name.

    Handles both path-based and subdomain-based routing:
    - Path mode (url path starts with /{runtime_id}): returns {scheme}://{netloc}/{runtime_id}/{service_name}
    - Subdomain mode: returns {scheme}://{service_name}-{netloc}{path}
    """
    parsed = urlparse(url)
    scheme, netloc, path = parsed.scheme, parsed.netloc, parsed.path or '/'
    # Path mode if runtime_url path starts with /{id}
    path_mode = path.startswith(f'/{runtime_id}')
    if path_mode:
        return f'{scheme}://{netloc}/{runtime_id}/{service_name}'
    else:
        return f'{scheme}://{service_name}-{netloc}{path}\''''

NEW = '''def _build_service_url(url: str, service_name: str, runtime_id: str) -> str:
    # Patch 32: Use localhost:port for Fargate sandbox URLs
    # The frontend (patch-fix.js) rewrites localhost:{port} to
    # https://{port}-{convId}.runtime.{subdomain}.{domain}/
    _port_map = {'vscode': 60001, 'work-1': 12000, 'work-2': 12001}
    port = _port_map.get(service_name)
    if port:
        return f'http://localhost:{port}'
    # Fallback to original behavior for unknown services
    parsed = urlparse(url)
    scheme, netloc, path = parsed.scheme, parsed.netloc, parsed.path or '/'
    path_mode = path.startswith(f'/{runtime_id}')
    if path_mode:
        return f'{scheme}://{netloc}/{runtime_id}/{service_name}'
    else:
        return f'{scheme}://{service_name}-{netloc}{path}\''''

if OLD in content:
    content = content.replace(OLD, NEW)
    with open(SERVICE_FILE, "w") as f:
        f.write(content)
    print("Patch 32: Fixed _build_service_url for Fargate (v1.6.0 signature)")
else:
    print("WARNING: Patch 32 pattern not found in remote_sandbox_service.py")
