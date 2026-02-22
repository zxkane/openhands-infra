"""Patch 32: Fix exposed_urls for Fargate sandbox mode.

The upstream _build_service_url() prepends service name to the hostname
(e.g., http://vscode-172.31.x.x:8000) for Kubernetes DNS resolution.
In Fargate, this doesn't resolve. Fix: use the actual sandbox IP with
the correct port for each service.

The VSCODE exposed URL should use the agent-server's /api/vscode/url
endpoint to get the real VS Code URL, since VS Code runs on a different
port (60001) than the agent-server (8000).
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

# Replace _build_service_url to use IP:port instead of service-name-IP:port
OLD = '''def _build_service_url(url: str, service_name: str):
    scheme, host_and_path = url.split('://')
    return scheme + '://' + service_name + '-' + host_and_path'''

# Map service names to their actual ports inside the Fargate container
NEW = '''def _build_service_url(url: str, service_name: str):
    # Patch 32: Use localhost:port for Fargate sandbox URLs
    # The frontend (patch-fix.js) rewrites localhost:{port} to
    # https://{port}-{convId}.runtime.{subdomain}.{domain}/
    # Using localhost instead of VPC IP ensures the URL goes through
    # the frontend rewriter → CloudFront → ALB → OpenResty → sandbox
    _port_map = {'vscode': 60001, 'work-1': 12000, 'work-2': 12001}
    port = _port_map.get(service_name)
    if port:
        return f'http://localhost:{port}'
    # Fallback to original behavior
    scheme, host_and_path = url.split('://')
    return scheme + '://' + service_name + '-' + host_and_path'''

if OLD in content:
    content = content.replace(OLD, NEW)
    # Also fix VS Code folder path to /workspace (not /workspace/project)
    # for consistency with Changes panel which shows /workspace/ level git changes
    content = content.replace(
        "folder=%2Fworkspace%2Fproject",
        "folder=%2Fworkspace"
    )
    with open(SERVICE_FILE, "w") as f:
        f.write(content)
    print("Patch 32: Fixed _build_service_url + VS Code folder path for Fargate")
else:
    print("WARNING: Patch 32 pattern not found in remote_sandbox_service.py")
