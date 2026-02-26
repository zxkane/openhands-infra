# OpenResty runtime proxy
# Routes /runtime/{conversation_id}/{port}/... to sandbox Fargate task IP:port
# Discovers sandbox IPs via the Sandbox Orchestrator API (Cloud Map DNS)
FROM openresty/openresty:1.27.1.2-alpine-fat

# Upgrade Alpine packages to fix CVEs:
#   openssl  3.5.4 → 3.5.5 (CVE-2025-15467, CVE-2025-69420, CVE-2025-69421, etc.)
#   libpng   1.6.54 → 1.6.55 (CVE-2026-25646)
#   busybox  1.37.0-r19 → 1.37.0-r20 (CVE-2025-46394, CVE-2024-58251)
RUN apk update && apk upgrade --no-cache && rm -rf /var/cache/apk/*

# Install lua-resty-http for Orchestrator API communication
# alpine-fat image includes opm (OpenResty Package Manager)
RUN opm get ledgetech/lua-resty-http

# Copy nginx config and Lua discovery script
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY sandbox_discovery.lua /usr/local/openresty/lualib/sandbox_discovery.lua

# Create log directory
RUN mkdir -p /var/log/openresty

EXPOSE 8080

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
