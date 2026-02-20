# OpenResty runtime proxy
# Routes /runtime/{conversation_id}/{port}/... to sandbox Fargate task IP:port
# Discovers sandbox IPs via the Sandbox Orchestrator API (Cloud Map DNS)
FROM openresty/openresty:1.25.3.1-alpine-fat

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
