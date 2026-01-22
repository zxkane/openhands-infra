# OpenResty Docker image for runtime proxy
# Routes /runtime/{conversation_id}/{port}/... to sandbox container IP:port
# Works by joining Docker bridge network - can reach any port without mappings
FROM openresty/openresty:1.25.3.1-alpine-fat

# Install lua-resty-http for Docker API communication
# alpine-fat image includes opm (OpenResty Package Manager)
RUN opm get ledgetech/lua-resty-http

# Copy nginx config and Lua script
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY docker_discovery.lua /usr/local/openresty/lualib/docker_discovery.lua

# Create log directory
RUN mkdir -p /var/log/openresty

EXPOSE 8080

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
