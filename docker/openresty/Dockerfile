# OpenResty runtime proxy
# Routes /runtime/{conversation_id}/{port}/... to sandbox Fargate task IP:port
# Discovers sandbox IPs via the Sandbox Orchestrator API (Cloud Map DNS)
# LAST_UPDATED forces CDK to rebuild when bumped (picks up base image security patches)
ARG OPENRESTY_VERSION=1.29.2.5
ARG OPENRESTY_IMAGE_DIGEST=sha256:6359d16c2cefedc216861e7092d486bb1ff19548abd1aa71e6dc094c82477aee
ARG LAST_UPDATED=2026-09-01
FROM openresty/openresty:${OPENRESTY_VERSION}-alpine-fat@${OPENRESTY_IMAGE_DIGEST}

# Upgrade Alpine packages to pick up latest security patches
ARG LAST_UPDATED
RUN echo "Refreshing Alpine packages as of ${LAST_UPDATED}" && \
    apk update && \
    apk upgrade --no-cache && \
    rm -rf /var/cache/apk/*

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
