-- Docker container discovery for OpenResty runtime proxy
-- Finds sandbox containers by conversation_id label and returns container IP + port
-- Since OpenResty runs in a container on the same bridge network as sandboxes,
-- it can route directly to container ports without going through host port mappings.
--
-- PORT ROUTING LOGIC:
-- The URL contains a port number that maps to services inside the container:
-- - System ports (8000=agent-server, 8001=vscode): Docker exposes these on random host ports
-- - User app ports (from WORKER_1/WORKER_2 env): Apps listen on the SAME port as the host port
--
-- We try to route to the requested port directly. If that fails, the app is either:
-- 1. A user app listening on the host port (e.g., Flask on 38013)
-- 2. A system service on a well-known internal port (translate via Docker mapping)

local http = require "resty.http"
local cjson = require "cjson"
local _M = {}

-- Well-known fixed ports inside sandbox containers.
-- These are the INTERNAL container ports for OpenHands services that do NOT
-- necessarily listen on the externally exposed (PublicPort) value.
--
-- For user apps, OpenHands commonly sets the app to listen on the same port
-- number that is exposed to the host/browser (PublicPort). In that case,
-- proxying directly to container_ip:requested_port is correct even if Docker
-- also exposes internal "worker" ports (8011/8012) that are not actually
-- serving HTTP.
local FIXED_INTERNAL_PORTS = {
  ["8000"] = true,  -- agent-server
  ["8001"] = true,  -- vscode
}

local function can_connect(ip, port)
  if not ip or not port then
    return false
  end
  local p = tonumber(port)
  if not p then
    return false
  end

  local sock = ngx.socket.tcp()
  sock:settimeout(100) -- fast probe; keeps request overhead low
  local ok = sock:connect(ip, p)
  if ok then
    sock:close()
    return true
  end
  sock:close()
  return false
end

-- Find container by conversation_id and return its IP, port, and user_id
-- @param cid: conversation_id to search for
-- @param tp: target port from URL
-- @return ip, port, user_id: container IP, port, and owner user_id (or nil if not found)
function _M.find_container(cid, tp)
  local h = http.new()

  -- Connect to Docker socket
  local ok, err = h:connect("unix:/var/run/docker.sock")
  if not ok then
    ngx.log(ngx.ERR, "Failed to connect to Docker socket: ", err)
    return nil, nil
  end

  -- List all containers
  local res, err = h:request({
    path = "/containers/json",
    headers = {["Host"] = "localhost"}
  })
  if not res then
    ngx.log(ngx.ERR, "Failed to list containers: ", err)
    return nil, nil
  end

  local body = res:read_body()
  local ok2, containers = pcall(cjson.decode, body)
  if not ok2 then
    ngx.log(ngx.ERR, "Failed to decode container list: ", containers)
    return nil, nil
  end

  -- Find container with matching conversation_id label
  for _, c in ipairs(containers) do
    local labels = c.Labels or {}
    if labels["conversation_id"] == cid then
      -- Get container IP from NetworkSettings.Networks
      -- Iterate over all networks to find a valid IP (fixes bridge network bug)
      local ip = nil
      local networks = c.NetworkSettings and c.NetworkSettings.Networks
      if networks then
        for net_name, net_info in pairs(networks) do
          if net_info.IPAddress and net_info.IPAddress ~= "" then
            ip = net_info.IPAddress
            ngx.log(ngx.DEBUG, "Found container IP ", ip, " on network ", net_name)
            break
          end
        end
      end

      if not ip or ip == "" then
        ngx.log(ngx.WARN, "Container found but no IP address for conversation: ", cid)
        return nil, nil
      end

      -- Determine the target port to connect to on the container IP.
      --
      -- Rule 1: If the container is already listening on the requested port, use it.
      --         (Common for user apps that bind to the externally exposed port.)
      -- Rule 2: Otherwise, if Docker exposes a mapping from the requested PublicPort to
      --         some PrivatePort, translate to that PrivatePort.
      -- Rule 3: Otherwise, fall back to the requested port.
      local target_port = tp

      if can_connect(ip, tp) then
        ngx.log(ngx.INFO, "Direct port reachable on container: ", tp)
        target_port = tp
      else
        local ports = c.Ports or {}
        local mapped_port = nil

        for _, p in ipairs(ports) do
          if p.PublicPort and tostring(p.PublicPort) == tp and p.PrivatePort then
            mapped_port = tostring(p.PrivatePort)
            break
          end
        end

        if mapped_port then
          if FIXED_INTERNAL_PORTS[mapped_port] then
            ngx.log(ngx.INFO, "Fixed port translation: host ", tp, " -> container ", mapped_port)
          else
            ngx.log(ngx.INFO, "Port translation: host ", tp, " -> container ", mapped_port)
          end
          target_port = mapped_port
        else
          ngx.log(ngx.INFO, "No mapping found; using requested port: ", tp)
          target_port = tp
        end
      end

      -- Get user_id label for ownership verification
      local user_id = labels["user_id"] or nil
      ngx.log(ngx.INFO, "Found container for ", cid, ": IP=", ip, ", port=", target_port, ", user_id=", user_id or "nil", " (requested=", tp, ")")
      return ip, target_port, user_id
    end
  end

  ngx.log(ngx.DEBUG, "No container found with conversation_id: ", cid)
  return nil, nil, nil
end

return _M
