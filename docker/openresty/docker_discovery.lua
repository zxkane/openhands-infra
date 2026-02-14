-- Sandbox discovery for OpenResty runtime proxy
-- Finds sandbox containers by conversation_id via the Sandbox Orchestrator API
-- which looks up the sandbox in DynamoDB and returns the Fargate task IP + user_id.
--
-- The Orchestrator URL is configured via the ORCHESTRATOR_URL environment variable.

local http = require "resty.http"
local cjson = require "cjson"
local _M = {}

-- Configuration
local ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL") or "http://localhost:8081"

-- Error types returned by find_container for proper HTTP status mapping
_M.ERR_SOCKET = "socket_error"      -- Orchestrator connection failed (503)
_M.ERR_LIST = "list_error"          -- Failed to query orchestrator (503)
_M.ERR_PARSE = "parse_error"        -- Failed to parse response (503)
_M.ERR_NO_IP = "no_ip_error"        -- Sandbox found but no IP address (502)
_M.ERR_NOT_FOUND = "not_found"      -- No sandbox with matching conversation_id (404)

-- Find sandbox by conversation_id via the Sandbox Orchestrator API
-- @param cid: conversation_id to search for
-- @param tp: target port from URL
-- @return ip, port, user_id, error_type
--         On success: ip, port, user_id, nil
--         On failure: nil, nil, nil, error_type (one of ERR_* constants)
function _M.find_container(cid, tp)
  local h = http.new()
  h:set_timeout(5000) -- 5s timeout for orchestrator calls

  local url = ORCHESTRATOR_URL .. "/sessions/" .. cid
  local res, err = h:request_uri(url, {
    method = "GET",
    headers = {

      ["Content-Type"] = "application/json",
    },
  })

  if not res then
    ngx.log(ngx.ERR, "Failed to connect to orchestrator: ", err)
    return nil, nil, nil, _M.ERR_SOCKET
  end

  if res.status == 404 then
    ngx.log(ngx.DEBUG, "Orchestrator: no sandbox found for ", cid)
    return nil, nil, nil, _M.ERR_NOT_FOUND
  end

  if res.status ~= 200 then
    ngx.log(ngx.ERR, "Orchestrator returned status ", res.status, " for ", cid)
    return nil, nil, nil, _M.ERR_LIST
  end

  local ok, data = pcall(cjson.decode, res.body)
  if not ok then
    ngx.log(ngx.ERR, "Failed to decode orchestrator response: ", data)
    return nil, nil, nil, _M.ERR_PARSE
  end

  local status = data.status or ""
  if status ~= "RUNNING" then
    ngx.log(ngx.INFO, "Sandbox not running for ", cid, ": status=", status)
    return nil, nil, nil, _M.ERR_NOT_FOUND
  end

  -- Extract IP from the url field (format: http://{ip}:{port})
  local task_url = data.url or ""
  local ip = task_url:match("http://([%d%.]+)")
  if not ip or ip == "" then
    ngx.log(ngx.WARN, "Orchestrator returned no IP for ", cid)
    return nil, nil, nil, _M.ERR_NO_IP
  end

  local user_id = data.user_id

  ngx.log(ngx.INFO, "Found sandbox via orchestrator for ", cid, ": IP=", ip, ", port=", tp, ", user_id=", user_id or "nil")

  -- Fire-and-forget activity update (non-blocking)
  local activity_h = http.new()
  activity_h:set_timeout(1000)
  activity_h:request_uri(ORCHESTRATOR_URL .. "/activity", {
    method = "POST",
    headers = {

      ["Content-Type"] = "application/json",
    },
    body = cjson.encode({ session_id = cid }),
  })

  return ip, tp, user_id, nil
end

return _M
