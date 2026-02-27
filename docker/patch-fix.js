<script>
// OpenHands URL fix - rewrites sandbox URLs to runtime subdomains
// Handles: localhost, host.docker.internal, and VPC private IPs (Fargate sandbox ENIs)
// Also handles main domain with port: {subdomain}.{domain}:{port} (VS Code editor)
// Uses runtime subdomain format: {port}-{convId}.runtime.{subdomain}.{domain}
(function() {
  // Pattern matches localhost, host.docker.internal, or VPC private IPs with port
  // VPC private IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x (Fargate task ENIs)
  var privateHost = '(?:localhost|host\\.docker\\.internal|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)';
  var wsPattern = new RegExp('^wss?:\\/\\/(' + privateHost + '):(\\d+)(.*)');
  var httpPattern = new RegExp('^https?:\\/\\/(' + privateHost + '):(\\d+)(.*)');

  // Pattern matches main domain with port (for VS Code URLs like {subdomain}.{domain}:{port})
  // Captures: (1) host without port, (2) port, (3) path+query (optional)
  var mainDomainPortPattern = /^https?:\/\/([^:\/]+):(\d+)(\/.*)?$/;

  // Extract conversation_id from URL (UUID format, remove hyphens to get hex)
  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    if (match) {
      // Remove hyphens from UUID to get hex format (matches sandbox_id = conversation_id.hex)
      return match[1].replace(/-/g, '');
    }
    return null;
  }

  // Check if URL host matches the main domain (ignoring port and subdomain prefix)
  // e.g., {subdomain}.{domain} matches current host {subdomain}.{domain}
  function isMainDomainUrl(urlHost) {
    var currentHost = window.location.host;
    // Strip any runtime subdomain prefix from both hosts for comparison
    var stripRuntime = function(h) {
      return h.replace(/^\d+-[a-f0-9]+\.runtime\./, '');
    };
    return stripRuntime(urlHost) === stripRuntime(currentHost);
  }

  // Rewrite main domain:port URL to runtime subdomain
  // http://{subdomain}.{domain}:{port}/?tkn=xxx -> https://{port}-{convId}.runtime.{subdomain}.{domain}/?tkn=xxx
  function rewriteMainDomainPortUrl(url) {
    var m = url.match(mainDomainPortPattern);
    if (!m) return url;

    var urlHost = m[1];  // {subdomain}.{domain}
    var port = m[2];     // {port}
    var pathAndQuery = m[3] || '/';  // /?tkn=xxx&folder=...

    // Only rewrite if this is the main domain
    if (!isMainDomainUrl(urlHost)) {
      return url;
    }

    var convId = getConversationId();
    if (!convId) {
      console.warn("No conversation_id found, cannot rewrite main domain URL");
      return url;
    }

    // Build runtime subdomain URL
    var proto = window.location.protocol;
    var hostParts = urlHost.split('.');
    var subDomain = hostParts[0];  // {subdomain}
    var baseDomain = hostParts.slice(1).join('.');  // {domain}
    var runtimeHost = port + '-' + convId + '.runtime.' + subDomain + '.' + baseDomain;

    return proto + '//' + runtimeHost + pathAndQuery;
  }

  // Build runtime subdomain URL for user apps
  // Transforms: {subdomain}.{domain} -> {port}-{convId}.runtime.{subdomain}.{domain}
  // For API paths (/api/..., /sockets/...), use path-based routing to preserve authentication
  function buildRuntimeUrl(port, path, usePathBased) {
    var convId = getConversationId();
    if (!convId) {
      console.warn("No conversation_id found, using path-based runtime URL");
      return window.location.origin + '/runtime/' + port + (path || '/');
    }

    // API calls need authentication via main domain, use path-based routing
    // This includes: /api/*, /sockets/* - these require session cookies
    if (usePathBased || (path && (path.startsWith('/api/') || path.startsWith('/sockets/')))) {
      return window.location.origin + '/runtime/' + convId + '/' + port + (path || '/');
    }

    // User apps use subdomain routing for proper relative path resolution
    var proto = window.location.protocol;
    var host = window.location.host;

    // Parse host to build runtime subdomain
    // e.g., {subdomain}.{domain} -> {port}-{convId}.runtime.{subdomain}.{domain}
    var parts = host.split('.');
    var subDomain = parts[0];  // {subdomain}
    var baseDomain = parts.slice(1).join('.');  // {domain}

    var runtimeHost = port + '-' + convId + '.runtime.' + subDomain + '.' + baseDomain;
    return proto + '//' + runtimeHost + (path || '/');
  }

  var origWS = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    var newUrl = url;
    var m = url.match(wsPattern);
    if (m) {
      var convId = getConversationId();
      var wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
      var path = m[3] || '/';

      // Agent event sockets (/sockets/events/*) need path-based routing to agent-server
      // The conversation URL points to agent-server which handles event sockets
      if (path.startsWith('/sockets/')) {
        if (convId) {
          newUrl = wsProto + "//" + window.location.host + "/runtime/" + convId + "/" + m[2] + path;
        } else {
          newUrl = wsProto + "//" + window.location.host + "/runtime/" + m[2] + path;
        }
        console.log("WS patched (agent sockets):", url, "->", newUrl);
      } else if (convId) {
        // User app WebSockets use subdomain routing
        var host = window.location.host;
        var parts = host.split('.');
        var subDomain = parts[0];
        var baseDomain = parts.slice(1).join('.');
        var runtimeHost = m[2] + '-' + convId + '.runtime.' + subDomain + '.' + baseDomain;
        newUrl = wsProto + "//" + runtimeHost + path;
        console.log("WS patched (subdomain):", url, "->", newUrl);
      } else {
        // Fallback to path-based URL
        newUrl = wsProto + "//" + window.location.host + "/runtime/" + m[2] + path;
        console.log("WS patched (fallback):", url, "->", newUrl);
      }
    }
    return protocols ? new origWS(newUrl, protocols) : new origWS(newUrl);
  };
  window.WebSocket.prototype = origWS.prototype;
  window.WebSocket.CONNECTING = origWS.CONNECTING;
  window.WebSocket.OPEN = origWS.OPEN;
  window.WebSocket.CLOSING = origWS.CLOSING;
  window.WebSocket.CLOSED = origWS.CLOSED;

  function parseJsonSafe(resp) {
    try {
      return resp.json();
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  var origFetch = window.fetch;
  window.fetch = function(url, opts) {
    var newUrl = url;
    if (typeof url === "string") {
      var m = url.match(httpPattern);
      if (m) {
        newUrl = buildRuntimeUrl(m[2], m[3]);

        // Normalize git paths - convert absolute workspace paths to relative
        // The agent-server's git router expects "." for the workspace root
        // Note: URL is now at runtime subdomain root, so git paths are simpler
        if (newUrl.includes('/api/git/')) {
          // Handle URL-encoded paths (%2F = /)
          // Case 1: Exact workspace root - .../api/git/changes/%2Fworkspace%2Fproject -> .../api/git/changes/.
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject$/gi, '$1/.');
          // Case 2: Subdirectory under workspace - .../api/git/changes/%2Fworkspace%2Fproject%2Fsubdir -> .../api/git/changes/subdir
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F/gi, '$1/');

          // Handle non-encoded paths
          // Case 1: Exact workspace root - .../api/git/changes//workspace/project -> .../api/git/changes/.
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project$/g, '$1/.');
          // Case 2: Subdirectory - .../api/git/changes//workspace/project/subdir -> .../api/git/changes/subdir
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\//g, '$1/');
        }

        console.log("Fetch patched:", url, "->", newUrl);
      }
    }
    var method = (opts && opts.method ? String(opts.method).toUpperCase() : "GET");
    var isCreateConversation =
      method === "POST" &&
      typeof newUrl === "string" &&
      newUrl.indexOf("/api/conversations") !== -1;

    var alreadyRetried = false;
    try {
      alreadyRetried = !!(opts && typeof opts === "object" && opts.__ohSettingsRetried);
    } catch (e) {}

    if (!isCreateConversation || alreadyRetried) {
      return origFetch.call(this, newUrl, opts).then(function(resp) {
        // Detect auth redirect: iOS Safari ITP silently blocks SameSite=None cookies,
        // causing API calls to return HTML (Cognito login page) instead of JSON.
        // Only check responses that: (1) are from our domain's /api/ path, (2) returned
        // 200 OK, and (3) weren't redirected to a different origin (resp.url check).
        if (resp.ok && typeof newUrl === "string" && newUrl.indexOf('/api/') !== -1) {
          var respUrl = resp.url || '';
          var sameOrigin = respUrl.indexOf(window.location.origin) === 0 || respUrl === '';
          if (sameOrigin) {
            var ct = resp.headers.get('content-type') || '';
            if (ct.indexOf('text/html') !== -1 && ct.indexOf('application/json') === -1) {
              console.warn('[Auth redirect] API returned HTML instead of JSON, redirecting to login:', newUrl);
              window.location.href = '/_logout';
              return new Response(JSON.stringify({ error: 'auth_redirect', message: 'Session expired' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
              });
            }
          }
        }
        return resp;
      });
    }

    return origFetch.call(this, newUrl, opts).then(function(resp) {
      if (!resp || resp.status !== 400) return resp;

      try {
        return parseJsonSafe(resp.clone()).then(function(body) {
          if (!body || body.msg_id !== "CONFIGURATION$SETTINGS_NOT_FOUND") return resp;
          if (typeof window.__ohEnsureDefaultSettings !== "function") return resp;

          console.warn("Conversation creation failed due to missing settings; creating defaults and retrying once...");

          return window.__ohEnsureDefaultSettings().then(function(ok) {
            if (!ok) return resp;
            var retryOpts = opts;
            try {
              if (opts && typeof opts === "object") {
                retryOpts = Object.assign({}, opts, { __ohSettingsRetried: true });
              }
            } catch (e) {}
            return origFetch.call(window, newUrl, retryOpts);
          });
        }).catch(function() { return resp; });
      } catch (e) {
        return resp;
      }
    });
  };

  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    var newUrl = url;
    if (typeof url === "string") {
      var m = url.match(httpPattern);
      if (m) {
        newUrl = buildRuntimeUrl(m[2], m[3]);

        // Normalize git paths - convert absolute workspace paths to relative
        if (newUrl.includes('/api/git/')) {
          // Handle URL-encoded paths (%2F = /)
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject$/gi, '$1/.');
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/%2F(workspace|openhands)%2Fproject%2F/gi, '$1/');
          // Handle non-encoded paths
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project$/g, '$1/.');
          newUrl = newUrl.replace(/(\/api\/git\/[^/]+)\/\/(workspace|openhands)\/project\//g, '$1/');
        }

        console.log("XHR patched:", url, "->", newUrl);
      }
    }
    return origOpen.call(this, method, newUrl, async, user, pass);
  };

  // Patch window.open to rewrite main domain:port URLs (VS Code editor tabs)
  // Example: http://{subdomain}.{domain}:49955/?tkn=xxx -> https://49955-{convId}.runtime.{subdomain}.{domain}/?tkn=xxx
  var origWindowOpen = window.open;
  window.open = function(url, target, features) {
    var newUrl = url;
    if (typeof url === "string") {
      // First check if it's a main domain with port (VS Code style)
      if (mainDomainPortPattern.test(url)) {
        newUrl = rewriteMainDomainPortUrl(url);
        if (newUrl !== url) {
          console.log("window.open patched (main domain:port):", url, "->", newUrl);
        }
      }
      // Also check for localhost URLs
      else if (httpPattern.test(url)) {
        var m = url.match(httpPattern);
        newUrl = buildRuntimeUrl(m[2], m[3]);
        console.log("window.open patched (localhost):", url, "->", newUrl);
      }
    }
    return origWindowOpen.call(window, newUrl, target, features);
  };

  console.log("OpenHands runtime subdomain URL fix loaded");
})();

// Intercept settings updates to:
// 1. Ensure Bedrock model prefix (model name may not include "bedrock/" prefix)
// 2. Filter out global MCP servers to prevent duplicates (user settings should only contain user-added servers)
// NOTE: OpenHands frontend uses XMLHttpRequest (via Axios), not fetch. We must intercept XHR.
(function() {
  // Global MCP servers from config.toml - these should NOT be saved in user settings
  // When the frontend saves settings, it includes all MCP servers (global + user).
  // We filter these out so only user-added servers are saved, preventing duplicates.
  var globalMcpServers = {
    stdio: [
      { name: 'chrome-devtools' }  // Match by name
    ],
    shttp: [
      { url: 'https://knowledge-mcp.global.api.aws' }  // Match by URL
    ],
    sse: []
  };

  // Known Bedrock model patterns that need the bedrock/ prefix
  var bedrockModelPatterns = [
    /^global\.anthropic\./i,
    /^anthropic\./i,
    /^amazon\./i,
    /^ai21\./i,
    /^cohere\./i,
    /^meta\./i,
    /^mistral\./i,
    /^stability\./i
  ];

  function needsBedrockPrefix(model) {
    if (!model || typeof model !== 'string') return false;
    if (model.startsWith('bedrock/')) return false;  // Already has prefix
    for (var i = 0; i < bedrockModelPatterns.length; i++) {
      if (bedrockModelPatterns[i].test(model)) return true;
    }
    return false;
  }

  function isGlobalStdioServer(server) {
    if (!server || !server.name) return false;
    for (var i = 0; i < globalMcpServers.stdio.length; i++) {
      if (globalMcpServers.stdio[i].name === server.name) return true;
    }
    return false;
  }

  function isGlobalShttpServer(server) {
    if (!server || !server.url) return false;
    for (var i = 0; i < globalMcpServers.shttp.length; i++) {
      if (globalMcpServers.shttp[i].url === server.url) return true;
    }
    return false;
  }

  function isGlobalSseServer(server) {
    if (!server || !server.url) return false;
    for (var i = 0; i < globalMcpServers.sse.length; i++) {
      if (globalMcpServers.sse[i].url === server.url) return true;
    }
    return false;
  }

  function filterGlobalMcpServers(mcpConfig) {
    if (!mcpConfig) return mcpConfig;

    var filtered = {};
    var removedCount = 0;

    // Filter stdio_servers
    if (Array.isArray(mcpConfig.stdio_servers)) {
      filtered.stdio_servers = mcpConfig.stdio_servers.filter(function(s) {
        var isGlobal = isGlobalStdioServer(s);
        if (isGlobal) removedCount++;
        return !isGlobal;
      });
    }

    // Filter shttp_servers
    if (Array.isArray(mcpConfig.shttp_servers)) {
      filtered.shttp_servers = mcpConfig.shttp_servers.filter(function(s) {
        var isGlobal = isGlobalShttpServer(s);
        if (isGlobal) removedCount++;
        return !isGlobal;
      });
    }

    // Filter sse_servers
    if (Array.isArray(mcpConfig.sse_servers)) {
      filtered.sse_servers = mcpConfig.sse_servers.filter(function(s) {
        var isGlobal = isGlobalSseServer(s);
        if (isGlobal) removedCount++;
        return !isGlobal;
      });
    }

    if (removedCount > 0) {
      console.log("Settings patch: Filtered out", removedCount, "global MCP server(s) to prevent duplicates");
    }

    return filtered;
  }

  function processSettingsBody(bodyStr) {
    try {
      var body = JSON.parse(bodyStr);
      var modified = false;

      // 1. Add Bedrock prefix if needed
      if (body && body.llm_model && needsBedrockPrefix(body.llm_model)) {
        console.log("Settings patch: Adding bedrock/ prefix to model:", body.llm_model);
        body.llm_model = 'bedrock/' + body.llm_model;
        modified = true;
      }

      // 2. Convert empty llm_base_url to null (Bedrock fails with empty string)
      if (body && body.hasOwnProperty('llm_base_url') && body.llm_base_url === '') {
        console.log("Settings patch: Converting empty llm_base_url to null");
        body.llm_base_url = null;
        modified = true;
      }

      // 3. For Bedrock models, convert llm_api_key to null (IAM auth doesn't use API keys)
      var isBedrockModel = body && body.llm_model && body.llm_model.startsWith('bedrock/');
      if (isBedrockModel && body.llm_api_key) {
        console.log("Settings patch: Removing llm_api_key for Bedrock IAM auth");
        body.llm_api_key = null;
        modified = true;
      }

      // 4. Filter out global MCP servers to prevent duplicates
      if (body && body.mcp_config) {
        body.mcp_config = filterGlobalMcpServers(body.mcp_config);
        modified = true;
      }

      if (modified) {
        return JSON.stringify(body);
      }
    } catch (e) {
      // Ignore JSON parse errors
    }
    return bodyStr;
  }

  // Intercept XMLHttpRequest (used by Axios in OpenHands frontend)
  var originalXhrOpen = XMLHttpRequest.prototype.open;
  var originalXhrSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    // Use a unique property name to avoid conflicts and store as non-enumerable
    Object.defineProperty(this, '_ohSettingsPatchData', {
      value: { method: method, url: url },
      writable: false,
      enumerable: false,
      configurable: true
    });
    return originalXhrOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    // Safely access the stored data (fallback to empty object if not set)
    var patchData = this._ohSettingsPatchData || {};

    // Only intercept POST/PUT to /api/settings
    if (patchData && patchData.url && typeof patchData.url === 'string' &&
        patchData.url.indexOf('/api/settings') !== -1 &&
        (patchData.method === 'POST' || patchData.method === 'PUT') && body) {
      try {
        var processedBody = processSettingsBody(body);
        return originalXhrSend.call(this, processedBody);
      } catch (e) {
        console.warn('Settings patch: Error processing request body, sending original:', e);
        return originalXhrSend.call(this, body);
      }
    }
    return originalXhrSend.apply(this, arguments);
  };

  console.log("OpenHands settings patch loaded (XHR intercept for Bedrock prefix + MCP deduplication)");
})();

// Auto-create default settings when LLM is already configured via config.toml.
// NOTE: Some deployments hide the settings UI (HIDE_LLM_SETTINGS=true), which prevents
// the settings modal from opening and can break conversation creation with:
//   400 {"msg_id":"CONFIGURATION$SETTINGS_NOT_FOUND", ...}
// This patch proactively creates default settings and closes the modal (if present).
(function() {
  var checkInterval = null;
  var checkCount = 0;
  var maxChecks = 50; // Check for 5 seconds max (50 * 100ms)
  var ensurePromise = null;

  function removeModal() {
    var overlay = document.querySelector('.fixed.inset-0.flex.items-center.justify-center.z-60');
    if (overlay) {
      overlay.remove();
      console.log("Settings modal removed from DOM");
    }
  }

  function parseJsonSafe(resp) {
    try {
      return resp.json();
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  function isSettingsMissingResponse(resp) {
    if (!resp) return Promise.resolve(false);
    if (resp.status === 404) return Promise.resolve(true);
    if (resp.status !== 400) return Promise.resolve(false);
    return parseJsonSafe(resp).then(function(body) {
      return !!(body && (body.msg_id === "CONFIGURATION$SETTINGS_NOT_FOUND" || body.message === "Settings not found"));
    }).catch(function() { return false; });
  }

  function pickDefaultModel(models) {
    var defaultModel = null;
    var modelPatterns = [
      /^global\.anthropic\.claude-opus/i,
      /^global\.anthropic\.claude-sonnet/i,
      /^anthropic\.claude-opus/i,
      /^anthropic\.claude-sonnet-4/i,
      /^anthropic\.claude-sonnet/i,
      /^anthropic\.claude.*v\d+:\d+$/
    ];

    if (Array.isArray(models)) {
      for (var p = 0; p < modelPatterns.length && !defaultModel; p++) {
        for (var i = 0; i < models.length; i++) {
          var model = models[i];
          if (typeof model !== 'string') continue;
          if (model.indexOf('embed') !== -1 || model.indexOf('haiku') !== -1) continue;
          if (modelPatterns[p].test(model)) {
            defaultModel = model;
            break;
          }
        }
      }

      if (!defaultModel) {
        for (var j = 0; j < models.length; j++) {
          if (typeof models[j] === 'string' && /^anthropic\.claude.*v\d+:\d+$/.test(models[j])) {
            defaultModel = models[j];
            break;
          }
        }
      }
    }

    return defaultModel || "global.anthropic.claude-opus-4-5-20251101-v1:0";
  }

  function ensureDefaultSettings() {
    if (ensurePromise) return ensurePromise;

    ensurePromise = fetch('/api/options/models')
      .then(function(r) { return r.json(); })
      .then(function(models) {
        var hasModels = Array.isArray(models) ? models.length > 0 : false;
        if (!hasModels) return false;

        return fetch('/api/settings').then(function(settingsResp) {
          if (settingsResp.ok) return true;
          return isSettingsMissingResponse(settingsResp.clone ? settingsResp.clone() : settingsResp).then(function(missing) {
            if (!missing) return false;

            console.log("Settings not found, creating default settings...");
            var defaultModel = pickDefaultModel(models);
            var bedrockModel = "bedrock/" + defaultModel;
            console.log("Using Bedrock model:", bedrockModel);

            var defaultSettings = {
              llm_provider: "bedrock",
              llm_model: bedrockModel,
              llm_api_key: null,
              aws_region: null
            };

            return fetch('/api/settings', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(defaultSettings)
            }).then(function(createResp) {
              if (createResp.ok) {
                console.log("Default settings created successfully");
                return true;
              }
              return parseJsonSafe(createResp).then(function(body) {
                console.warn("Failed to create settings:", createResp.status, body);
                return false;
              }).catch(function() {
                console.warn("Failed to create settings:", createResp.status);
                return false;
              });
            });
          });
        });
      })
      .catch(function() {
        // Common on unauthenticated routes - ignore.
        return false;
      });

    return ensurePromise;
  }

  // Expose for other patches (e.g., fetch retry on /api/conversations).
  try { window.__ohEnsureDefaultSettings = ensureDefaultSettings; } catch (e) {}

  function closeSettingsModal() {
    // Find the modal by test ID
    var modal = document.querySelector('[data-testid="ai-config-modal"]');
    if (modal) {
      ensureDefaultSettings().then(function(ok) {
        if (ok) removeModal();
      });
      clearInterval(checkInterval);
      return;
    }

    checkCount++;
    if (checkCount >= maxChecks) {
      clearInterval(checkInterval);
    }
  }

  // Start checking after page load
  if (document.readyState === 'complete') {
    try {
      if (!(window.location.pathname || '').startsWith('/_')) {
        ensureDefaultSettings().then(function() { /* no-op */ });
      }
    } catch (e) {}
    checkInterval = setInterval(closeSettingsModal, 100);
  } else {
    window.addEventListener('load', function() {
      try {
        if (!(window.location.pathname || '').startsWith('/_')) {
          ensureDefaultSettings().then(function() { /* no-op */ });
        }
      } catch (e) {}
      checkInterval = setInterval(closeSettingsModal, 100);
    });
  }

  console.log("OpenHands auto-close settings modal patch loaded");
})();

// Auto-resume sandbox conversations by triggering sandbox start/recreation.
// Handles two scenarios:
// 1. Sandbox is MISSING (e.g., EC2 replacement) — triggers recreation
// 2. SPA navigation to a conversation — sandbox not started because client-side
//    routing (React Router pushState) doesn't trigger a full page load, so the
//    backend never receives the initialization request that starts the sandbox.
//    A hard refresh works because it triggers full page load + app initialization.
// This patch detects non-running sandbox states and calls the /resume endpoint.
// It hooks into pushState/replaceState/popstate to re-trigger on SPA navigation.
(function() {
  var resumeAttempted = {};  // Track which conversations we've tried to resume
  var checkInterval = null;
  var maxCheckTime = 120000;  // 2 minutes max check time
  var checkStartTime = null;
  var currentConvId = null;   // Track current conversation to detect navigation

  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    if (match) {
      return match[1].replace(/-/g, '');
    }
    return null;
  }

  function formatConversationId(convId) {
    return convId.slice(0, 8) + '-' + convId.slice(8, 12) + '-' + convId.slice(12, 16) + '-' + convId.slice(16, 20) + '-' + convId.slice(20);
  }

  function stopChecking() {
    if (checkInterval) {
      clearInterval(checkInterval);
      checkInterval = null;
    }
  }

  function checkAndResume() {
    var convId = getConversationId();
    if (!convId) {
      stopChecking();
      return;
    }

    // If navigated to a different conversation, reset and re-init
    if (currentConvId && convId !== currentConvId) {
      stopChecking();
      init();
      return;
    }

    // Check timeout
    if (checkStartTime && (Date.now() - checkStartTime > maxCheckTime)) {
      console.log('Auto-resume: timeout reached, stopping checks');
      stopChecking();
      return;
    }

    // Use app-conversations endpoint which returns sandbox_status
    fetch('/api/v1/app-conversations?ids=' + convId)
      .then(function(resp) { return resp.json(); })
      .then(function(convList) {
        var conv = convList && convList[0];
        if (!conv) {
          console.log('Auto-resume: conversation not found');
          return;
        }

        console.log('Auto-resume: checking conversation, sandbox_status=' + conv.sandbox_status);

        if (conv.sandbox_status === 'RUNNING' || conv.sandbox_status === 'STARTING') {
          // Sandbox is active, stop checking
          console.log('Auto-resume: sandbox is ' + conv.sandbox_status + ', stopping checks');
          stopChecking();
        } else if (!resumeAttempted[convId]) {
          // Sandbox is not running (MISSING, STOPPED, PAUSED, ERROR, null, etc.)
          // Trigger sandbox start via the resume endpoint — only once per conversation.
          // After calling /resume, we keep polling status to confirm RUNNING, but
          // do NOT call /resume again to avoid duplicate requests while Fargate provisions.
          console.log('Auto-resume: sandbox is ' + conv.sandbox_status + ', triggering resume...');
          resumeAttempted[convId] = true;

          var formattedId = formatConversationId(convId);
          fetch('/api/v1/app-conversations/' + formattedId + '/resume', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
          }).then(function(resp) {
            if (resp.ok) {
              console.log('Auto-resume: sandbox resume triggered, waiting for RUNNING status...');
              // Keep resumeAttempted[convId] = true so we don't call /resume again.
              // The polling interval continues checking status and stops when
              // sandbox reaches RUNNING/STARTING. No page reload needed — the
              // OpenHands frontend WebSocket reconnects automatically.
            } else {
              resp.text().then(function(text) {
                console.warn('Auto-resume: failed to trigger sandbox resume:', resp.status, text);
              });
            }
          }).catch(function(err) {
            console.warn('Auto-resume: error triggering sandbox resume:', err);
          });
        }
        // else: resumeAttempted is true — already called /resume, just polling status
      })
      .catch(function(err) {
        // Ignore errors - might be authentication redirect
        console.log('Auto-resume: error fetching conversation:', err);
      });
  }

  function init() {
    var convId = getConversationId();
    if (!convId) return;

    // Reset state for new conversation
    currentConvId = convId;
    stopChecking();
    checkStartTime = Date.now();

    console.log('Auto-resume: initialized for conversation ' + convId);
    // Check every 5 seconds
    checkInterval = setInterval(checkAndResume, 5000);
    // Also check immediately after a delay (let page load first)
    setTimeout(checkAndResume, 2000);
  }

  // Re-initialize on SPA navigation (React Router uses pushState/replaceState).
  // This is the key fix: without this, navigating to a conversation via the
  // home page or left nav bar never triggers sandbox start because the page
  // doesn't fully reload — only the React component tree updates.
  function onNavigation() {
    var newConvId = getConversationId();
    if (newConvId && newConvId !== currentConvId) {
      console.log('Auto-resume: SPA navigation detected, re-initializing for ' + newConvId);
      init();
    } else if (!newConvId) {
      // Navigated away from a conversation page
      stopChecking();
      currentConvId = null;
    }
  }

  window.addEventListener('popstate', onNavigation);
  var origPushState = history.pushState;
  var origReplaceState = history.replaceState;
  history.pushState = function() {
    var result = origPushState.apply(this, arguments);
    onNavigation();
    return result;
  };
  history.replaceState = function() {
    var result = origReplaceState.apply(this, arguments);
    onNavigation();
    return result;
  };

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  console.log('OpenHands auto-resume sandbox patch loaded');
})();

// Rewrite localhost URLs in displayed text (chat messages, etc.)
// The AI agent outputs URLs like "http://localhost:51745" which users cannot access
// Also handles main domain with port (VS Code URLs): http://{subdomain}.{domain}:49955
// This rewrites them to runtime subdomain URLs: https://{port}-{convId}.runtime.{subdomain}.{domain}/
//
// MOBILE OPTIMIZATION: Uses requestIdleCallback-based batched processing instead of
// synchronous recursive DOM walking. The previous implementation processed every added
// DOM node synchronously in the MutationObserver callback, which blocked the main thread
// on mobile Safari (iPhone) during large conversation loads, preventing messages from rendering.
(function() {
  // Pattern for localhost/host.docker.internal URLs
  var urlPattern = /https?:\/\/(localhost|host\.docker\.internal):(\d+)(\/[^\s<>"')\]]*)?/gi;
  // Pattern for main domain with port (VS Code URLs)
  // Matches: http://{subdomain}.{domain}:49955/path?query (with path/query being optional)
  // Excludes runtime subdomains: {port}-{hex}.runtime.* using negative lookahead
  // This prevents matching URLs like: https://5000-abc123.runtime.{subdomain}.{domain}/
  // SECURITY NOTE: This regex only matches URLs for rewriting, not for security decisions.
  // Actual domain validation happens via CloudFront (only accepts configured domains) and
  // Lambda@Edge (verifies JWT from our Cognito pool). Rewritten URLs always point to
  // our runtime subdomain, never to external domains.
  var mainDomainPortPattern = /https?:\/\/(?!\d+-[a-f0-9]+\.runtime\.)([a-z0-9][a-z0-9.-]*\.[a-z]{2,}):(\d+)(\/[^\s<>"')\]]*)?/gi;

  // Cache conversation ID to avoid repeated regex matching on every DOM mutation.
  // Invalidated on navigation (popstate) so it re-checks on SPA route changes.
  var cachedConvId = null;
  var convIdChecked = false;

  // Extract conversation_id from URL (UUID format, remove hyphens to get hex)
  function getConversationId() {
    if (convIdChecked) return cachedConvId;
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    cachedConvId = match ? match[1].replace(/-/g, '') : null;
    convIdChecked = true;
    return cachedConvId;
  }

  // Invalidate cache on navigation to handle SPA route changes.
  // popstate fires on browser back/forward; pushState/replaceState are used by React Router.
  function invalidateConvIdCache() { convIdChecked = false; }
  window.addEventListener('popstate', invalidateConvIdCache);
  var origPushState = history.pushState;
  var origReplaceState = history.replaceState;
  history.pushState = function() {
    invalidateConvIdCache();
    return origPushState.apply(this, arguments);
  };
  history.replaceState = function() {
    invalidateConvIdCache();
    return origReplaceState.apply(this, arguments);
  };

  // Check if URL host matches the main domain (ignoring port)
  function isMainDomainUrl(urlHost) {
    var currentHost = window.location.host;
    // Strip any runtime subdomain prefix from current host for comparison
    var baseHost = currentHost.replace(/^\d+-[a-f0-9]+\.runtime\./, '');
    return urlHost === baseHost;
  }

  function rewriteTextUrls(text) {
    var convId = getConversationId();

    // First, rewrite localhost/host.docker.internal URLs
    text = text.replace(urlPattern, function(match, host, port, path) {
      var newUrl;
      if (convId) {
        // Build runtime subdomain URL
        var proto = window.location.protocol;
        var hostParts = window.location.host.split('.');
        var subDomain = hostParts[0];  // openhands
        var baseDomain = hostParts.slice(1).join('.');  // {domain}
        var runtimeHost = port + '-' + convId + '.runtime.' + subDomain + '.' + baseDomain;
        newUrl = proto + '//' + runtimeHost + (path || '/');
      } else {
        // Fallback to path-based URL
        newUrl = window.location.origin + '/runtime/' + port + (path || '/');
      }
      console.log('Text URL rewritten (localhost):', match, '->', newUrl);
      return newUrl;
    });

    // Then, rewrite main domain with port URLs (VS Code)
    text = text.replace(mainDomainPortPattern, function(match, urlHost, port, path) {
      // Only rewrite if it's the main domain, not any random domain with a port
      if (!isMainDomainUrl(urlHost)) {
        return match;  // Don't rewrite external domains
      }

      if (!convId) {
        console.warn('No conversation_id found, cannot rewrite main domain URL');
        return match;
      }

      var proto = window.location.protocol;
      var hostParts = urlHost.split('.');
      var subDomain = hostParts[0];  // openhands
      var baseDomain = hostParts.slice(1).join('.');  // {domain}
      var runtimeHost = port + '-' + convId + '.runtime.' + subDomain + '.' + baseDomain;
      var newUrl = proto + '//' + runtimeHost + (path || '/');
      console.log('Text URL rewritten (main domain:port):', match, '->', newUrl);
      return newUrl;
    });

    return text;
  }

  function processNode(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      var original = node.textContent;
      var rewritten = rewriteTextUrls(original);
      if (original !== rewritten) {
        node.textContent = rewritten;
      }
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      // Skip script and style elements
      if (node.tagName === 'SCRIPT' || node.tagName === 'STYLE') {
        return;
      }
      // Process href attributes on anchor tags
      if (node.tagName === 'A' && node.href) {
        var newHref = rewriteTextUrls(node.href);
        if (newHref !== node.href) {
          node.href = newHref;
        }
      }
      // Recursively process child nodes
      node.childNodes.forEach(processNode);
    }
  }

  // Batched, non-blocking node processing for MutationObserver.
  // Instead of processing every DOM node synchronously (which blocks the main thread
  // on mobile during large conversation loads), we collect pending nodes and process
  // them in the next idle callback or animation frame.
  var pendingNodes = [];
  var idleCallbackScheduled = false;
  var MAX_PENDING_NODES = 10000;  // Prevent unbounded growth in background tabs

  function processPendingNodes() {
    var nodes = pendingNodes;
    pendingNodes = [];
    idleCallbackScheduled = false;

    // Reset cache at the start of each batch so it re-reads the current URL.
    // This handles SPA navigation via pushState/replaceState which does not
    // fire popstate events. The cache still benefits within a single batch
    // (multiple rewriteTextUrls calls during processNode share the cached value).
    convIdChecked = false;

    // Skip all processing if not on a conversation page
    if (!getConversationId()) return;

    for (var i = 0; i < nodes.length; i++) {
      processNode(nodes[i]);
    }
  }

  function scheduleProcessing() {
    if (idleCallbackScheduled) return;
    idleCallbackScheduled = true;
    // Use requestIdleCallback for non-blocking processing when available (most modern browsers).
    // Falls back to requestAnimationFrame which runs before the next paint.
    if (typeof requestIdleCallback === 'function') {
      requestIdleCallback(processPendingNodes, { timeout: 500 });
    } else {
      requestAnimationFrame(processPendingNodes);
    }
  }

  // Register with shared MutationObserver dispatcher (see bottom of file)
  window.__ohMutationHandlers = window.__ohMutationHandlers || [];
  window.__ohMutationHandlers.push(function(mutations) {
    // Skip if not on a conversation page (early exit before iterating mutations)
    if (!getConversationId()) return;

    for (var i = 0; i < mutations.length; i++) {
      var addedNodes = mutations[i].addedNodes;
      for (var j = 0; j < addedNodes.length; j++) {
        var node = addedNodes[j];
        if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
          if (pendingNodes.length < MAX_PENDING_NODES) {
            pendingNodes.push(node);
          }
        }
      }
    }
    if (pendingNodes.length > 0) {
      scheduleProcessing();
    }
  });

  // Process existing content after DOM is ready
  function init() {
    if (document.body) {
      processNode(document.body);
      console.log('OpenHands localhost URL text rewriter loaded');
    }
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

// Logout button fix - intercepts logout button clicks and redirects to /_logout
// The OpenHands frontend's native logout doesn't work with Cognito authentication.
// This patch uses MutationObserver to find and override logout button behavior.
(function() {
  var patchedButtons = new WeakSet();

  function isLogoutButton(button) {
    var text = (button.textContent || button.innerText || '').toLowerCase();
    var cleanText = text.replace(/\s+/g, ' ').trim();
    return cleanText === 'logout';
  }

  function patchLogoutButton(button) {
    if (patchedButtons.has(button)) return;
    patchedButtons.add(button);

    // Override click at the element level using capture
    button.addEventListener('click', function(e) {
      console.log('Logout button click intercepted, redirecting to /_logout');
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      window.location.href = '/_logout';
      return false;
    }, true);

    // Also intercept mousedown to catch before React's synthetic events
    button.addEventListener('mousedown', function(e) {
      console.log('Logout button mousedown intercepted, redirecting to /_logout');
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      window.location.href = '/_logout';
      return false;
    }, true);

    console.log('Patched logout button');
  }

  function scanForLogoutButtons() {
    var buttons = document.querySelectorAll('button');
    buttons.forEach(function(button) {
      if (isLogoutButton(button)) {
        patchLogoutButton(button);
      }
    });
  }

  // Scan initially
  scanForLogoutButtons();

  // Register with shared MutationObserver dispatcher (see bottom of file)
  window.__ohMutationHandlers = window.__ohMutationHandlers || [];
  window.__ohMutationHandlers.push(function(mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var addedNodes = mutations[i].addedNodes;
      for (var j = 0; j < addedNodes.length; j++) {
        var node = addedNodes[j];
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'BUTTON' && isLogoutButton(node)) {
            patchLogoutButton(node);
          }
          // Check child buttons in added subtrees
          var buttons = node.querySelectorAll ? node.querySelectorAll('button') : [];
          buttons.forEach(function(button) {
            if (isLogoutButton(button)) {
              patchLogoutButton(button);
            }
          });
        }
      }
    }
  });

  // Also add document-level backup handler on mousedown (fires before React click)
  document.addEventListener('mousedown', function(event) {
    var target = event.target;
    var button = target.closest ? target.closest('button') : null;
    if (!button) {
      var el = target;
      while (el && el !== document.body && el.parentElement) {
        if (el.tagName === 'BUTTON') {
          button = el;
          break;
        }
        el = el.parentElement;
      }
    }

    if (button && isLogoutButton(button)) {
      console.log('Logout mousedown via document handler, redirecting to /_logout');
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      window.location.href = '/_logout';
      return false;
    }
  }, true);

  console.log('OpenHands logout button patch loaded');
})();

// Protect global MCP servers from modification/deletion
// Global servers defined in config.toml should be read-only in the UI
(function() {
  // List of global MCP server identifiers (names or URLs from config.toml)
  // These are system-managed and should not be editable by users
  var GLOBAL_MCP_SERVERS = [
    'chrome-devtools',
    'https://knowledge-mcp.global.api.aws'
  ];

  function isGlobalServer(serverName) {
    if (!serverName) return false;
    var normalized = serverName.trim().toLowerCase();
    for (var i = 0; i < GLOBAL_MCP_SERVERS.length; i++) {
      if (normalized === GLOBAL_MCP_SERVERS[i].toLowerCase()) {
        return true;
      }
    }
    return false;
  }

  function protectGlobalMcpServers() {
    // Only run on MCP settings page
    if (window.location.pathname !== '/settings/mcp') {
      return;
    }

    // Find all Edit and Delete buttons for MCP servers
    var editButtons = document.querySelectorAll('button[aria-label^="Edit "]');
    var deleteButtons = document.querySelectorAll('button[aria-label^="Delete "]');

    var protectedCount = 0;

    // Process Edit buttons
    editButtons.forEach(function(btn) {
      var label = btn.getAttribute('aria-label') || '';
      var serverName = label.replace(/^Edit\s+/, '');
      if (isGlobalServer(serverName)) {
        btn.disabled = true;
        btn.style.opacity = '0.4';
        btn.style.cursor = 'not-allowed';
        btn.title = 'System-managed MCP server (configured in config.toml)';
        protectedCount++;
      }
    });

    // Process Delete buttons
    deleteButtons.forEach(function(btn) {
      var label = btn.getAttribute('aria-label') || '';
      var serverName = label.replace(/^Delete\s+/, '');
      if (isGlobalServer(serverName)) {
        btn.disabled = true;
        btn.style.opacity = '0.4';
        btn.style.cursor = 'not-allowed';
        btn.title = 'System-managed MCP server (configured in config.toml)';
        protectedCount++;
      }
    });

    if (protectedCount > 0) {
      console.log('MCP protection: Disabled edit/delete for', protectedCount / 2, 'global server(s)');
    }
  }

  // Run on page load and when URL changes (SPA navigation)
  function setupProtection() {
    // Initial check
    setTimeout(protectGlobalMcpServers, 500);

    // Register with shared MutationObserver dispatcher (see bottom of file)
    var mcpDebounceTimer = null;
    window.__ohMutationHandlers = window.__ohMutationHandlers || [];
    window.__ohMutationHandlers.push(function() {
      // Debounce - only run once per batch of mutations
      clearTimeout(mcpDebounceTimer);
      mcpDebounceTimer = setTimeout(protectGlobalMcpServers, 200);
    });

    // Also handle URL changes (popstate for back/forward)
    window.addEventListener('popstate', function() {
      setTimeout(protectGlobalMcpServers, 500);
    });
  }

  if (document.readyState === 'complete') {
    setupProtection();
  } else {
    window.addEventListener('load', setupProtection);
  }

  console.log('OpenHands MCP protection patch loaded');
})();

// TEMPORARY: Remove after upgrading to OpenHands >= version with PR #12821
// Fix stuck chat-messages-skeleton on narrow viewports (< ~1200px / mobile).
// Root cause: upstream ConversationMain remounts WebSocket provider when switching
// mobile/desktop layout at 1024px, resetting loading state. The "history loaded"
// flag stays false because the isLoadingHistory transition from true->false never
// fires after remount. This patch detects the stuck state and forces the flag to
// true via React fiber internals.
// Upstream fix: All-Hands-AI/OpenHands#12821 (merged, not yet released)
(function() {
  var SKELETON_CHECK_DELAY = 3000;
  var SKELETON_RECHECK_INTERVAL = 2000;
  var MAX_RETRIES = 5;
  var SKELETON_SELECTOR = '[data-testid="chat-messages-skeleton"]';
  var MAX_FIBER_DEPTH = 15;
  var retryCount = 0;
  var fixApplied = false;
  var recheckTimer = null;

  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    return match ? match[1] : null;
  }

  function stopRechecking() {
    if (recheckTimer) {
      clearInterval(recheckTimer);
      recheckTimer = null;
    }
  }

  function markDone() {
    fixApplied = true;
    stopRechecking();
  }

  // React stores fiber references on DOM nodes via __reactFiber$ or __reactInternalInstance$ keys
  function findFiberFromDom(domNode) {
    var keys = Object.keys(domNode);
    for (var i = 0; i < keys.length; i++) {
      if (keys[i].indexOf('__reactFiber$') === 0 || keys[i].indexOf('__reactInternalInstance$') === 0) {
        return domNode[keys[i]];
      }
    }
    return null;
  }

  // Walk the useState hooks linked list to find a stuck boolean false flag with a dispatch queue.
  // This targets the history-loaded flag: [isLoaded, setIsLoaded] = useState(false)
  function findAndFixHistoryLoadedHook(fiber) {
    var hookState = fiber.memoizedState;
    var hookIndex = 0;

    while (hookState) {
      if (hookState.memoizedState === false && hookState.queue && typeof hookState.queue.dispatch === 'function') {
        console.log('[Patch 8] Found stuck history-loaded hook at index', hookIndex, '- forcing to true');
        hookState.queue.dispatch(true);
        return true;
      }
      hookState = hookState.next;
      hookIndex++;
    }
    return false;
  }

  // Walk up the fiber tree from the skeleton element, checking each FunctionComponent
  // (tag === 0) for a stuck useState(false) hook that controls skeleton visibility.
  function fixStuckFiber(skeleton) {
    var fiber = findFiberFromDom(skeleton);
    if (!fiber) {
      console.warn('[Patch 8] Could not find React fiber on skeleton element');
      return false;
    }

    var current = fiber;
    for (var depth = 0; depth < MAX_FIBER_DEPTH; depth++) {
      if (!current.return) break;
      current = current.return;
      if (current.tag === 0 && current.memoizedState) {
        if (findAndFixHistoryLoadedHook(current)) {
          console.log('[Patch 8] Fix applied at fiber depth', depth + 1, 'from skeleton');
          return true;
        }
      }
    }
    return false;
  }

  function attemptFix() {
    if (fixApplied) return;

    var convId = getConversationId();
    if (!convId) return;

    var skeleton = document.querySelector(SKELETON_SELECTOR);
    if (!skeleton) {
      markDone();
      return;
    }

    // Verify events are actually loaded before assuming the skeleton is stuck
    // Use app-conversations API to check if conversation has events loaded.
    // The events/search endpoint is on the agent-server (not main app), so we
    // check conversation status instead: an ARCHIVED conversation with a title
    // indicates the agent processed messages (events exist in the DB).
    fetch('/api/v1/app-conversations?ids=' + convId)
      .then(function(resp) {
        if (!resp.ok) return;
        return resp.json().then(function(data) {
          var conv = Array.isArray(data) && data[0];
          // Conversation has events if it has a title (agent processed messages)
          // or if its status is not CREATED (i.e., something happened)
          var hasEvents = conv && (conv.title || conv.status === 'RUNNING' || conv.status === 'ARCHIVED');
          if (!hasEvents) {
            console.log('[Patch 8] Skeleton visible but no events yet - waiting');
            return;
          }

          console.log('[Patch 8] Stuck skeleton detected with loaded events - attempting fiber fix');

          // Re-check: skeleton may have resolved during the async fetch
          skeleton = document.querySelector(SKELETON_SELECTOR);
          if (!skeleton) {
            markDone();
            return;
          }

          if (fixStuckFiber(skeleton)) {
            markDone();
          } else {
            retryCount++;
            console.log('[Patch 8] Could not find stuck hook (attempt', retryCount + '/' + MAX_RETRIES + ')');
            if (retryCount >= MAX_RETRIES) {
              console.warn('[Patch 8] Max retries reached - giving up');
              stopRechecking();
            }
          }
        });
      })
      .catch(function(err) {
        console.log('[Patch 8] Error checking events:', err);
      });
  }

  function init() {
    if (!getConversationId()) return;

    setTimeout(function() {
      attemptFix();
      if (!fixApplied && retryCount < MAX_RETRIES) {
        recheckTimer = setInterval(function() {
          if (fixApplied || retryCount >= MAX_RETRIES) {
            stopRechecking();
            return;
          }
          attemptFix();
        }, SKELETON_RECHECK_INTERVAL);
      }
    }, SKELETON_CHECK_DELAY);
  }

  function reset() {
    fixApplied = false;
    retryCount = 0;
    stopRechecking();
    setTimeout(init, 500);
  }

  window.addEventListener('popstate', reset);
  var origPushState = history.pushState;
  var origReplaceState = history.replaceState;
  history.pushState = function() {
    var result = origPushState.apply(this, arguments);
    reset();
    return result;
  };
  history.replaceState = function() {
    var result = origReplaceState.apply(this, arguments);
    reset();
    return result;
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  console.log('[Patch 8] OpenHands stuck skeleton fix loaded (remove after upgrade with PR #12821)');
})();

// Shared MutationObserver dispatcher - consolidates all MutationObserver callbacks into
// a single observer to reduce overhead on mobile devices.
// Previously, 3 independent MutationObservers on document.body with {childList: true,
// subtree: true} meant the browser invoked 3 separate JavaScript callbacks for every
// single DOM mutation. On mobile Safari (iPhone) with limited CPU, this tripled the
// callback overhead during large conversation loads, blocking message rendering.
// Now a single observer dispatches to all registered handlers.
(function() {
  var observer = new MutationObserver(function(mutations) {
    // Re-read handlers on each callback to support late registration
    // (e.g., MCP protection handler registers on 'load' event)
    var currentHandlers = window.__ohMutationHandlers || [];
    for (var i = 0; i < currentHandlers.length; i++) {
      try {
        currentHandlers[i](mutations);
      } catch (e) {
        console.error('Shared MutationObserver handler error:', e);
      }
    }
  });

  function startObserving() {
    var target = document.body || document.documentElement;
    if (target) {
      observer.observe(target, { childList: true, subtree: true });
      console.log('Shared MutationObserver started with', (window.__ohMutationHandlers || []).length, 'handler(s)');
    }
  }

  if (document.body) {
    startObserving();
  } else {
    document.addEventListener('DOMContentLoaded', startObserving);
  }
})();
</script>
