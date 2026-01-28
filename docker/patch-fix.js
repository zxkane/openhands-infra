<script>
// OpenHands localhost URL fix - rewrites localhost/host.docker.internal URLs to runtime subdomains
// Handles both localhost:{port} and host.docker.internal:{port} patterns
// Also handles main domain with port: {subdomain}.{domain}:{port} (VS Code editor)
// Uses runtime subdomain format: {port}-{convId}.runtime.{subdomain}.{domain}
// This allows apps to run at domain root, fixing internal routing issues
(function() {
  // Pattern matches localhost or host.docker.internal with port
  var wsPattern = /^wss?:\/\/(localhost|host\.docker\.internal):(\d+)(.*)/;
  var httpPattern = /^https?:\/\/(localhost|host\.docker\.internal):(\d+)(.*)/;
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
      return origFetch.call(this, newUrl, opts);
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

// Intercept settings updates to ensure Bedrock model prefix
// When users update settings via UI, the model name may not include "bedrock/" prefix.
// This patch intercepts POST/PUT requests to /api/settings and adds the prefix if missing.
(function() {
  var originalFetch = window.fetch;

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

  window.fetch = function(url, options) {
    // Only intercept POST/PUT to /api/settings
    if (typeof url === 'string' && url.indexOf('/api/settings') !== -1 &&
        options && (options.method === 'POST' || options.method === 'PUT') && options.body) {
      try {
        var body = JSON.parse(options.body);
        if (body && body.llm_model && needsBedrockPrefix(body.llm_model)) {
          console.log("Settings patch: Adding bedrock/ prefix to model:", body.llm_model);
          body.llm_model = 'bedrock/' + body.llm_model;
          options = Object.assign({}, options, { body: JSON.stringify(body) });
        }
      } catch (e) {
        // Ignore JSON parse errors
      }
    }
    return originalFetch.apply(this, arguments);
  };

  console.log("OpenHands settings Bedrock prefix patch loaded");
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

// Auto-resume MISSING sandbox conversations by triggering sandbox recreation
// When a sandbox is missing (due to EC2 replacement), the frontend shows "Connecting..."
// indefinitely. This patch detects sandbox_status=MISSING and triggers recreation.
(function() {
  var resumeAttempted = {};  // Track which conversations we've tried to resume
  var checkInterval = null;
  var maxCheckTime = 120000;  // 2 minutes max check time
  var checkStartTime = null;

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

  function checkAndResume() {
    var convId = getConversationId();
    if (!convId) return;

    // Don't retry if we've already attempted for this conversation
    if (resumeAttempted[convId]) return;

    // Check timeout
    if (checkStartTime && (Date.now() - checkStartTime > maxCheckTime)) {
      console.log('Auto-resume: timeout reached, stopping checks');
      clearInterval(checkInterval);
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

        if (conv.sandbox_status === 'MISSING') {
          console.log('Auto-resume: sandbox is MISSING, triggering recreation...');
          resumeAttempted[convId] = true;

          // Trigger sandbox recreation by calling the resume endpoint (Patch 3c)
          var formattedId = formatConversationId(convId);
          fetch('/api/v1/app-conversations/' + formattedId + '/resume', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
          }).then(function(resp) {
            if (resp.ok) {
              console.log('Auto-resume: sandbox recreation triggered successfully, reloading...');
              // Reload the page to reconnect
              setTimeout(function() {
                window.location.reload();
              }, 3000);
            } else {
              resp.text().then(function(text) {
                console.warn('Auto-resume: failed to trigger sandbox recreation:', resp.status, text);
              });
            }
          }).catch(function(err) {
            console.warn('Auto-resume: error triggering sandbox recreation:', err);
          });
        } else if (conv.sandbox_status === 'RUNNING' || conv.sandbox_status === 'STARTING') {
          // Sandbox is active, stop checking
          console.log('Auto-resume: sandbox is ' + conv.sandbox_status + ', stopping checks');
          clearInterval(checkInterval);
        }
      })
      .catch(function(err) {
        // Ignore errors - might be authentication redirect
        console.log('Auto-resume: error fetching conversation:', err);
      });
  }

  function init() {
    var convId = getConversationId();
    if (!convId) return;

    console.log('Auto-resume: initialized for conversation ' + convId);
    checkStartTime = Date.now();
    // Check every 5 seconds
    checkInterval = setInterval(checkAndResume, 5000);
    // Also check immediately after a delay (let page load first)
    setTimeout(checkAndResume, 2000);
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  console.log('OpenHands auto-resume MISSING sandbox patch loaded');
})();

// Rewrite localhost URLs in displayed text (chat messages, etc.)
// The AI agent outputs URLs like "http://localhost:51745" which users cannot access
// Also handles main domain with port (VS Code URLs): http://{subdomain}.{domain}:49955
// This rewrites them to runtime subdomain URLs: https://{port}-{convId}.runtime.{subdomain}.{domain}/
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

  // Extract conversation_id from URL (UUID format, remove hyphens to get hex)
  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    if (match) {
      return match[1].replace(/-/g, '');
    }
    return null;
  }

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

  // Process existing content after DOM is ready
  function init() {
    if (document.body) {
      processNode(document.body);

      // Observe future DOM changes
      var observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          mutation.addedNodes.forEach(function(node) {
            if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
              processNode(node);
            }
          });
        });
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true
      });

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

  // Watch for new buttons added to DOM
  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
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
      });
    });
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
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
</script>
