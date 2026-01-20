<script>
// OpenHands localhost URL fix - rewrites localhost/host.docker.internal URLs to /runtime/{conversation_id}/{port}/...
// Handles both localhost:{port} and host.docker.internal:{port} patterns
// conversation_id is extracted from the current page URL (/conversations/{uuid})
(function() {
  // Pattern matches localhost or host.docker.internal with port
  var wsPattern = /^wss?:\/\/(localhost|host\.docker\.internal):(\d+)(.*)/;
  var httpPattern = /^https?:\/\/(localhost|host\.docker\.internal):(\d+)(.*)/;

  // Extract conversation_id from URL (UUID format, remove hyphens to get hex)
  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    if (match) {
      // Remove hyphens from UUID to get hex format (matches sandbox_id = conversation_id.hex)
      return match[1].replace(/-/g, '');
    }
    return null;
  }

  // Build runtime URL with conversation_id
  function buildRuntimeUrl(port, path) {
    var convId = getConversationId();
    if (convId) {
      return window.location.origin + '/runtime/' + convId + '/' + port + (path || '/');
    }
    // Fallback: use old format without conversation_id (won't work with new router)
    console.warn("No conversation_id found, runtime routing may fail");
    return window.location.origin + '/runtime/' + port + (path || '/');
  }

  var origWS = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    var newUrl = url;
    var m = url.match(wsPattern);
    if (m) {
      var proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      var convId = getConversationId();
      if (convId) {
        newUrl = proto + "//" + window.location.host + "/runtime/" + convId + "/" + m[2] + m[3];
      } else {
        newUrl = proto + "//" + window.location.host + "/runtime/" + m[2] + m[3];
      }
      console.log("WS patched:", url, "->", newUrl);
    }
    return protocols ? new origWS(newUrl, protocols) : new origWS(newUrl);
  };
  window.WebSocket.prototype = origWS.prototype;
  window.WebSocket.CONNECTING = origWS.CONNECTING;
  window.WebSocket.OPEN = origWS.OPEN;
  window.WebSocket.CLOSING = origWS.CLOSING;
  window.WebSocket.CLOSED = origWS.CLOSED;

  var origFetch = window.fetch;
  window.fetch = function(url, opts) {
    var newUrl = url;
    if (typeof url === "string") {
      var m = url.match(httpPattern);
      if (m) {
        newUrl = buildRuntimeUrl(m[2], m[3]);

        // Normalize git paths - convert absolute workspace paths to relative
        // The agent-server's git router expects "." for the workspace root
        // Frontend sends "/workspace/project" which the backend interprets as a subdirectory,
        // prepending /workspace/project/ and causing: "/workspace/project/project"
        // Note: URL at this point includes /runtime/{conv_id}/{port}/ prefix, e.g.:
        // https://domain/runtime/abc123/38793/api/git/changes/%2Fworkspace%2Fproject
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
    return origFetch.call(this, newUrl, opts);
  };

  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    var newUrl = url;
    if (typeof url === "string") {
      var m = url.match(httpPattern);
      if (m) {
        newUrl = buildRuntimeUrl(m[2], m[3]);

        // Normalize git paths - convert absolute workspace paths to relative
        // Note: URL at this point includes /runtime/{conv_id}/{port}/ prefix
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

  console.log("OpenHands localhost/host.docker.internal URL fix loaded (with conversation_id routing)");
})();

// Auto-close AI settings modal when LLM is already configured via config.toml
// The modal opens when /api/settings returns 404 but LLM may already be set up
// When LLM is configured but settings don't exist, create default settings first
// This modal is intentionally non-dismissible (no close button, backdrop click ignored)
// So we remove it from DOM directly when LLM is already configured
(function() {
  var checkInterval = null;
  var checkCount = 0;
  var maxChecks = 50; // Check for 5 seconds max (50 * 100ms)

  function removeModal() {
    var overlay = document.querySelector('.fixed.inset-0.flex.items-center.justify-center.z-60');
    if (overlay) {
      overlay.remove();
      console.log("Settings modal removed from DOM");
    }
  }

  function closeSettingsModal() {
    // Find the modal by test ID
    var modal = document.querySelector('[data-testid="ai-config-modal"]');
    if (modal) {
      // Check if LLM is configured by fetching /api/options/models
      // If models are available, LLM is configured via config.toml
      fetch('/api/options/models')
        .then(function(r) { return r.json(); })
        .then(function(models) {
          // API returns array directly, not {models: [...]}
          var hasModels = Array.isArray(models) ? models.length > 0 : false;
          if (hasModels) {
            console.log("LLM configured via config.toml, checking if settings exist...");

            // Check if settings already exist
            fetch('/api/settings')
              .then(function(settingsResp) {
                if (settingsResp.status === 404) {
                  // Settings don't exist, create default settings
                  console.log("Settings not found, creating default settings...");

                  // Model selection priority for Bedrock Claude:
                  // 1. Claude 4 / Opus models (best tool calling support)
                  // 2. Claude Sonnet 4 models
                  // 3. Any other Claude model (avoid Haiku for tool-heavy workflows)
                  var defaultModel = null;

                  // Priority patterns (higher priority first)
                  var modelPatterns = [
                    // Global inference profiles (opus, sonnet in priority order)
                    /^global\.anthropic\.claude-opus/i,
                    /^global\.anthropic\.claude-sonnet/i,
                    // Regional opus and sonnet models
                    /^anthropic\.claude-opus/i,
                    /^anthropic\.claude-sonnet-4/i,
                    /^anthropic\.claude-sonnet/i,
                    // Any Claude model (except embed and haiku)
                    /^anthropic\.claude.*v\d+:\d+$/
                  ];

                  // Find best model based on priority
                  for (var p = 0; p < modelPatterns.length && !defaultModel; p++) {
                    for (var i = 0; i < models.length; i++) {
                      var model = models[i];
                      // Skip embedding and haiku models for tool-heavy workflows
                      if (model.indexOf('embed') !== -1 || model.indexOf('haiku') !== -1) continue;
                      if (modelPatterns[p].test(model)) {
                        defaultModel = model;
                        break;
                      }
                    }
                  }

                  // Fallback: if only haiku is available, use it (better than nothing)
                  if (!defaultModel) {
                    for (var i = 0; i < models.length; i++) {
                      if (/^anthropic\.claude.*v\d+:\d+$/.test(models[i])) {
                        defaultModel = models[i];
                        break;
                      }
                    }
                  }

                  // Fallback to hardcoded Opus 4.5 global inference profile
                  defaultModel = defaultModel || "global.anthropic.claude-opus-4-5-20251101-v1:0";

                  // Create minimal settings - LLM provider is "bedrock" for config.toml setup
                  // IMPORTANT: Use the exact model format from config.toml with bedrock/ prefix
                  // The /api/options/models returns models without bedrock/ prefix, but OpenHands
                  // needs the full bedrock/ prefixed format to use instance profile auth
                  var bedrockModel = "bedrock/" + defaultModel;
                  console.log("Using Bedrock model:", bedrockModel);

                  var defaultSettings = {
                    llm_provider: "bedrock",
                    llm_model: bedrockModel,
                    llm_api_key: null,  // Not needed when using config.toml with instance profile
                    aws_region: null    // Will use region from config.toml
                  };

                  return fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(defaultSettings)
                  }).then(function(createResp) {
                    if (createResp.ok) {
                      console.log("Default settings created successfully");
                    } else {
                      console.log("Failed to create settings:", createResp.status);
                    }
                    return removeModal();
                  });
                } else {
                  // Settings exist, just close modal
                  console.log("Settings already exist");
                  return removeModal();
                }
              })
              .catch(function(e) {
                console.log("Error checking settings:", e);
                removeModal();
              });
          }
        })
        .catch(function(e) {
          console.log("Error fetching models (LLM may not be configured):", e);
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
    checkInterval = setInterval(closeSettingsModal, 100);
  } else {
    window.addEventListener('load', function() {
      checkInterval = setInterval(closeSettingsModal, 100);
    });
  }

  console.log("OpenHands auto-close settings modal patch loaded");
})();

// Rewrite localhost URLs in displayed text (chat messages, etc.)
// The AI agent outputs URLs like "http://localhost:51745" which users cannot access
// This rewrites them to the accessible path-based URL: https://{domain}/runtime/{conversation_id}/{port}/
(function() {
  var urlPattern = /https?:\/\/(localhost|host\.docker\.internal):(\d+)(\/[^\s<>"')\]]*)?/gi;

  // Extract conversation_id from URL (UUID format, remove hyphens to get hex)
  function getConversationId() {
    var match = window.location.pathname.match(/\/conversations\/([a-f0-9-]+)/i);
    if (match) {
      return match[1].replace(/-/g, '');
    }
    return null;
  }

  function rewriteTextUrls(text) {
    var convId = getConversationId();
    return text.replace(urlPattern, function(match, host, port, path) {
      var newUrl;
      if (convId) {
        newUrl = window.location.origin + '/runtime/' + convId + '/' + port + (path || '/');
      } else {
        newUrl = window.location.origin + '/runtime/' + port + (path || '/');
      }
      console.log('Text URL rewritten:', match, '->', newUrl);
      return newUrl;
    });
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
</script>
