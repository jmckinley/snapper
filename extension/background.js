/**
 * Snapper Browser Extension — Background Service Worker
 *
 * Handles evaluate calls to Snapper server, approval polling,
 * session-level caching of allow decisions, auth token management,
 * and device fingerprinting.
 */

// Session cache for allow decisions (cleared on extension restart)
const allowCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Recent decisions for popup display
const recentDecisions = [];
const MAX_RECENT = 10;

// Track whether device meta has been sent this session
let deviceMetaSent = false;

/**
 * Get extension configuration from managed storage (enterprise) or local storage.
 */
async function getConfig() {
  // Try managed storage first (enterprise admin-configured)
  try {
    const managed = await chrome.storage.managed.get([
      "snapper_url",
      "snapper_api_key",
      "agent_id",
      "fail_mode",
      "pii_scanning",
      "pii_blocking_mode",
    ]);
    if (managed.snapper_url) {
      return {
        snapperUrl: managed.snapper_url,
        apiKey: managed.snapper_api_key || "",
        agentId: managed.agent_id || "browser-extension",
        failMode: managed.fail_mode || "closed",
        piiScanning: managed.pii_scanning !== false,
        piiBlockingMode: managed.pii_blocking_mode || "warn",
        managed: true,
      };
    }
  } catch (e) {
    // Managed storage not available
  }

  // Fall back to local storage
  const local = await chrome.storage.local.get([
    "snapper_url",
    "snapper_api_key",
    "agent_id",
    "fail_mode",
    "pii_scanning",
    "pii_blocking_mode",
  ]);

  return {
    snapperUrl: local.snapper_url || "",
    apiKey: local.snapper_api_key || "",
    agentId: local.agent_id || "browser-extension",
    failMode: local.fail_mode || "closed",
    piiScanning: local.pii_scanning !== false,
    piiBlockingMode: local.pii_blocking_mode || "warn",
    managed: false,
  };
}

/**
 * Get or create a persistent device ID for this browser instance.
 */
async function getOrCreateDeviceId() {
  const stored = await chrome.storage.local.get(["device_id"]);
  if (stored.device_id) return stored.device_id;
  const deviceId = crypto.randomUUID();
  await chrome.storage.local.set({ device_id: deviceId });
  return deviceId;
}

/**
 * Collect device metadata for fingerprinting.
 */
function getDeviceMeta() {
  return {
    platform: navigator.platform || "",
    language: navigator.language || "",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    cores: navigator.hardwareConcurrency || 0,
    memory: navigator.deviceMemory || 0,
  };
}

/**
 * Get stored auth token, refreshing if about to expire.
 */
async function getAuthToken(snapperUrl) {
  const stored = await chrome.storage.local.get([
    "access_token",
    "token_expires_at",
    "refresh_token",
  ]);

  if (!stored.access_token) return null;

  // Check if token is about to expire (< 2 min remaining)
  if (stored.token_expires_at && Date.now() > stored.token_expires_at - 120000) {
    if (stored.refresh_token) {
      const refreshed = await refreshToken(snapperUrl, stored.refresh_token);
      if (refreshed) return refreshed;
    }
    // Refresh failed — clear stale tokens
    await chrome.storage.local.remove([
      "access_token",
      "refresh_token",
      "token_expires_at",
      "user_email",
      "user_role",
    ]);
    return null;
  }

  return stored.access_token;
}

/**
 * Refresh an access token using the refresh token.
 */
async function refreshToken(snapperUrl, refreshTokenValue) {
  try {
    const response = await fetch(`${snapperUrl}/api/v1/auth/extension/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshTokenValue }),
    });

    if (!response.ok) return null;

    const data = await response.json();
    await chrome.storage.local.set({
      access_token: data.access_token,
      token_expires_at: Date.now() + data.expires_in * 1000,
    });
    return data.access_token;
  } catch (e) {
    return null;
  }
}

/**
 * Build common headers for Snapper API calls.
 * Includes API key, auth token (if signed in), and device ID.
 */
async function buildHeaders(config) {
  const headers = { "Content-Type": "application/json" };

  if (config.apiKey) {
    headers["X-API-Key"] = config.apiKey;
  }

  // Auth token (if user is signed in)
  const token = await getAuthToken(config.snapperUrl);
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Device identification
  const deviceId = await getOrCreateDeviceId();
  headers["X-Device-Id"] = deviceId;

  // Send device meta once per session
  if (!deviceMetaSent) {
    headers["X-Device-Meta"] = JSON.stringify(getDeviceMeta());
    deviceMetaSent = true;
  }

  return headers;
}

/**
 * Evaluate a tool call against Snapper policy.
 */
async function evaluate(toolName, toolInput, requestType, source) {
  const config = await getConfig();

  if (!config.snapperUrl) {
    return {
      decision: "allow",
      reason: "Snapper not configured",
      configured: false,
    };
  }

  // Check cache
  const cacheKey = `${toolName}:${JSON.stringify(toolInput)}`;
  const cached = allowCache.get(cacheKey);
  if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
    return cached.result;
  }

  const payload = {
    agent_id: config.agentId,
    request_type: requestType || "tool",
    tool_name: toolName,
    tool_input: toolInput || {},
  };

  try {
    const headers = await buildHeaders(config);

    const response = await fetch(`${config.snapperUrl}/api/v1/rules/evaluate`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    // On 401, try refresh once and retry
    if (response.status === 401) {
      const stored = await chrome.storage.local.get(["refresh_token"]);
      if (stored.refresh_token) {
        const newToken = await refreshToken(config.snapperUrl, stored.refresh_token);
        if (newToken) {
          headers["Authorization"] = `Bearer ${newToken}`;
          const retryResponse = await fetch(
            `${config.snapperUrl}/api/v1/rules/evaluate`,
            { method: "POST", headers, body: JSON.stringify(payload) }
          );
          if (retryResponse.ok) {
            const retryData = await retryResponse.json();
            if (retryData.decision === "allow") {
              allowCache.set(cacheKey, { result: retryData, time: Date.now() });
            }
            trackDecision(toolName, retryData.decision, retryData.reason, source);
            return retryData;
          }
        }
      }
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    // Cache allow decisions
    if (data.decision === "allow") {
      allowCache.set(cacheKey, { result: data, time: Date.now() });
    }

    // Track decision
    trackDecision(toolName, data.decision, data.reason, source);

    return data;
  } catch (error) {
    const result = {
      decision: config.failMode === "open" ? "allow" : "deny",
      reason: `Snapper unreachable (fail-${config.failMode}): ${error.message}`,
    };
    trackDecision(toolName, result.decision, result.reason, source);
    return result;
  }
}

/**
 * Poll for approval status.
 */
async function pollApproval(approvalId, timeoutMs = 300000) {
  const config = await getConfig();
  const start = Date.now();
  const pollInterval = 5000;

  while (Date.now() - start < timeoutMs) {
    try {
      const headers = await buildHeaders(config);

      const response = await fetch(
        `${config.snapperUrl}/api/v1/approvals/${approvalId}/status`,
        { headers }
      );

      if (!response.ok) {
        await sleep(pollInterval);
        continue;
      }

      const data = await response.json();

      switch (data.status) {
        case "approved":
          return { decision: "allow", ...data };
        case "denied":
          return { decision: "deny", reason: data.reason || "Approval denied" };
        case "expired":
          return { decision: "deny", reason: "Approval expired" };
        case "pending":
          await sleep(Math.min((data.wait_seconds || 5) * 1000, 10000));
          break;
        default:
          await sleep(pollInterval);
      }
    } catch (error) {
      await sleep(pollInterval);
    }
  }

  return { decision: "deny", reason: "Approval timed out" };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function trackDecision(toolName, decision, reason, source) {
  recentDecisions.unshift({
    toolName,
    decision,
    reason,
    source: source || "unknown",
    timestamp: Date.now(),
  });
  if (recentDecisions.length > MAX_RECENT) {
    recentDecisions.pop();
  }

  // Update badge
  updateBadge(decision);
}

function updateBadge(lastDecision) {
  const colors = {
    allow: "#22c55e",
    deny: "#ef4444",
    require_approval: "#eab308",
  };
  chrome.action.setBadgeBackgroundColor({
    color: colors[lastDecision] || "#6b7280",
  });
}

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "evaluate") {
    evaluate(
      message.toolName,
      message.toolInput,
      message.requestType,
      message.source
    ).then(sendResponse);
    return true; // Keep channel open for async response
  }

  if (message.type === "poll_approval") {
    pollApproval(message.approvalId, message.timeout).then(sendResponse);
    return true;
  }

  if (message.type === "get_config") {
    getConfig().then(sendResponse);
    return true;
  }

  if (message.type === "get_recent_decisions") {
    sendResponse(recentDecisions);
    return false;
  }

  if (message.type === "clear_cache") {
    allowCache.clear();
    sendResponse({ cleared: true });
    return false;
  }

  if (message.type === "get_auth_state") {
    chrome.storage.local
      .get(["access_token", "user_email", "user_role"])
      .then((stored) => {
        sendResponse({
          authenticated: !!stored.access_token,
          email: stored.user_email || null,
          role: stored.user_role || null,
        });
      });
    return true;
  }
});

// Clean expired cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of allowCache.entries()) {
    if (now - value.time > CACHE_TTL_MS) {
      allowCache.delete(key);
    }
  }
}, 60000);

console.log("[Snapper] Background service worker initialized");
