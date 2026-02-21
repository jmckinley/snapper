/**
 * Snapper Browser Extension — Options Page Script
 *
 * Dynamically generates service toggles from SERVICE_REGISTRY.
 * Supports categorized browsing with tabs.
 */

// Core settings fields (non-service toggles)
const CORE_FIELDS = [
  "snapper_url",
  "snapper_api_key",
  "agent_id",
  "fail_mode",
  "pii_scanning",
  "pii_blocking_mode",
  "clipboard_monitoring",
  "shadow_ai_tracking",
  "config_auto_sync",
  "sync_interval_minutes",
];

// Get all service toggle field names
function getServiceFields() {
  if (typeof SERVICE_REGISTRY === "undefined") return [];
  return SERVICE_REGISTRY.map((s) => `${s.source}_enabled`);
}

// All fields = core + service toggles
function getAllFields() {
  return [...CORE_FIELDS, ...getServiceFields()];
}

document.addEventListener("DOMContentLoaded", async () => {
  // Generate service toggles from registry
  renderServices("all");

  // Setup tab switching
  document.querySelectorAll("#service-tabs .tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll("#service-tabs .tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      renderServices(tab.dataset.category);
    });
  });

  // Check for managed settings
  let managed = false;
  try {
    const managedSettings = await chrome.storage.managed.get(["snapper_url"]);
    if (managedSettings.snapper_url) {
      managed = true;
      document.getElementById("managed-notice").style.display = "block";

      const allManaged = await chrome.storage.managed.get(getAllFields());
      for (const [key, value] of Object.entries(allManaged)) {
        const el = document.getElementById(key);
        if (!el) continue;
        if (el.type === "checkbox") {
          el.checked = value !== false;
        } else {
          el.value = value || "";
        }
        el.disabled = true;
      }
    }
  } catch (e) {
    // Managed storage not available
  }

  if (!managed) {
    // Load local settings
    const settings = await chrome.storage.local.get(getAllFields());
    for (const key of getAllFields()) {
      const el = document.getElementById(key);
      if (!el) continue;
      if (el.type === "checkbox") {
        el.checked = settings[key] !== false;
      } else if (settings[key]) {
        el.value = settings[key];
      }
    }
  }

  // Load auth state
  await refreshAuthUI();

  // Save button
  document.getElementById("save-btn").addEventListener("click", async () => {
    if (managed) {
      showToast("Settings are managed by your organization", "warning");
      return;
    }

    const values = {};
    for (const key of getAllFields()) {
      const el = document.getElementById(key);
      if (!el) continue;
      if (el.type === "checkbox") {
        values[key] = el.checked;
      } else {
        values[key] = el.value;
      }
    }

    await chrome.storage.local.set(values);
    showToast("Settings saved");
  });

  // Test button
  document.getElementById("test-btn").addEventListener("click", async () => {
    const url = document.getElementById("snapper_url").value;
    if (!url) {
      showToast("Enter a Snapper URL first", "error");
      return;
    }

    try {
      const response = await fetch(`${url}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok) {
        showToast("Connected successfully!");
      } else {
        showToast(`Server returned ${response.status}`, "error");
      }
    } catch (e) {
      showToast(`Cannot reach server: ${e.message}`, "error");
    }
  });

  // Sign in button
  document.getElementById("signin-btn").addEventListener("click", handleSignIn);

  // Sign out button
  document.getElementById("signout-btn").addEventListener("click", handleSignOut);

  // Enter key on password field triggers sign in
  document.getElementById("login_password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleSignIn();
  });

  // Sync Now button
  document.getElementById("sync-now-btn").addEventListener("click", async () => {
    const btn = document.getElementById("sync-now-btn");
    const statusEl = document.getElementById("sync-status");
    btn.disabled = true;
    btn.textContent = "Syncing...";
    statusEl.textContent = "";

    try {
      const result = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "sync_config_now" }, resolve);
      });
      if (result && result.config_sync_status === "current") {
        statusEl.textContent = "Synced just now";
        statusEl.style.color = "#22c55e";
      } else {
        statusEl.textContent = `Sync failed: ${(result && result.config_sync_error) || "unknown"}`;
        statusEl.style.color = "#ef4444";
      }
    } catch (e) {
      statusEl.textContent = `Error: ${e.message}`;
      statusEl.style.color = "#ef4444";
    } finally {
      btn.disabled = false;
      btn.textContent = "Sync Now";
    }
  });

  // Refresh sync status display
  refreshSyncStatus();
});


/**
 * Render service toggles, filtered by category.
 */
function renderServices(category) {
  const container = document.getElementById("services-list");
  container.innerHTML = "";

  if (typeof SERVICE_REGISTRY === "undefined") {
    container.innerHTML = '<div style="padding: 12px; color: #9ca3af;">Service registry not loaded.</div>';
    return;
  }

  const services = category === "all"
    ? SERVICE_REGISTRY
    : SERVICE_REGISTRY.filter((s) => s.category === category);

  for (const service of services) {
    const fieldId = `${service.source}_enabled`;
    const tierLabel = `Tier ${service.tier}`;
    const tierClass = `badge-tier${service.tier}`;
    const riskClass = `badge-${service.risk}`;

    const row = document.createElement("div");
    row.className = "service-row";
    row.innerHTML = `
      <div class="service-info">
        <div>
          <span class="service-name">${service.label}</span>
          <span class="badge ${tierClass}">${tierLabel}</span>
          <span class="badge ${riskClass}">${service.risk}</span>
        </div>
        <div class="service-domain">${service.domains.join(", ")}</div>
      </div>
      <label class="toggle">
        <input type="checkbox" id="${fieldId}" checked>
        <span class="toggle-slider"></span>
      </label>
    `;
    container.appendChild(row);
  }

  // Load saved states for the rendered checkboxes
  const fieldIds = services.map((s) => `${s.source}_enabled`);
  chrome.storage.local.get(fieldIds, (settings) => {
    for (const id of fieldIds) {
      const el = document.getElementById(id);
      if (el) el.checked = settings[id] !== false;
    }
  });
}


async function handleSignIn() {
  const email = document.getElementById("login_email").value.trim();
  const password = document.getElementById("login_password").value;
  const errorEl = document.getElementById("login-error");

  if (!email || !password) {
    errorEl.textContent = "Email and password are required";
    errorEl.style.display = "block";
    return;
  }

  const url = document.getElementById("snapper_url").value;
  if (!url) {
    errorEl.textContent = "Set a Snapper URL first";
    errorEl.style.display = "block";
    return;
  }

  errorEl.style.display = "none";
  const btn = document.getElementById("signin-btn");
  btn.disabled = true;
  btn.textContent = "Signing in...";

  try {
    const response = await fetch(`${url}/api/v1/auth/extension/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${response.status}`);
    }

    const data = await response.json();

    await chrome.storage.local.set({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      user_email: data.user.email,
      user_role: data.user.role,
      token_expires_at: Date.now() + data.expires_in * 1000,
    });

    document.getElementById("login_password").value = "";
    showToast(`Signed in as ${data.user.email}`);
    await refreshAuthUI();
  } catch (e) {
    errorEl.textContent = e.message;
    errorEl.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign In";
  }
}

async function handleSignOut() {
  await chrome.storage.local.remove([
    "access_token",
    "refresh_token",
    "user_email",
    "user_role",
    "token_expires_at",
  ]);
  showToast("Signed out");
  await refreshAuthUI();
}

async function refreshAuthUI() {
  const stored = await chrome.storage.local.get([
    "access_token",
    "user_email",
    "user_role",
  ]);

  const signedOut = document.getElementById("auth-signed-out");
  const signedIn = document.getElementById("auth-signed-in");

  if (stored.access_token && stored.user_email) {
    signedOut.style.display = "none";
    signedIn.style.display = "block";
    document.getElementById("auth-email").textContent = stored.user_email;
    document.getElementById("auth-role").textContent = stored.user_role || "member";
  } else {
    signedOut.style.display = "block";
    signedIn.style.display = "none";
  }
}

async function refreshSyncStatus() {
  const statusEl = document.getElementById("sync-status");
  if (!statusEl) return;

  try {
    const data = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "get_sync_status" }, resolve);
    });

    if (!data || data.status === "never") {
      statusEl.textContent = "Never synced";
      statusEl.style.color = "#9ca3af";
    } else if (data.status === "error") {
      statusEl.textContent = `Last sync failed: ${data.error || "unknown"}`;
      statusEl.style.color = "#ef4444";
    } else {
      const ago = data.lastSync ? formatTimeAgo(data.lastSync) : "unknown";
      statusEl.textContent = `Last synced: ${ago} — ${data.serviceCount} services, ${data.blockedCount} blocked`;
      statusEl.style.color = "#22c55e";
    }
  } catch (e) {
    statusEl.textContent = "";
  }
}

function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.style.background =
    type === "error" ? "#ef4444" : type === "warning" ? "#f59e0b" : "#22c55e";
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 3000);
}
