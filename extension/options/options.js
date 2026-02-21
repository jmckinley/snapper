/**
 * Snapper Browser Extension — Options Page Script
 */

const FIELDS = [
  "snapper_url",
  "snapper_api_key",
  "agent_id",
  "fail_mode",
  "chatgpt_enabled",
  "claude_enabled",
  "gemini_enabled",
  "copilot_enabled",
  "grok_enabled",
  "pii_scanning",
  "pii_blocking_mode",
];

document.addEventListener("DOMContentLoaded", async () => {
  // Check for managed settings
  let managed = false;
  try {
    const managedSettings = await chrome.storage.managed.get(["snapper_url"]);
    if (managedSettings.snapper_url) {
      managed = true;
      document.getElementById("managed-notice").style.display = "block";

      // Load managed values and disable inputs
      const allManaged = await chrome.storage.managed.get(FIELDS);
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
    const settings = await chrome.storage.local.get(FIELDS);
    for (const key of FIELDS) {
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
    for (const key of FIELDS) {
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
});

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

function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.style.background =
    type === "error" ? "#ef4444" : type === "warning" ? "#f59e0b" : "#22c55e";
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 3000);
}
