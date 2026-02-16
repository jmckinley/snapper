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
  "pii_scanning",
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
});

function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.style.background =
    type === "error" ? "#ef4444" : type === "warning" ? "#f59e0b" : "#22c55e";
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 3000);
}
