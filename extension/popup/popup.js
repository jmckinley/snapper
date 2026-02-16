/**
 * Snapper Browser Extension — Popup Script
 */

document.addEventListener("DOMContentLoaded", async () => {
  // Check connection status
  const config = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "get_config" }, resolve);
  });

  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");

  if (!config || !config.snapperUrl) {
    dot.className = "status-dot unconfigured";
    text.textContent = "Not configured — click Settings";
  } else {
    // Test connection
    try {
      const response = await fetch(`${config.snapperUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok) {
        dot.className = "status-dot connected";
        text.textContent = `Connected to ${new URL(config.snapperUrl).host}`;
      } else {
        dot.className = "status-dot disconnected";
        text.textContent = "Server error";
      }
    } catch (e) {
      dot.className = "status-dot disconnected";
      text.textContent = "Cannot reach Snapper";
    }

    // Set dashboard link
    document.getElementById("dashboard-link").href = config.snapperUrl;
    document.getElementById("dashboard-link").addEventListener("click", (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: config.snapperUrl });
    });
  }

  // Load recent decisions
  const decisions = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "get_recent_decisions" }, resolve);
  });

  const list = document.getElementById("decisions-list");

  if (decisions && decisions.length > 0) {
    list.innerHTML = decisions
      .map((d) => {
        const badgeClass =
          d.decision === "allow"
            ? "badge-allow"
            : d.decision === "deny"
            ? "badge-deny"
            : "badge-approval";

        const timeAgo = formatTimeAgo(d.timestamp);

        return `
          <div class="decision-item">
            <span class="decision-badge ${badgeClass}">${d.decision}</span>
            <span class="decision-tool" title="${d.toolName}">${d.toolName}</span>
            <span class="decision-time">${timeAgo}</span>
          </div>
        `;
      })
      .join("");
  }

  // Settings link
  document.getElementById("settings-link").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});

function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
