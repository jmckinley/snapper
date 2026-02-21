/**
 * Snapper Shared Content Script Utilities
 *
 * Common functions used by all Tier 1 and Tier 2 content scripts:
 * - DOM selectors
 * - Tool call evaluation
 * - Approval polling
 * - Deny/approval overlays
 * - Clipboard/paste monitoring
 */

// Prevent double-loading
if (!window.__snapperSharedLoaded) {
  window.__snapperSharedLoaded = true;

  /**
   * Selector helper with fallback chains for robustness.
   */
  window.snapper$ = function (selectors, root = document) {
    for (const sel of selectors) {
      try {
        const el = root.querySelector(sel);
        if (el) return el;
      } catch (e) { /* skip invalid selector */ }
    }
    return null;
  };

  /**
   * Multi-element selector helper.
   */
  window.snapper$$ = function (selectors, root = document) {
    for (const sel of selectors) {
      try {
        const els = root.querySelectorAll(sel);
        if (els.length > 0) return Array.from(els);
      } catch (e) { /* skip */ }
    }
    return [];
  };

  /**
   * Show deny overlay on a tool output element.
   */
  window.snapperShowDenyOverlay = function (element, toolName, reason, ruleName) {
    const overlay = document.createElement("div");
    overlay.className = "snapper-inline-deny";
    overlay.innerHTML = `
      <div class="snapper-inline-header">
        <span class="snapper-icon">&#128721;</span>
        <strong>Blocked by Snapper</strong>
      </div>
      <div class="snapper-inline-details">
        <div>Tool: <code>${toolName}</code></div>
        <div>Rule: ${ruleName || "Security Policy"}</div>
        <div>Reason: ${reason}</div>
      </div>
    `;
    element.style.position = "relative";
    element.appendChild(overlay);
  };

  /**
   * Show approval waiting banner.
   */
  window.snapperShowApprovalBanner = function (element, toolName, approvalId) {
    const banner = document.createElement("div");
    banner.className = "snapper-inline-approval";
    banner.id = `snapper-approval-${approvalId}`;
    banner.innerHTML = `
      <div class="snapper-inline-header">
        <span class="snapper-icon snapper-pulse">&#9203;</span>
        <strong>Waiting for Approval</strong>
      </div>
      <div class="snapper-inline-details">
        <div>Tool: <code>${toolName}</code></div>
        <div>Request: ${approvalId.substring(0, 8)}...</div>
        <div class="snapper-approval-note">Check Telegram, Slack, or Snapper dashboard to approve.</div>
      </div>
    `;
    element.style.position = "relative";
    element.appendChild(banner);
    return banner;
  };

  /**
   * Evaluate a tool call via the background service worker.
   */
  window.snapperEvaluateToolCall = async function (toolName, toolInput, requestType, source) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "evaluate", toolName, toolInput, requestType, source },
        resolve
      );
    });
  };

  /**
   * Poll for approval via background service worker.
   */
  window.snapperPollApproval = async function (approvalId) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "poll_approval", approvalId, timeout: 300000 },
        resolve
      );
    });
  };

  /**
   * Handle a detected tool call — evaluate + show overlay/banner as needed.
   */
  window.snapperHandleToolCall = async function (element, toolName, toolInput, requestType, source) {
    const result = await window.snapperEvaluateToolCall(toolName, toolInput, requestType, source);

    if (!result || result.decision === "allow") return;

    if (result.decision === "deny") {
      window.snapperShowDenyOverlay(element, toolName, result.reason, result.matched_rule_name);
      return;
    }

    if (result.decision === "require_approval") {
      const approvalId = result.approval_request_id;
      if (!approvalId) {
        window.snapperShowDenyOverlay(element, toolName, "Approval required but no ID", null);
        return;
      }

      const banner = window.snapperShowApprovalBanner(element, toolName, approvalId);
      const approvalResult = await window.snapperPollApproval(approvalId);
      banner.remove();

      if (approvalResult.decision === "allow") return;

      window.snapperShowDenyOverlay(
        element,
        toolName,
        approvalResult.reason || "Approval denied",
        null
      );
    }
  };

  /**
   * Setup clipboard/paste monitoring for PII detection.
   * Intercepts paste events in capture phase, scans for PII,
   * and blocks paste if PII is detected (respects pii_blocking_mode).
   */
  window.snapperSetupClipboardMonitoring = function () {
    chrome.storage.local.get(["clipboard_monitoring", "pii_scanning", "pii_blocking_mode"], (settings) => {
      if (settings.clipboard_monitoring === false) return;
      if (settings.pii_scanning === false) return;

      const mode = settings.pii_blocking_mode || "warn";

      document.addEventListener("paste", (event) => {
        const text = event.clipboardData?.getData("text/plain");
        if (!text || text.length < 5) return;

        // Use the PII scanner if available
        if (typeof scanForPII !== "function") return;

        const findings = scanForPII(text);
        if (findings.length === 0) return;

        // Report paste event to background
        chrome.runtime.sendMessage({
          type: "report_paste",
          findings: findings.map((f) => f.type),
          source: document.location.hostname,
        });

        if (mode === "block") {
          event.preventDefault();
          event.stopPropagation();
          if (typeof showPIIWarning === "function") {
            showPIIWarning(findings, mode, () => {}, () => {});
          }
        } else {
          // Warn mode — show warning but don't block
          if (typeof showPIIWarning === "function") {
            showPIIWarning(
              findings,
              mode,
              () => { /* proceed — paste already happened */ },
              () => { /* cancel — too late, just warn */ }
            );
          }
        }
      }, true); // Capture phase
    });
  };

  console.log("[Snapper] Shared utilities loaded");
}
