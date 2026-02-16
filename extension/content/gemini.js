/**
 * Snapper Content Script — Gemini (gemini.google.com)
 *
 * Intercepts extension calls (Search, Workspace, Maps, YouTube),
 * code execution, and file analysis.
 */

(function () {
  "use strict";

  const SOURCE = "gemini";
  let enabled = true;

  chrome.storage.local.get(["gemini_enabled"], (result) => {
    enabled = result.gemini_enabled !== false;
  });

  function showDenyOverlay(element, toolName, reason, ruleName) {
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
  }

  function showApprovalBanner(element, toolName, approvalId) {
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
        <div class="snapper-approval-note">Check Telegram or Snapper dashboard.</div>
      </div>
    `;
    element.style.position = "relative";
    element.appendChild(banner);
    return banner;
  }

  async function evaluateToolCall(toolName, toolInput, requestType) {
    if (!enabled) return { decision: "allow", reason: "Extension disabled" };

    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "evaluate", toolName, toolInput, requestType, source: SOURCE },
        resolve
      );
    });
  }

  async function pollApproval(approvalId) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "poll_approval", approvalId, timeout: 300000 },
        resolve
      );
    });
  }

  async function handleToolCall(element, toolName, toolInput, requestType) {
    const result = await evaluateToolCall(toolName, toolInput, requestType);

    if (result.decision === "allow") return;

    if (result.decision === "deny") {
      showDenyOverlay(element, toolName, result.reason, result.matched_rule_name);
      return;
    }

    if (result.decision === "require_approval") {
      const approvalId = result.approval_request_id;
      if (!approvalId) {
        showDenyOverlay(element, toolName, "Approval required but no ID", null);
        return;
      }

      const banner = showApprovalBanner(element, toolName, approvalId);
      const approvalResult = await pollApproval(approvalId);
      banner.remove();

      if (approvalResult.decision !== "allow") {
        showDenyOverlay(element, toolName, approvalResult.reason || "Denied", null);
      }
    }
  }

  // ---- DOM Observation ----

  // Gemini extension name mapping
  const EXTENSION_TOOLS = {
    "google_search": "tool",
    "google_maps": "tool",
    "youtube": "tool",
    "google_flights": "tool",
    "google_hotels": "tool",
    "workspace": "tool",
  };

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect extension calls (Google Search, Maps, etc.)
        const extensionBlocks = node.querySelectorAll(
          '[class*="extension"], [data-extension-name], .extension-output, [class*="grounding"]'
        );
        for (const block of extensionBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const extName = block.dataset.extensionName ||
            block.querySelector(".extension-name")?.textContent ||
            "extension";

          handleToolCall(block, extName, {}, "tool");
        }

        // Detect code execution blocks
        const codeBlocks = node.querySelectorAll(
          '[class*="code-execution"], [data-testid*="code"], .code-block-execution'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.querySelector("code, pre")?.textContent || "";
          handleToolCall(block, "code_execution", { code: code.substring(0, 1000) }, "command");
        }

        // Detect file analysis
        const fileBlocks = node.querySelectorAll(
          '[class*="file-chip"], [class*="attachment"], .uploaded-file'
        );
        for (const block of fileBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const fileName = block.textContent?.trim() || "unknown";
          handleToolCall(block, "file_analysis", { file: fileName }, "file_access");
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // ---- PII Scanning ----

  function setupPIIScanning() {
    const textareaObserver = new MutationObserver(() => {
      const editor = document.querySelector(
        '.ql-editor[contenteditable="true"], [contenteditable="true"][aria-label*="prompt"], textarea[aria-label*="prompt"]'
      );
      const sendButton = document.querySelector(
        'button[aria-label="Send message"], button[data-testid="send-button"], .send-button'
      );

      if (editor && sendButton && !editor.dataset.snapperPii) {
        editor.dataset.snapperPii = "true";
        attachPIIScanner(editor, sendButton);
      }
    });

    textareaObserver.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupPIIScanning);
  } else {
    setupPIIScanning();
  }

  console.log("[Snapper] Gemini content script loaded");
})();
