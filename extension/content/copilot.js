/**
 * Snapper Content Script — Microsoft Copilot (copilot.microsoft.com)
 *
 * Intercepts tool calls (search, code generation, image creation)
 * via DOM observation and fetch interception.
 */

(function () {
  "use strict";

  const SOURCE = "copilot";
  let enabled = true;

  chrome.storage.local.get(["copilot_enabled"], (result) => {
    enabled = result.copilot_enabled !== false;
  });

  // --- Selector helper with fallback chains ---

  function $(selectors, root = document) {
    for (const sel of selectors) {
      try {
        const el = root.querySelector(sel);
        if (el) return el;
      } catch (e) {
        // Invalid selector, skip
      }
    }
    return null;
  }

  function $$(selectors, root = document) {
    for (const sel of selectors) {
      try {
        const els = root.querySelectorAll(sel);
        if (els.length > 0) return Array.from(els);
      } catch (e) {
        // Invalid selector, skip
      }
    }
    return [];
  }

  // --- Overlays ---

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

  // --- Evaluate & poll ---

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

  // --- DOM Observation ---

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect search/grounding results
        const searchBlocks = $$(
          [
            '[class*="search-result"]',
            '[data-testid*="search"]',
            '[class*="grounding"]',
            '[class*="citation"]',
            '[class*="reference-list"]',
          ],
          node
        );
        for (const block of searchBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";
          handleToolCall(block, "web_search", {}, "tool");
        }

        // Detect code generation blocks
        const codeBlocks = $$(
          [
            '[class*="code-block"]',
            'pre code',
            '[data-testid*="code"]',
            '[class*="CodeBlock"]',
          ],
          node
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";
          const code = block.textContent?.substring(0, 1000) || "";
          handleToolCall(block, "code_generation", { code }, "command");
        }

        // Detect image generation
        const imageBlocks = $$(
          [
            '[class*="image-creator"]',
            '[class*="dalle"]',
            '[data-testid*="image"]',
            'img[class*="generated"]',
          ],
          node
        );
        for (const block of imageBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";
          handleToolCall(block, "image_generation", {}, "tool");
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // --- Fetch interception for API calls ---

  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const [url] = args;
    const urlStr = typeof url === "string" ? url : url?.url || "";

    if (enabled && urlStr.includes("/api/") && urlStr.includes("copilot")) {
      // Let the request go through but monitor for tool calls
    }

    return originalFetch.apply(this, args);
  };

  // --- PII Scanning ---

  function setupPIIScanning() {
    const textareaObserver = new MutationObserver(() => {
      const editor = $(
        [
          'textarea[id="searchbox"]',
          '#searchbox',
          'textarea[aria-label*="message"]',
          'textarea[placeholder*="message"]',
          '[contenteditable="true"][role="textbox"]',
          'textarea',
        ]
      );
      const sendButton = $(
        [
          'button[aria-label="Submit"]',
          'button[aria-label="Send"]',
          'button[type="submit"]',
          'button[data-testid="submit"]',
          'button[class*="submit"]',
        ]
      );

      if (editor && sendButton && !editor.dataset.snapperPii) {
        editor.dataset.snapperPii = "true";
        if (typeof attachPIIScanner === "function") {
          attachPIIScanner(editor, sendButton);
        }
      }
    });

    textareaObserver.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupPIIScanning);
  } else {
    setupPIIScanning();
  }

  console.log("[Snapper] Copilot content script loaded");
})();
