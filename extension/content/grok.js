/**
 * Snapper Content Script — Grok (grok.com)
 *
 * Intercepts tool calls (search, code generation, image generation)
 * via DOM observation and fetch interception.
 * Uses shared.js for evaluation, overlays, and clipboard monitoring.
 */

(function () {
  "use strict";

  const SOURCE = "grok";
  let enabled = true;

  chrome.storage.local.get(["grok_enabled", "synced_blocked_services"], (result) => {
    enabled = result.grok_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect search/web results
        const searchBlocks = node.querySelectorAll(
          '[class*="search"], [data-testid*="web-result"], [class*="citation"], [class*="source"]'
        );
        for (const block of searchBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "web_search", {}, "tool", SOURCE);
          }
        }

        // Detect code blocks
        const codeBlocks = node.querySelectorAll(
          'pre code, [class*="code-block"], [data-testid*="code"], [class*="hljs"]'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.textContent?.substring(0, 1000) || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "code_generation", { code }, "command", SOURCE);
          }
        }

        // Detect image generation
        const imageBlocks = node.querySelectorAll(
          '[class*="image-gen"], [data-testid*="image"], img[class*="generated"], [class*="flux"]'
        );
        for (const block of imageBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "image_generation", {}, "tool", SOURCE);
          }
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // ---- Fetch Interception ----

  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const [url] = args;
    const urlStr = typeof url === "string" ? url : url?.url || "";

    if (enabled && (urlStr.includes("/rest/app-chat/") || urlStr.includes("/api/"))) {
      // Monitor for tool-use API calls
    }

    return originalFetch.apply(this, args);
  };

  // ---- PII Scanning ----

  function setupPIIScanning() {
    const textareaObserver = new MutationObserver(() => {
      const editor = document.querySelector(
        'textarea[placeholder*="Ask"], textarea[placeholder*="message"], textarea[aria-label*="message"], [contenteditable="true"][role="textbox"], textarea'
      );
      const sendButton = document.querySelector(
        'button[aria-label="Send"], button[type="submit"], button[data-testid="send"], button[class*="send"]'
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

  if (typeof window.snapperSetupClipboardMonitoring === "function") {
    window.snapperSetupClipboardMonitoring();
  }

  console.log("[Snapper] Grok content script loaded");
})();
