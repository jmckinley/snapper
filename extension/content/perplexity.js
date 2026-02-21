/**
 * Snapper Content Script — Perplexity (perplexity.ai)
 *
 * Intercepts tool calls: Pro Search, web search, file analysis.
 * Uses shared.js utilities for evaluation and overlays.
 */

(function () {
  "use strict";

  const SOURCE = "perplexity";
  let enabled = true;

  chrome.storage.local.get(["perplexity_enabled", "synced_blocked_services"], (result) => {
    enabled = result.perplexity_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Pro Search / web search sources
        const searchBlocks = node.querySelectorAll(
          '[class*="source"], [class*="citation"], [data-testid*="source"]'
        );
        for (const block of searchBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const url = block.querySelector("a")?.href || "";
          const text = block.textContent?.substring(0, 200) || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(
              block, "pro_search", { url, query: text }, "network", SOURCE
            );
          }
        }

        // File analysis blocks
        const fileBlocks = node.querySelectorAll(
          '[class*="file"], [class*="upload"], [class*="attachment"]'
        );
        for (const block of fileBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const fileName = block.textContent?.trim() || "unknown";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(
              block, "file_analysis", { file: fileName }, "file_access", SOURCE
            );
          }
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // ---- PII Scanning ----

  function setupPIIScanning() {
    const obs = new MutationObserver(() => {
      const textarea = document.querySelector(
        'textarea[placeholder*="Ask"], textarea, [contenteditable="true"]'
      );
      const sendBtn = document.querySelector(
        'button[aria-label*="Submit"], button[aria-label*="send"], button[type="submit"]'
      );

      if (textarea && sendBtn && !textarea.dataset.snapperPii) {
        textarea.dataset.snapperPii = "true";
        if (typeof attachPIIScanner === "function") {
          attachPIIScanner(textarea, sendBtn);
        }
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupPIIScanning);
  } else {
    setupPIIScanning();
  }

  if (typeof window.snapperSetupClipboardMonitoring === "function") {
    window.snapperSetupClipboardMonitoring();
  }

  console.log("[Snapper] Perplexity content script loaded");
})();
