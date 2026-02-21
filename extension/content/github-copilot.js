/**
 * Snapper Content Script — GitHub Copilot Web (github.com/copilot)
 *
 * Intercepts tool calls: code generation, workspace context access.
 * Uses shared.js utilities for evaluation and overlays.
 */

(function () {
  "use strict";

  const SOURCE = "github_copilot";
  let enabled = true;

  // Only activate on the Copilot chat page
  if (!window.location.pathname.startsWith("/copilot")) return;

  chrome.storage.local.get(["github_copilot_enabled", "synced_blocked_services"], (result) => {
    enabled = result.github_copilot_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Code generation blocks
        const codeBlocks = node.querySelectorAll(
          'pre code, [class*="highlight"], [class*="code-block"], .markdown-body pre'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.textContent || "";
          if (code.length > 20 && typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(
              block, "code_generation", { code: code.substring(0, 1000) }, "command", SOURCE
            );
          }
        }

        // Workspace context references
        const contextBlocks = node.querySelectorAll(
          '[class*="context"], [class*="reference"], [data-testid*="context"]'
        );
        for (const block of contextBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const ref = block.textContent?.trim() || "";
          if (ref && typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(
              block, "workspace_context", { reference: ref }, "file_access", SOURCE
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
        'textarea[placeholder*="Ask Copilot"], textarea[name*="chat"], textarea'
      );
      const sendBtn = document.querySelector(
        'button[aria-label*="Send"], button[type="submit"], button[data-testid*="send"]'
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

  console.log("[Snapper] GitHub Copilot Web content script loaded");
})();
