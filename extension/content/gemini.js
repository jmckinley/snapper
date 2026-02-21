/**
 * Snapper Content Script — Gemini (gemini.google.com)
 *
 * Intercepts extension calls (Search, Workspace, Maps, YouTube),
 * code execution, and file analysis.
 * Uses shared.js for evaluation, overlays, and clipboard monitoring.
 */

(function () {
  "use strict";

  const SOURCE = "gemini";
  let enabled = true;

  chrome.storage.local.get(["gemini_enabled", "synced_blocked_services"], (result) => {
    enabled = result.gemini_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

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

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, extName, {}, "tool", SOURCE);
          }
        }

        // Detect code execution blocks
        const codeBlocks = node.querySelectorAll(
          '[class*="code-execution"], [data-testid*="code"], .code-block-execution'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.querySelector("code, pre")?.textContent || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "code_execution", { code: code.substring(0, 1000) }, "command", SOURCE);
          }
        }

        // Detect file analysis
        const fileBlocks = node.querySelectorAll(
          '[class*="file-chip"], [class*="attachment"], .uploaded-file'
        );
        for (const block of fileBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const fileName = block.textContent?.trim() || "unknown";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "file_analysis", { file: fileName }, "file_access", SOURCE);
          }
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

  console.log("[Snapper] Gemini content script loaded");
})();
