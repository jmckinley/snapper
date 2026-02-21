/**
 * Snapper Content Script — Claude.ai
 *
 * Intercepts tool_use content blocks, computer use actions,
 * artifact code execution, and file analysis.
 * Uses shared.js for evaluation, overlays, and clipboard monitoring.
 */

(function () {
  "use strict";

  const SOURCE = "claude";
  let enabled = true;

  chrome.storage.local.get(["claude_enabled", "synced_blocked_services"], (result) => {
    enabled = result.claude_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect tool_use blocks
        const toolBlocks = node.querySelectorAll(
          '[data-testid*="tool"], .tool-use-block, [class*="tool_use"], [class*="tool-result"]'
        );
        for (const block of toolBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const toolName = block.dataset.toolName || block.querySelector(".tool-name")?.textContent || "tool_use";
          const toolInput = {};

          try {
            const inputEl = block.querySelector(".tool-input, pre, code");
            if (inputEl) {
              Object.assign(toolInput, JSON.parse(inputEl.textContent));
            }
          } catch (e) {
            toolInput.raw = block.textContent?.substring(0, 500);
          }

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, toolName, toolInput, "tool", SOURCE);
          }
        }

        // Detect computer use actions
        const computerBlocks = node.querySelectorAll(
          '[class*="computer"], [data-testid*="computer"], [class*="screenshot"]'
        );
        for (const block of computerBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "computer_use", {}, "tool", SOURCE);
          }
        }

        // Detect artifact code execution
        const artifactBlocks = node.querySelectorAll(
          '[class*="artifact"], [data-testid*="artifact"], .code-artifact'
        );
        for (const block of artifactBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.querySelector("code, pre")?.textContent || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "artifact_execute", { code: code.substring(0, 1000) }, "command", SOURCE);
          }
        }

        // Detect file analysis
        const fileBlocks = node.querySelectorAll(
          '[class*="file-block"], [data-testid*="file"], .attachment-preview'
        );
        for (const block of fileBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const fileName = block.querySelector(".file-name")?.textContent || "unknown";
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
        '[contenteditable="true"].ProseMirror, textarea[placeholder*="Reply"], div[contenteditable="true"]'
      );
      const sendButton = document.querySelector(
        'button[aria-label="Send Message"], button[data-testid="send-button"]'
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

  console.log("[Snapper] Claude.ai content script loaded");
})();
