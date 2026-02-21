/**
 * Snapper Content Script — ChatGPT (chatgpt.com / chat.openai.com)
 *
 * Intercepts tool calls (Code Interpreter, web browsing, DALL-E, plugins)
 * via DOM observation and fetch monkey-patching.
 * Uses shared.js for evaluation, overlays, and clipboard monitoring.
 */

(function () {
  "use strict";

  const SOURCE = "chatgpt";
  let enabled = true;

  chrome.storage.local.get(["chatgpt_enabled", "synced_blocked_services"], (result) => {
    enabled = result.chatgpt_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect Code Interpreter output blocks
        const codeBlocks = node.querySelectorAll(
          '[data-testid*="code-interpreter"], .code-interpreter-output, [class*="sandbox"]'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.textContent || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "code_interpreter", { code }, "command", SOURCE);
          }
        }

        // Detect web browsing results
        const browseBlocks = node.querySelectorAll(
          '[data-testid*="browsing"], .browsing-result, [class*="browse"]'
        );
        for (const block of browseBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const url = block.querySelector("a")?.href || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "web_browse", { url }, "network", SOURCE);
          }
        }

        // Detect DALL-E generation
        const dalleBlocks = node.querySelectorAll(
          '[data-testid*="dalle"], .dalle-image, [class*="image-gen"]'
        );
        for (const block of dalleBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "dalle", {}, "tool", SOURCE);
          }
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  // ---- Fetch Interception ----

  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const [url, options] = args;

    if (
      typeof url === "string" &&
      url.includes("/backend-api/conversation") &&
      options?.method === "POST"
    ) {
      try {
        const body = JSON.parse(options.body);

        if (body.attachments && body.attachments.length > 0) {
          const fileNames = body.attachments.map((a) => a.name || "unknown");
          if (typeof window.snapperEvaluateToolCall === "function") {
            const result = await window.snapperEvaluateToolCall(
              "file_upload", { files: fileNames }, "file_access", SOURCE
            );

            if (result?.decision === "deny") {
              console.warn("[Snapper] File upload blocked:", result.reason);
              return new Response(JSON.stringify({ error: "Blocked by Snapper" }), {
                status: 403,
              });
            }
          }
        }
      } catch (e) {
        // Parse error — let it through
      }
    }

    return originalFetch.apply(this, args);
  };

  // ---- PII Scanning on Input ----

  function setupPIIScanning() {
    const textareaObserver = new MutationObserver(() => {
      const textarea = document.querySelector(
        'textarea[data-id="root"], #prompt-textarea, textarea[placeholder*="Message"]'
      );
      const sendButton = document.querySelector(
        'button[data-testid="send-button"], button[aria-label="Send"]'
      );

      if (textarea && sendButton && !textarea.dataset.snapperPii) {
        textarea.dataset.snapperPii = "true";
        if (typeof attachPIIScanner === "function") {
          attachPIIScanner(textarea, sendButton);
        }
      }
    });

    textareaObserver.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupPIIScanning);
  } else {
    setupPIIScanning();
  }

  // Setup clipboard monitoring
  if (typeof window.snapperSetupClipboardMonitoring === "function") {
    window.snapperSetupClipboardMonitoring();
  }

  console.log("[Snapper] ChatGPT content script loaded");
})();
