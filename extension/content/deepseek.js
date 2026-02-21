/**
 * Snapper Content Script — DeepSeek (chat.deepseek.com)
 *
 * Intercepts tool calls: code execution, web search, file upload.
 * Uses shared.js utilities for evaluation and overlays.
 */

(function () {
  "use strict";

  const SOURCE = "deepseek";
  let enabled = true;

  chrome.storage.local.get(["deepseek_enabled", "synced_blocked_services"], (result) => {
    enabled = result.deepseek_enabled !== false;
    if ((result.synced_blocked_services || []).includes(SOURCE)) enabled = false;
  });

  // ---- DOM Observation ----

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Code execution output blocks
        const codeBlocks = node.querySelectorAll(
          '[class*="code-block"], [class*="sandbox"], [data-testid*="code"]'
        );
        for (const block of codeBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.textContent || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "code_execution", { code }, "command", SOURCE);
          }
        }

        // Web search results
        const searchBlocks = node.querySelectorAll(
          '[class*="search-result"], [class*="web-search"], [data-testid*="search"]'
        );
        for (const block of searchBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const query = block.textContent?.substring(0, 200) || "";
          if (typeof window.snapperHandleToolCall === "function") {
            window.snapperHandleToolCall(block, "web_search", { query }, "network", SOURCE);
          }
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // ---- Fetch Interception ----

  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const [url, options] = args;

    if (
      typeof url === "string" &&
      url.includes("/api/") &&
      options?.method === "POST"
    ) {
      try {
        const body = JSON.parse(options.body);
        if (body.attachments?.length > 0 || body.files?.length > 0) {
          const files = (body.attachments || body.files || []).map((a) => a.name || "unknown");
          if (typeof window.snapperEvaluateToolCall === "function") {
            const result = await window.snapperEvaluateToolCall(
              "file_upload", { files }, "file_access", SOURCE
            );
            if (result?.decision === "deny") {
              return new Response(JSON.stringify({ error: "Blocked by Snapper" }), { status: 403 });
            }
          }
        }
      } catch (e) { /* parse error — let through */ }
    }

    return originalFetch.apply(this, args);
  };

  // ---- PII Scanning ----

  function setupPIIScanning() {
    const obs = new MutationObserver(() => {
      const textarea = document.querySelector('textarea, [contenteditable="true"]');
      const sendBtn = document.querySelector('button[class*="send"], button[aria-label*="Send"]');

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

  console.log("[Snapper] DeepSeek content script loaded");
})();
