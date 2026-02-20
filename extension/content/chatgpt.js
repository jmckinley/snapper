/**
 * Snapper Content Script — ChatGPT (chatgpt.com / chat.openai.com)
 *
 * Intercepts tool calls (Code Interpreter, web browsing, DALL-E, plugins)
 * via DOM observation and fetch monkey-patching.
 */

(function () {
  "use strict";

  const SOURCE = "chatgpt";
  let enabled = true;

  // Check if extension is enabled for this site
  chrome.storage.local.get(["chatgpt_enabled"], (result) => {
    enabled = result.chatgpt_enabled !== false;
  });

  // Selector helper with fallback chains for robustness
  function $(selectors, root = document) {
    for (const sel of selectors) {
      try { const el = root.querySelector(sel); if (el) return el; } catch (e) { /* skip */ }
    }
    return null;
  }

  /**
   * Show deny overlay on a tool output element.
   */
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

  /**
   * Show approval waiting banner.
   */
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
        <div class="snapper-approval-note">Check Telegram or Snapper dashboard to approve.</div>
      </div>
    `;
    element.style.position = "relative";
    element.appendChild(banner);
    return banner;
  }

  /**
   * Evaluate a tool call via the background service worker.
   */
  async function evaluateToolCall(toolName, toolInput, requestType) {
    if (!enabled) return { decision: "allow", reason: "Extension disabled" };

    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        {
          type: "evaluate",
          toolName,
          toolInput,
          requestType,
          source: SOURCE,
        },
        resolve
      );
    });
  }

  /**
   * Poll for approval via background service worker.
   */
  async function pollApproval(approvalId) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        {
          type: "poll_approval",
          approvalId,
          timeout: 300000,
        },
        resolve
      );
    });
  }

  /**
   * Handle a detected tool call.
   */
  async function handleToolCall(element, toolName, toolInput, requestType) {
    const result = await evaluateToolCall(toolName, toolInput, requestType);

    if (result.decision === "allow") {
      return; // Normal behavior
    }

    if (result.decision === "deny") {
      showDenyOverlay(
        element,
        toolName,
        result.reason,
        result.matched_rule_name
      );
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

      if (approvalResult.decision === "allow") {
        // Approval granted — let it proceed
        return;
      }

      showDenyOverlay(
        element,
        toolName,
        approvalResult.reason || "Approval denied",
        null
      );
    }
  }

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
          handleToolCall(block, "code_interpreter", { code }, "command");
        }

        // Detect web browsing results
        const browseBlocks = node.querySelectorAll(
          '[data-testid*="browsing"], .browsing-result, [class*="browse"]'
        );
        for (const block of browseBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const url = block.querySelector("a")?.href || "";
          handleToolCall(block, "web_browse", { url }, "network");
        }

        // Detect DALL-E generation
        const dalleBlocks = node.querySelectorAll(
          '[data-testid*="dalle"], .dalle-image, [class*="image-gen"]'
        );
        for (const block of dalleBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          handleToolCall(block, "dalle", {}, "tool");
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

    // Intercept conversation API calls
    if (
      typeof url === "string" &&
      url.includes("/backend-api/conversation") &&
      options?.method === "POST"
    ) {
      try {
        const body = JSON.parse(options.body);

        // Check for file uploads
        if (body.attachments && body.attachments.length > 0) {
          const fileNames = body.attachments.map((a) => a.name || "unknown");
          const result = await evaluateToolCall(
            "file_upload",
            { files: fileNames },
            "file_access"
          );

          if (result.decision === "deny") {
            console.warn("[Snapper] File upload blocked:", result.reason);
            return new Response(JSON.stringify({ error: "Blocked by Snapper" }), {
              status: 403,
            });
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
        attachPIIScanner(textarea, sendButton);
      }
    });

    textareaObserver.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  // Initialize PII scanning after DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupPIIScanning);
  } else {
    setupPIIScanning();
  }

  console.log("[Snapper] ChatGPT content script loaded");
})();
