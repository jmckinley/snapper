/**
 * Snapper Content Script — Claude.ai
 *
 * Intercepts tool_use content blocks, computer use actions,
 * artifact code execution, and file analysis.
 */

(function () {
  "use strict";

  const SOURCE = "claude";
  let enabled = true;

  chrome.storage.local.get(["claude_enabled"], (result) => {
    enabled = result.claude_enabled !== false;
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

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Detect tool_use blocks (Claude renders these as special UI elements)
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

          handleToolCall(block, toolName, toolInput, "tool");
        }

        // Detect computer use actions
        const computerBlocks = node.querySelectorAll(
          '[class*="computer"], [data-testid*="computer"], [class*="screenshot"]'
        );
        for (const block of computerBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          handleToolCall(block, "computer_use", {}, "tool");
        }

        // Detect artifact code execution
        const artifactBlocks = node.querySelectorAll(
          '[class*="artifact"], [data-testid*="artifact"], .code-artifact'
        );
        for (const block of artifactBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const code = block.querySelector("code, pre")?.textContent || "";
          handleToolCall(block, "artifact_execute", { code: code.substring(0, 1000) }, "command");
        }

        // Detect file analysis
        const fileBlocks = node.querySelectorAll(
          '[class*="file-block"], [data-testid*="file"], .attachment-preview'
        );
        for (const block of fileBlocks) {
          if (block.dataset.snapperChecked) continue;
          block.dataset.snapperChecked = "true";

          const fileName = block.querySelector(".file-name")?.textContent || "unknown";
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
        '[contenteditable="true"].ProseMirror, textarea[placeholder*="Reply"], div[contenteditable="true"]'
      );
      const sendButton = document.querySelector(
        'button[aria-label="Send Message"], button[data-testid="send-button"]'
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

  console.log("[Snapper] Claude.ai content script loaded");
})();
