/**
 * Snapper Content Script — Generic AI Service (Tier 2)
 *
 * Works on any AI service without DOM-specific selectors:
 * - Input detection via textarea, contenteditable, textbox
 * - Submit detection via button click, Enter key, form submit
 * - File upload blocking
 * - PII scanning before submission
 * - Visit reporting for shadow AI tracking
 */

(function () {
  "use strict";

  // Determine source from current hostname
  const hostname = window.location.hostname.replace("www.", "");
  let SOURCE = "generic_ai";

  // Try to match from service registry if loaded
  if (typeof SERVICE_REGISTRY !== "undefined") {
    const match = SERVICE_REGISTRY.find((s) =>
      s.domains.some((d) => hostname.includes(d.replace("www.", "")))
    );
    if (match) SOURCE = match.source;
  }

  let enabled = true;
  const storageKey = `${SOURCE}_enabled`;

  chrome.storage.local.get([storageKey, "shadow_ai_tracking", "synced_blocked_services"], (result) => {
    enabled = result[storageKey] !== false;

    // Check if this service is blocked by server config
    if ((result.synced_blocked_services || []).includes(SOURCE)) {
      enabled = false;
    }

    // Report visit for shadow AI tracking
    if (result.shadow_ai_tracking !== false) {
      chrome.runtime.sendMessage({
        type: "report_visit",
        source: SOURCE,
        hostname,
        url: window.location.href,
      });
    }
  });

  // ---- Input Detection ----

  const INPUT_SELECTORS = [
    "textarea",
    '[contenteditable="true"]',
    '[role="textbox"]',
    '[data-testid*="input"]',
    '[data-testid*="prompt"]',
  ];

  const SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'button[aria-label*="Send"]',
    'button[aria-label*="send"]',
    'button[aria-label*="Submit"]',
    'button[data-testid*="send"]',
    'button[data-testid*="submit"]',
  ];

  /**
   * Find the active input element on the page.
   */
  function findInput() {
    return window.snapper$ ? window.snapper$(INPUT_SELECTORS) : document.querySelector(INPUT_SELECTORS[0]);
  }

  /**
   * Find the submit button near the input.
   */
  function findSubmitButton() {
    return window.snapper$ ? window.snapper$(SUBMIT_SELECTORS) : document.querySelector(SUBMIT_SELECTORS[0]);
  }

  /**
   * Get text from an input element (textarea or contenteditable).
   */
  function getInputText(el) {
    if (!el) return "";
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return el.value;
    return el.innerText || el.textContent || "";
  }

  // ---- Submit Interception ----

  let piiScanAttached = false;

  function attachSubmitInterception() {
    if (!enabled || piiScanAttached) return;

    const input = findInput();
    const submitBtn = findSubmitButton();

    if (input && submitBtn && !submitBtn.dataset.snapperGeneric) {
      submitBtn.dataset.snapperGeneric = "true";
      piiScanAttached = true;

      // PII scanning via the shared pii-scanner.js
      if (typeof attachPIIScanner === "function") {
        attachPIIScanner(input, submitBtn);
      }
    }
  }

  // ---- File Upload Blocking ----

  function interceptFileUploads() {
    // Intercept file input elements
    document.addEventListener("change", async (event) => {
      if (!enabled) return;
      const target = event.target;
      if (target.type !== "file") return;

      const files = Array.from(target.files || []).map((f) => f.name);
      if (files.length === 0) return;

      if (typeof window.snapperEvaluateToolCall !== "function") return;

      const result = await window.snapperEvaluateToolCall(
        "file_upload",
        { files, source: SOURCE },
        "file_access",
        SOURCE
      );

      if (result && result.decision === "deny") {
        event.preventDefault();
        target.value = "";
        console.warn("[Snapper] File upload blocked:", result.reason);
      }
    }, true);

    // Intercept drag-and-drop file uploads
    document.addEventListener("drop", async (event) => {
      if (!enabled) return;
      const files = Array.from(event.dataTransfer?.files || []).map((f) => f.name);
      if (files.length === 0) return;

      if (typeof window.snapperEvaluateToolCall !== "function") return;

      const result = await window.snapperEvaluateToolCall(
        "file_upload",
        { files, source: SOURCE },
        "file_access",
        SOURCE
      );

      if (result && result.decision === "deny") {
        event.preventDefault();
        event.stopPropagation();
        console.warn("[Snapper] File drop blocked:", result.reason);
      }
    }, true);
  }

  // ---- Initialization ----

  function initialize() {
    // Attach submit interception
    attachSubmitInterception();
    interceptFileUploads();

    // Setup clipboard monitoring
    if (typeof window.snapperSetupClipboardMonitoring === "function") {
      window.snapperSetupClipboardMonitoring();
    }

    // Re-check for input elements periodically (SPA navigation)
    const observer = new MutationObserver(() => {
      if (!piiScanAttached) attachSubmitInterception();
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize);
  } else {
    initialize();
  }

  console.log(`[Snapper] Generic AI content script loaded for ${SOURCE} (${hostname})`);
})();
