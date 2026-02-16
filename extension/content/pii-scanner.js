/**
 * Snapper PII Scanner — Shared content script for detecting PII in user input.
 *
 * Scans textarea content before submission to AI services.
 * Ported from Snapper's Python PII patterns (app/services/rule_engine.py).
 */

const SNAPPER_PII_PATTERNS = [
  // Credit cards
  { name: "credit_card_visa", pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, label: "Visa card number" },
  { name: "credit_card_mc", pattern: /\b5[1-5][0-9]{14}\b/g, label: "Mastercard number" },
  { name: "credit_card_amex", pattern: /\b3[47][0-9]{13}\b/g, label: "Amex card number" },
  { name: "credit_card_discover", pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/g, label: "Discover card number" },

  // SSN
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "Social Security Number" },
  { name: "ssn_no_dash", pattern: /\b\d{9}\b/g, label: "SSN (no dashes)", minContext: true },

  // Phone numbers
  { name: "phone_us", pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, label: "US phone number" },
  { name: "phone_intl", pattern: /\b\+\d{1,3}[-.\s]?\d{4,14}\b/g, label: "International phone number" },

  // Email
  { name: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, label: "Email address" },

  // IP addresses
  { name: "ipv4", pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, label: "IPv4 address" },

  // US passport
  { name: "passport_us", pattern: /\b[A-Z]\d{8}\b/g, label: "US passport number" },

  // Bank account / routing
  { name: "routing_number", pattern: /\b\d{9}\b/g, label: "Bank routing number", minContext: true },
  { name: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b/g, label: "IBAN" },

  // AWS keys
  { name: "aws_access_key", pattern: /\bAKIA[0-9A-Z]{16}\b/g, label: "AWS Access Key" },
  { name: "aws_secret_key", pattern: /\b[A-Za-z0-9/+=]{40}\b/g, label: "Possible AWS Secret Key", minContext: true },

  // API keys / tokens
  { name: "generic_api_key", pattern: /\b(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret[_-]?key)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, label: "API key/token" },
  { name: "bearer_token", pattern: /\bBearer\s+[A-Za-z0-9_\-\.]{20,}/g, label: "Bearer token" },

  // Private keys
  { name: "private_key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, label: "Private key" },

  // Snapper vault tokens (should use placeholders, not raw data)
  { name: "vault_token", pattern: /\{\{SNAPPER_VAULT:[a-f0-9]{8,32}\}\}/g, label: "Snapper vault token" },

  // Date of birth patterns
  { name: "dob", pattern: /\b(?:DOB|date of birth|born on|birthday)\s*[:\-]?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/gi, label: "Date of birth" },

  // Driver's license (US format varies by state)
  { name: "drivers_license", pattern: /\b(?:DL|driver'?s?\s*lic(?:ense)?)\s*[:#]?\s*[A-Z0-9]{5,15}\b/gi, label: "Driver's license" },

  // Medical record numbers
  { name: "mrn", pattern: /\b(?:MRN|medical record)\s*[:#]?\s*[A-Z0-9]{6,12}\b/gi, label: "Medical record number" },
];

/**
 * Scan text for PII patterns.
 * @param {string} text - Text to scan.
 * @returns {Array<{name: string, label: string, matches: string[]}>} Detected PII.
 */
function scanForPII(text) {
  if (!text || text.length < 5) return [];

  const findings = [];

  for (const rule of SNAPPER_PII_PATTERNS) {
    // Skip patterns that need context unless text is long enough
    if (rule.minContext && text.length < 50) continue;

    // Reset regex lastIndex
    rule.pattern.lastIndex = 0;
    const matches = [];
    let match;

    while ((match = rule.pattern.exec(text)) !== null) {
      matches.push(match[0]);
    }

    if (matches.length > 0) {
      findings.push({
        name: rule.name,
        label: rule.label,
        matches: matches.slice(0, 5), // Limit to 5 per type
      });
    }
  }

  return findings;
}

/**
 * Show PII warning modal before user submits input.
 * @param {Array} findings - PII scan results.
 * @param {Function} onProceed - Called if user chooses to proceed.
 * @param {Function} onCancel - Called if user cancels.
 */
function showPIIWarning(findings, onProceed, onCancel) {
  // Remove existing warning if any
  const existing = document.getElementById("snapper-pii-warning");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "snapper-pii-warning";
  overlay.className = "snapper-overlay snapper-overlay-warning";

  const findingsList = findings
    .map(
      (f) =>
        `<div class="snapper-finding">
          <strong>${f.label}</strong>: ${f.matches.length} found
          <span class="snapper-finding-preview">(${f.matches[0].substring(0, 8)}...)</span>
        </div>`
    )
    .join("");

  overlay.innerHTML = `
    <div class="snapper-modal">
      <div class="snapper-modal-header snapper-warning">
        <span class="snapper-icon">&#9888;</span>
        <span>Snapper: PII Detected in Input</span>
      </div>
      <div class="snapper-modal-body">
        <p>The following sensitive data was detected in your message:</p>
        ${findingsList}
        <p class="snapper-modal-note">This data will be sent to the AI service. Consider using Snapper vault tokens instead.</p>
      </div>
      <div class="snapper-modal-actions">
        <button id="snapper-pii-cancel" class="snapper-btn snapper-btn-secondary">Cancel</button>
        <button id="snapper-pii-proceed" class="snapper-btn snapper-btn-warning">Send Anyway</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("snapper-pii-cancel").addEventListener("click", () => {
    overlay.remove();
    if (onCancel) onCancel();
  });

  document.getElementById("snapper-pii-proceed").addEventListener("click", () => {
    overlay.remove();
    if (onProceed) onProceed();
  });
}

/**
 * Attach PII scanning to a textarea or contenteditable element.
 * @param {HTMLElement} element - Input element to monitor.
 * @param {HTMLElement} submitButton - Submit button to intercept.
 */
function attachPIIScanner(element, submitButton) {
  if (!submitButton || !element) return;

  const originalClick = submitButton.onclick;

  submitButton.addEventListener(
    "click",
    (e) => {
      const text =
        element.value || element.textContent || element.innerText || "";
      const findings = scanForPII(text);

      if (findings.length > 0) {
        e.preventDefault();
        e.stopPropagation();

        showPIIWarning(
          findings,
          () => {
            // User chose to proceed
            if (originalClick) originalClick.call(submitButton, e);
            else submitButton.click();
          },
          null
        );
      }
    },
    true
  );
}

// Export for testing
if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanForPII, SNAPPER_PII_PATTERNS, showPIIWarning };
}
