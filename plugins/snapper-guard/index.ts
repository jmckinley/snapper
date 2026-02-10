/**
 * Snapper Guard — OpenClaw plugin for PII vault token resolution
 * and security policy enforcement.
 *
 * Intercepts browser (and other sensitive) tool calls, sends them to
 * Snapper's evaluate endpoint, and:
 *   - Auto mode: resolves vault tokens inline and returns modified params
 *   - Protected mode: blocks the tool call until human approves via Telegram,
 *     then resolves tokens and returns modified params
 *   - Deny: blocks the tool call entirely
 */

const VAULT_TOKEN_RE = /\{\{SNAPPER_VAULT:[a-f0-9]{8,32}\}\}/g;
const VAULT_LABEL_RE = /\bvault:[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,62}[A-Za-z0-9])?\b/gi;

// Tools that should be evaluated by Snapper
const EVALUATED_TOOLS = new Set(["browser", "exec", "bash", "write"]);

// --------------------------------------------------------------------------
// Types matching Snapper's REST API
// --------------------------------------------------------------------------

interface EvaluateRequest {
  agent_id: string;
  request_type: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  command?: string;
}

interface EvaluateResponse {
  decision: "allow" | "deny" | "require_approval";
  reason: string;
  matched_rule_id?: string;
  matched_rule_name?: string;
  approval_request_id?: string;
  approval_timeout_seconds?: number;
  resolved_data?: Record<string, ResolvedToken>;
}

interface ResolvedToken {
  value: string;
  category: string;
  label: string;
  masked_value: string;
}

interface ApprovalStatusResponse {
  id: string;
  status: "pending" | "approved" | "denied" | "expired";
  reason?: string;
  wait_seconds?: number;
  resolved_data?: Record<string, ResolvedToken>;
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function containsVaultTokens(obj: unknown): boolean {
  const json = JSON.stringify(obj);
  VAULT_TOKEN_RE.lastIndex = 0;
  return VAULT_TOKEN_RE.test(json);
}

function containsVaultLabels(obj: unknown): boolean {
  const json = JSON.stringify(obj);
  VAULT_LABEL_RE.lastIndex = 0;
  return VAULT_LABEL_RE.test(json);
}

/**
 * Deep-replace vault tokens in a params object with resolved values.
 */
function replaceTokensInParams(
  params: Record<string, unknown>,
  resolved: Record<string, ResolvedToken>,
): Record<string, unknown> {
  const json = JSON.stringify(params);
  let result = json;
  for (const [token, data] of Object.entries(resolved)) {
    // Escape for use in JSON string (the token is already inside a JSON string)
    result = result.split(token).join(data.value);
  }
  return JSON.parse(result) as Record<string, unknown>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --------------------------------------------------------------------------
// Plugin entry point
// --------------------------------------------------------------------------

export default function register(api: any) {
  const cfg = (api.pluginConfig ?? {}) as {
    snapperUrl?: string;
    agentId?: string;
    apiKey?: string;
    approvalTimeoutMs?: number;
    pollIntervalMs?: number;
  };

  const snapperUrl = (cfg.snapperUrl ?? "http://127.0.0.1:8000").replace(
    /\/$/,
    "",
  );
  const agentId = cfg.agentId ?? "openclaw-main";
  const apiKey = cfg.apiKey ?? "";
  const approvalTimeoutMs = cfg.approvalTimeoutMs ?? 300_000; // 5 min
  const pollIntervalMs = cfg.pollIntervalMs ?? 5_000; // 5 sec

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  // Track last navigated URL so we can include it for non-navigate browser actions
  let lastPageUrl: string | null = null;

  api.logger.info(
    `snapper-guard: registered (snapper=${snapperUrl}, agent=${agentId})`,
  );

  // -----------------------------------------------------------------------
  // Call Snapper evaluate endpoint
  // -----------------------------------------------------------------------

  async function evaluate(
    toolName: string,
    params: Record<string, unknown>,
  ): Promise<EvaluateResponse> {
    const body: EvaluateRequest = {
      agent_id: agentId,
      request_type: "browser_action",
      tool_name: toolName,
      tool_input: params,
    };

    const res = await fetch(`${snapperUrl}/api/v1/rules/evaluate`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`Snapper evaluate returned ${res.status}: ${await res.text()}`);
    }

    return (await res.json()) as EvaluateResponse;
  }

  // -----------------------------------------------------------------------
  // Poll for approval decision
  // -----------------------------------------------------------------------

  async function waitForApproval(
    approvalId: string,
    timeoutMs: number,
  ): Promise<ApprovalStatusResponse> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const res = await fetch(
        `${snapperUrl}/api/v1/approvals/${approvalId}/status`,
        { headers },
      );

      if (!res.ok) {
        throw new Error(`Approval status returned ${res.status}`);
      }

      const status = (await res.json()) as ApprovalStatusResponse;

      if (status.status !== "pending") {
        return status;
      }

      // Wait before next poll
      const waitMs = Math.min(
        (status.wait_seconds ?? 5) * 1000,
        pollIntervalMs,
      );
      await sleep(waitMs);
    }

    return {
      id: approvalId,
      status: "expired",
      reason: "Timed out waiting for approval",
    };
  }

  // -----------------------------------------------------------------------
  // before_tool_call hook
  // -----------------------------------------------------------------------

  api.on(
    "before_tool_call",
    async (
      event: { toolName: string; params: Record<string, unknown> },
      ctx: { agentId?: string; sessionKey?: string; toolName: string },
    ) => {
      const { toolName, params } = event;

      // Only evaluate tools in our watch list
      if (!EVALUATED_TOOLS.has(toolName)) {
        return;
      }

      // Track the last navigated URL for browser actions
      if (
        toolName === "browser" &&
        params.action === "navigate" &&
        typeof params.url === "string"
      ) {
        lastPageUrl = params.url;
      }

      // Quick check: if no vault tokens/labels and not a browser tool, skip
      const hasTokens = containsVaultTokens(params);
      const hasLabels = containsVaultLabels(params);
      if (!hasTokens && !hasLabels && toolName !== "browser") {
        return;
      }

      // Inject last known page URL for non-navigate browser actions
      const toolInput =
        toolName === "browser" &&
        params.action !== "navigate" &&
        lastPageUrl &&
        !params.page_url
          ? { ...params, page_url: lastPageUrl }
          : params;

      // Call Snapper evaluate endpoint
      let evalResult: EvaluateResponse;
      try {
        evalResult = await evaluate(toolName, toolInput);
      } catch (err) {
        // Fail-open: if Snapper is unreachable, allow the call
        api.logger.warn(
          `snapper-guard: Snapper unreachable, allowing ${toolName}: ${err}`,
        );
        return;
      }

      api.logger.info(
        `snapper-guard: ${toolName} → ${evalResult.decision} (${evalResult.reason})`,
      );

      // ------ DENY ------
      if (evalResult.decision === "deny") {
        return {
          block: true,
          blockReason: `Blocked by Snapper: ${evalResult.reason}`,
        };
      }

      // ------ ALLOW (auto mode with resolved tokens) ------
      if (evalResult.decision === "allow") {
        if (evalResult.resolved_data && Object.keys(evalResult.resolved_data).length > 0) {
          const newParams = replaceTokensInParams(params, evalResult.resolved_data);
          api.logger.info(
            `snapper-guard: resolved ${Object.keys(evalResult.resolved_data).length} vault token(s) for ${toolName}`,
          );
          return { params: newParams };
        }
        // No tokens to resolve, allow as-is
        return;
      }

      // ------ REQUIRE_APPROVAL ------
      if (evalResult.decision === "require_approval") {
        if (!evalResult.approval_request_id) {
          return {
            block: true,
            blockReason: "Snapper requires approval but no approval ID was returned",
          };
        }

        api.logger.info(
          `snapper-guard: waiting for human approval (${evalResult.approval_request_id})...`,
        );

        let approvalResult: ApprovalStatusResponse;
        try {
          approvalResult = await waitForApproval(
            evalResult.approval_request_id,
            approvalTimeoutMs,
          );
        } catch (err) {
          return {
            block: true,
            blockReason: `Error polling approval: ${err}`,
          };
        }

        if (approvalResult.status === "approved") {
          api.logger.info(
            `snapper-guard: approved by ${approvalResult.reason ?? "user"}`,
          );

          // Replace vault tokens with resolved values if present
          if (
            approvalResult.resolved_data &&
            Object.keys(approvalResult.resolved_data).length > 0
          ) {
            const newParams = replaceTokensInParams(
              params,
              approvalResult.resolved_data,
            );
            return { params: newParams };
          }

          // Approved but no tokens to resolve
          return;
        }

        // Denied or expired
        return {
          block: true,
          blockReason: `Snapper: ${approvalResult.status} — ${approvalResult.reason ?? "request not approved"}`,
        };
      }
    },
    { priority: 100 },
  );
}
