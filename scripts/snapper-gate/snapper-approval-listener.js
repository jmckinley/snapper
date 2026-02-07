#!/usr/bin/env node
/**
 * Snapper Approval Listener for OpenClaw
 *
 * Connects to OpenClaw gateway and intercepts exec.approval.requested events.
 * Evaluates commands against Snapper rules and auto-resolves or forwards for approval.
 *
 * Auth failure handling:
 *   - Exponential backoff: 5s → 10s → 20s → 40s → 60s cap
 *   - After 5 consecutive auth failures: exit 1 (systemd shows "failed")
 *   - Successful connect resets backoff and failure counter
 */

const WebSocket = require("ws");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const os = require("os");

// Configuration from environment
const SNAPPER_URL = process.env.SNAPPER_URL || "http://127.0.0.1:8000";
const SNAPPER_AGENT_ID = process.env.SNAPPER_AGENT_ID || "openclaw-main";
const SNAPPER_API_KEY = process.env.SNAPPER_API_KEY || "";
const GATEWAY_URL = process.env.OPENCLAW_GATEWAY_URL || "ws://127.0.0.1:18789";
const GATEWAY_TOKEN = process.env.OPENCLAW_GATEWAY_TOKEN || "";

// Parse URL
const snapperUrl = new URL(SNAPPER_URL);
const httpModule = snapperUrl.protocol === "https:" ? https : http;

let ws = null;
let reconnectTimer = null;
const BASE_RECONNECT_DELAY = 5000;
const MAX_RECONNECT_DELAY = 60000;
const MAX_AUTH_FAILURES = 5;
const PROTOCOL_VERSION = 3;

// Backoff state
let authFailureCount = 0;
let currentReconnectDelay = BASE_RECONNECT_DELAY;

function log(msg) {
  console.log("[" + new Date().toISOString() + "] " + msg);
}

function isAuthFailure(code, reason) {
  const reasonStr = String(reason || "").toLowerCase();
  return (
    code === 4001 ||
    code === 4003 ||
    code === 1008 ||
    reasonStr.includes("device identity") ||
    reasonStr.includes("unauthorized") ||
    reasonStr.includes("authentication") ||
    reasonStr.includes("forbidden")
  );
}

function callSnapperEvaluate(command, agentId) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      agent_id: agentId || SNAPPER_AGENT_ID,
      request_type: "command",
      command: command,
    });

    const options = {
      hostname: snapperUrl.hostname,
      port: snapperUrl.port || (snapperUrl.protocol === "https:" ? 443 : 80),
      path: "/api/v1/rules/evaluate",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
      rejectUnauthorized: false,
    };

    if (SNAPPER_API_KEY) {
      options.headers["X-API-Key"] = SNAPPER_API_KEY;
    }

    const req = httpModule.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error("Failed to parse response: " + data));
        }
      });
    });

    req.on("error", reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error("Snapper request timed out"));
    });
    req.write(payload);
    req.end();
  });
}

// Pending requests
const pending = new Map();

function sendRequest(method, params) {
  return new Promise((resolve, reject) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      reject(new Error("Gateway not connected"));
      return;
    }

    const id = crypto.randomUUID();
    const message = {
      type: "req",
      id: id,
      method: method,
      params: params,
    };

    pending.set(id, { resolve, reject });

    // Timeout after 30 seconds
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error("Request timed out"));
      }
    }, 30000);

    ws.send(JSON.stringify(message));
    log("Sent request: " + method);
  });
}

async function handleApprovalRequest(request) {
  const id = request.id;
  const reqData = request.request || {};
  const command = reqData.command || "";
  const agentId = reqData.agentId || SNAPPER_AGENT_ID;

  log(
    "Approval request: " +
      id.substring(0, 8) +
      "... command: " +
      command.substring(0, 50) +
      "..."
  );

  try {
    const result = await callSnapperEvaluate(command, agentId);
    log("Snapper decision: " + result.decision);

    switch (result.decision) {
      case "allow":
        await sendRequest("exec.approval.resolve", {
          id: id,
          decision: "allow-once",
        });
        log("Auto-approved: " + id.substring(0, 8) + "...");
        break;

      case "deny":
        await sendRequest("exec.approval.resolve", {
          id: id,
          decision: "deny",
        });
        log(
          "Auto-denied: " +
            id.substring(0, 8) +
            "... reason: " +
            (result.reason || "Security policy")
        );
        break;

      case "require_approval":
        log(
          "Pending manual approval: " +
            id.substring(0, 8) +
            "... request_id: " +
            result.approval_request_id
        );
        break;

      default:
        await sendRequest("exec.approval.resolve", {
          id: id,
          decision: "deny",
        });
        log("Denied (unknown decision): " + id.substring(0, 8) + "...");
    }
  } catch (err) {
    log("Snapper error: " + err.message + " - denying request");
    try {
      await sendRequest("exec.approval.resolve", {
        id: id,
        decision: "deny",
      });
    } catch (e) {
      log("Failed to send deny: " + e.message);
    }
  }
}

function connect() {
  if (ws) {
    ws.terminate();
  }

  log("Connecting to gateway: " + GATEWAY_URL);
  ws = new WebSocket(GATEWAY_URL, {
    maxPayload: 25 * 1024 * 1024,
  });

  ws.on("open", async () => {
    log("Connected to OpenClaw gateway");

    // Send connect request using the proper protocol
    const connectParams = {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        displayName: "Snapper Approval Listener",
        version: "1.0.0",
        platform: os.platform(),
        mode: "backend",
      },
      caps: [],
      role: "operator",
      scopes: ["operator.approvals"],
      auth: GATEWAY_TOKEN ? { token: GATEWAY_TOKEN } : undefined,
    };

    try {
      const result = await sendRequest("connect", connectParams);
      log(
        "Gateway connect acknowledged: " +
          JSON.stringify(result?.server || {})
      );

      // Successful auth — reset backoff
      authFailureCount = 0;
      currentReconnectDelay = BASE_RECONNECT_DELAY;
    } catch (err) {
      log("Connect handshake failed: " + err.message);
      // The gateway will likely close the socket; backoff handled in on("close")
    }
  });

  ws.on("message", (data) => {
    try {
      const msg = JSON.parse(data.toString());

      // Handle response frames
      if (msg.type === "res" && msg.id) {
        const handler = pending.get(msg.id);
        if (handler) {
          pending.delete(msg.id);
          if (msg.ok) {
            handler.resolve(msg.payload);
          } else {
            handler.reject(
              new Error((msg.error && msg.error.message) || "Request failed")
            );
          }
        }
        return;
      }

      // Handle event frames
      if (msg.type === "event") {
        if (msg.event === "exec.approval.requested") {
          handleApprovalRequest(msg.payload);
          return;
        }

        if (msg.event === "exec.approval.resolved") {
          const payload = msg.payload || {};
          log(
            "Approval resolved: " +
              (payload.id || "").substring(0, 8) +
              "... decision: " +
              payload.decision
          );
          return;
        }

        // Ignore tick events
        if (msg.event === "tick") {
          return;
        }

        log("Event: " + msg.event);
      }
    } catch (e) {
      log("Parse error: " + e.message);
    }
  });

  ws.on("close", (code, reason) => {
    const reasonStr = String(reason || "");
    log("Disconnected: " + code + " " + reasonStr);

    if (isAuthFailure(code, reasonStr)) {
      authFailureCount++;
      currentReconnectDelay = Math.min(
        BASE_RECONNECT_DELAY * Math.pow(2, authFailureCount - 1),
        MAX_RECONNECT_DELAY
      );

      log(
        "Auth failure " +
          authFailureCount +
          "/" +
          MAX_AUTH_FAILURES +
          " — next retry in " +
          (currentReconnectDelay / 1000) +
          "s"
      );

      if (authFailureCount >= MAX_AUTH_FAILURES) {
        log(
          "[fatal] " +
            MAX_AUTH_FAILURES +
            " consecutive auth failures. Check your OPENCLAW_GATEWAY_TOKEN:"
        );
        log(
          "[fatal]   1. Verify the token: grep OPENCLAW_GATEWAY_TOKEN /opt/openclaw/.env"
        );
        log("[fatal]   2. Copy it to this service's .env file");
        log("[fatal]   3. Restart: systemctl restart snapper-listener");
        process.exit(1);
      }
    } else {
      // Non-auth disconnect (network blip, server restart) — normal reconnect
      currentReconnectDelay = BASE_RECONNECT_DELAY;
    }

    scheduleReconnect();
  });

  ws.on("error", (err) => {
    log("WebSocket error: " + err.message);
  });
}

function scheduleReconnect() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }
  reconnectTimer = setTimeout(() => {
    log("Reconnecting...");
    connect();
  }, currentReconnectDelay);
}

// Start
log("Snapper Approval Listener starting");
log("Snapper URL: " + SNAPPER_URL);
log("Agent ID: " + SNAPPER_AGENT_ID);
log("Gateway URL: " + GATEWAY_URL);
connect();

// Handle shutdown
process.on("SIGINT", () => {
  log("Shutting down...");
  if (ws) ws.close();
  process.exit(0);
});
