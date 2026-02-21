/**
 * Snapper Service Registry — single source of truth for all monitored AI services.
 *
 * Tier 1: Deep Integration — custom content scripts, tool detection
 * Tier 2: Standard Monitoring — generic content script, PII scanning, input interception
 * Tier 3: Visit-Only Tracking — background.js webNavigation, shadow AI reporting
 */

const SERVICE_REGISTRY = [
  // ---- Tier 1: Deep Integration ----
  { source: "chatgpt", label: "ChatGPT", domains: ["chatgpt.com", "chat.openai.com"], tier: 1, category: "chat", risk: "medium" },
  { source: "claude", label: "Claude", domains: ["claude.ai"], tier: 1, category: "chat", risk: "medium" },
  { source: "gemini", label: "Gemini", domains: ["gemini.google.com"], tier: 1, category: "chat", risk: "medium" },
  { source: "copilot", label: "Microsoft Copilot", domains: ["copilot.microsoft.com"], tier: 1, category: "chat", risk: "medium" },
  { source: "grok", label: "Grok", domains: ["grok.com"], tier: 1, category: "chat", risk: "medium" },
  { source: "deepseek", label: "DeepSeek", domains: ["chat.deepseek.com"], tier: 1, category: "chat", risk: "high" },
  { source: "perplexity", label: "Perplexity", domains: ["perplexity.ai", "www.perplexity.ai"], tier: 1, category: "chat", risk: "medium" },
  { source: "github_copilot", label: "GitHub Copilot Web", domains: ["github.com/copilot"], tier: 1, category: "coding", risk: "medium" },

  // ---- Tier 2: Standard Monitoring ----
  { source: "mistral", label: "Mistral Le Chat", domains: ["chat.mistral.ai"], tier: 2, category: "chat", risk: "medium" },
  { source: "poe", label: "Poe", domains: ["poe.com"], tier: 2, category: "chat", risk: "medium" },
  { source: "meta_ai", label: "Meta AI", domains: ["meta.ai", "www.meta.ai"], tier: 2, category: "chat", risk: "medium" },
  { source: "huggingchat", label: "HuggingChat", domains: ["huggingface.co/chat"], tier: 2, category: "chat", risk: "low" },
  { source: "cursor", label: "Cursor", domains: ["cursor.com", "www.cursor.com"], tier: 2, category: "coding", risk: "medium" },
  { source: "replit", label: "Replit", domains: ["replit.com"], tier: 2, category: "coding", risk: "medium" },
  { source: "v0", label: "v0.dev", domains: ["v0.dev"], tier: 2, category: "coding", risk: "medium" },
  { source: "bolt", label: "bolt.new", domains: ["bolt.new"], tier: 2, category: "coding", risk: "medium" },
  { source: "lovable", label: "Lovable", domains: ["lovable.dev"], tier: 2, category: "coding", risk: "medium" },
  { source: "jasper", label: "Jasper", domains: ["app.jasper.ai"], tier: 2, category: "writing", risk: "low" },
  { source: "copyai", label: "Copy.ai", domains: ["app.copy.ai"], tier: 2, category: "writing", risk: "low" },
  { source: "writesonic", label: "Writesonic", domains: ["app.writesonic.com"], tier: 2, category: "writing", risk: "low" },
  { source: "notion_ai", label: "Notion AI", domains: ["notion.so", "www.notion.so"], tier: 2, category: "writing", risk: "medium" },
  { source: "writer", label: "Writer", domains: ["app.writer.com"], tier: 2, category: "writing", risk: "low" },
  { source: "midjourney", label: "Midjourney", domains: ["midjourney.com", "www.midjourney.com"], tier: 2, category: "image", risk: "low" },
  { source: "leonardo", label: "Leonardo.ai", domains: ["app.leonardo.ai"], tier: 2, category: "image", risk: "low" },
  { source: "ideogram", label: "Ideogram", domains: ["ideogram.ai"], tier: 2, category: "image", risk: "low" },
  { source: "runway", label: "Runway", domains: ["app.runwayml.com"], tier: 2, category: "image", risk: "low" },
  { source: "sora", label: "Sora", domains: ["sora.com"], tier: 2, category: "image", risk: "medium" },
  { source: "grammarly", label: "Grammarly", domains: ["app.grammarly.com"], tier: 2, category: "writing", risk: "low" },

  // ---- Tier 3: Visit-Only Tracking ----
  { source: "together", label: "Together AI", domains: ["together.xyz", "api.together.xyz"], tier: 3, category: "chat", risk: "low" },
  { source: "cohere", label: "Cohere", domains: ["coral.cohere.com", "dashboard.cohere.com"], tier: 3, category: "chat", risk: "low" },
  { source: "anyscale", label: "Anyscale", domains: ["console.anyscale.com"], tier: 3, category: "chat", risk: "low" },
  { source: "fireworks", label: "Fireworks AI", domains: ["fireworks.ai"], tier: 3, category: "chat", risk: "low" },
  { source: "groq", label: "Groq", domains: ["console.groq.com", "groq.com"], tier: 3, category: "chat", risk: "low" },
  { source: "openrouter", label: "OpenRouter", domains: ["openrouter.ai"], tier: 3, category: "chat", risk: "low" },
  { source: "replicate", label: "Replicate", domains: ["replicate.com"], tier: 3, category: "chat", risk: "low" },
  { source: "stability", label: "Stability AI", domains: ["platform.stability.ai"], tier: 3, category: "image", risk: "low" },
  { source: "photoroom", label: "PhotoRoom", domains: ["app.photoroom.com"], tier: 3, category: "image", risk: "low" },
  { source: "canva_ai", label: "Canva AI", domains: ["canva.com"], tier: 3, category: "image", risk: "low" },
  { source: "adobe_firefly", label: "Adobe Firefly", domains: ["firefly.adobe.com"], tier: 3, category: "image", risk: "low" },
  { source: "descript", label: "Descript", domains: ["descript.com", "app.descript.com"], tier: 3, category: "image", risk: "low" },
  { source: "otter_ai", label: "Otter.ai", domains: ["otter.ai"], tier: 3, category: "writing", risk: "medium" },
  { source: "coda_ai", label: "Coda AI", domains: ["coda.io"], tier: 3, category: "writing", risk: "low" },
  { source: "tome", label: "Tome", domains: ["tome.app"], tier: 3, category: "writing", risk: "low" },
  { source: "gamma", label: "Gamma", domains: ["gamma.app"], tier: 3, category: "writing", risk: "low" },
  { source: "beautiful_ai", label: "Beautiful.ai", domains: ["www.beautiful.ai"], tier: 3, category: "writing", risk: "low" },
  { source: "tabnine", label: "Tabnine", domains: ["app.tabnine.com"], tier: 3, category: "coding", risk: "medium" },
  { source: "codeium", label: "Codeium", domains: ["codeium.com"], tier: 3, category: "coding", risk: "medium" },
  { source: "sourcegraph", label: "Sourcegraph Cody", domains: ["sourcegraph.com"], tier: 3, category: "coding", risk: "medium" },
  { source: "amazon_q", label: "Amazon Q", domains: ["us-east-1.console.aws.amazon.com"], tier: 3, category: "coding", risk: "medium" },
  { source: "windsurf", label: "Windsurf", domains: ["windsurf.com", "codeium.com/windsurf"], tier: 3, category: "coding", risk: "medium" },
  { source: "phind", label: "Phind", domains: ["phind.com", "www.phind.com"], tier: 3, category: "coding", risk: "low" },
  { source: "you", label: "You.com", domains: ["you.com"], tier: 3, category: "chat", risk: "low" },
  { source: "pi", label: "Pi AI", domains: ["pi.ai"], tier: 3, category: "chat", risk: "low" },
  { source: "character_ai", label: "Character.AI", domains: ["character.ai", "beta.character.ai"], tier: 3, category: "chat", risk: "low" },
  { source: "inflection", label: "Inflection", domains: ["inflection.ai"], tier: 3, category: "chat", risk: "low" },
];

/**
 * Return the effective service registry — synced from server if available,
 * static SERVICE_REGISTRY as fallback.
 */
async function getEffectiveServiceRegistry() {
  try {
    const stored = await chrome.storage.local.get(["synced_service_registry"]);
    if (stored.synced_service_registry && stored.synced_service_registry.length > 0) {
      return stored.synced_service_registry;
    }
  } catch (e) {
    // chrome.storage not available (e.g., Node.js tests)
  }
  return SERVICE_REGISTRY;
}

// Export for use in different contexts
if (typeof module !== "undefined" && module.exports) {
  module.exports = { SERVICE_REGISTRY, getEffectiveServiceRegistry };
}
