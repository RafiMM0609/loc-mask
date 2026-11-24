/**
 * PII-Shield extension for Pi dev CLI (@earendil-works/pi-coding-agent).
 *
 * Placement: ~/.pi/agent/extensions/pii-shield.ts
 * Provides automatic 2-way masking/unmasking across all Pi providers
 * (opencode-go, openai, anthropic, gemini, etc.) via the local PII-Shield server.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const SHIELD_URL = (process.env.PII_SHIELD_URL || "http://127.0.0.1:8787").replace(/\/$/, "");

interface MaskResponse {
  text?: string | null;
  payload?: unknown;
  count: number;
  entity_types: string[];
}

interface UnmaskResponse {
  text?: string | null;
  payload?: unknown;
  restored_count: number;
}

async function postShield<T>(path: string, body: unknown, timeoutMs = 3000): Promise<T | null> {
  try {
    const resp = await fetch(`${SHIELD_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

async function maskContentBlocks(
  content: unknown,
  sessionId: string,
): Promise<{ content: unknown; types: string[] }> {
  if (typeof content === "string") {
    const res = await postShield<MaskResponse>("/api/v1/mask", {
      text: content,
      session_id: sessionId,
    });
    return res && res.text != null
      ? { content: res.text, types: res.entity_types }
      : { content, types: [] };
  }
  if (!Array.isArray(content)) {
    return { content, types: [] };
  }

  const detectedTypes: string[] = [];
  const nextBlocks = await Promise.all(
    content.map(async (block) => {
      if (block && typeof block === "object" && (block as { type?: string }).type === "text") {
        const textVal = (block as { text?: unknown }).text;
        if (typeof textVal === "string") {
          const res = await postShield<MaskResponse>("/api/v1/mask", {
            text: textVal,
            session_id: sessionId,
          });
          if (res && res.text != null) {
            for (const t of res.entity_types) {
              if (!detectedTypes.includes(t)) detectedTypes.push(t);
            }
            return { ...block, text: res.text };
          }
        }
      }
      return block;
    }),
  );
  return { content: nextBlocks, types: detectedTypes };
}

async function unmaskContentBlocks(content: unknown, sessionId: string): Promise<unknown> {
  if (typeof content === "string") {
    const res = await postShield<UnmaskResponse>("/api/v1/unmask", {
      text: content,
      session_id: sessionId,
    });
    return res && res.text != null ? res.text : content;
  }
  if (!Array.isArray(content)) {
    return content;
  }

  return Promise.all(
    content.map(async (block) => {
      if (block && typeof block === "object" && (block as { type?: string }).type === "text") {
        const textVal = (block as { text?: unknown }).text;
        if (typeof textVal === "string") {
          const res = await postShield<UnmaskResponse>("/api/v1/unmask", {
            text: textVal,
            session_id: sessionId,
          });
          if (res && res.text != null) {
            return { ...block, text: res.text };
          }
        }
      }
      return block;
    }),
  );
}

export default function (pi: ExtensionAPI) {
  const getSessionId = (ctx: { sessionManager?: { getSessionId?: () => string } }) =>
    ctx.sessionManager?.getSessionId?.() || "pi-default";

  pi.on("session_start", async (_event, ctx) => {
    try {
      const resp = await fetch(`${SHIELD_URL}/health`, { signal: AbortSignal.timeout(1000) });
      if (resp.ok) {
        ctx.ui.setStatus("pii-shield", "PII-Shield: ON");
        return;
      }
    } catch {
      // Server offline
    }
    ctx.ui.setStatus("pii-shield", "PII-Shield: OFF");
  });

  pi.on("input", async (event, ctx) => {
    if (event.source === "extension" || !event.text.trim()) {
      return { action: "continue" };
    }

    const sessionId = getSessionId(ctx);
    const res = await postShield<MaskResponse>("/api/v1/mask", {
      text: event.text,
      session_id: sessionId,
    });

    if (!res) {
      ctx.ui.setStatus("pii-shield", "PII-Shield: OFF");
      if (ctx.hasUI) {
        const allow = await ctx.ui.confirm(
          "PII-Shield Offline",
          "Server PII-Shield tidak berjalan. Tetap kirim prompt tanpa masking?",
        );
        if (!allow) return { action: "handled" };
      }
      return { action: "continue" };
    }

    ctx.ui.setStatus("pii-shield", "PII-Shield: ON");
    if (res.count > 0 && res.text != null) {
      ctx.ui.notify(`PII-Shield masked: ${res.entity_types.join(", ")}`, "info");
      return { action: "transform", text: res.text };
    }

    return { action: "continue" };
  });

  pi.on("tool_result", async (event, ctx) => {
    const sessionId = getSessionId(ctx);
    const { content, types } = await maskContentBlocks(event.content, sessionId);
    if (types.length > 0) {
      ctx.ui.notify(`PII-Shield masked tool output (${event.toolName}): ${types.join(", ")}`, "info");
      return { content: content as typeof event.content };
    }
  });

  pi.on("context", async (event, ctx) => {
    const sessionId = getSessionId(ctx);
    let changed = false;
    const maskedMessages = await Promise.all(
      event.messages.map(async (msg) => {
        if (!msg || typeof msg !== "object" || !("content" in msg)) return msg;
        const { content, types } = await maskContentBlocks(
          (msg as { content: unknown }).content,
          sessionId,
        );
        if (types.length > 0) {
          changed = true;
          return { ...msg, content };
        }
        return msg;
      }),
    );
    if (changed) {
      return { messages: maskedMessages as typeof event.messages };
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    const sessionId = getSessionId(ctx);
    const res = await postShield<UnmaskResponse>("/api/v1/unmask", {
      payload: event.input,
      session_id: sessionId,
    });
    if (res && res.restored_count > 0 && res.payload && typeof res.payload === "object") {
      Object.assign(event.input as Record<string, unknown>, res.payload as Record<string, unknown>);
    }
  });

  pi.on("message_end", async (event, ctx) => {
    if (event.message.role !== "assistant") return;
    const sessionId = getSessionId(ctx);
    const unmasked = await unmaskContentBlocks(event.message.content, sessionId);
    if (unmasked !== event.message.content) {
      return {
        message: {
          ...event.message,
          content: unmasked as typeof event.message.content,
        },
      };
    }
  });

  pi.registerCommand("pii-status", {
    description: "Check local PII-Shield server status",
    handler: async (_args, ctx) => {
      try {
        const resp = await fetch(`${SHIELD_URL}/health`, { signal: AbortSignal.timeout(1500) });
        if (resp.ok) {
          const info = (await resp.json()) as { active_placeholders?: number };
          ctx.ui.setStatus("pii-shield", "PII-Shield: ON");
          ctx.ui.notify(
            `PII-Shield ONLINE (${SHIELD_URL}) | Active placeholders: ${info.active_placeholders ?? 0}`,
            "info",
          );
          return;
        }
      } catch {
        // offline
      }
      ctx.ui.setStatus("pii-shield", "PII-Shield: OFF");
      ctx.ui.notify(`PII-Shield OFFLINE (${SHIELD_URL})`, "warning");
    },
  });
}
