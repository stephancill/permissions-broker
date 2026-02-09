import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { db } from "../db/client";
import { env } from "../env";
import { createProxyRequest } from "../proxy/requests";
import { telegramApi } from "../telegram/api";

const CreateProxyRequestSchema = z.object({
  upstream_url: z.string().min(1),
  consent_hint: z.string().optional(),
  idempotency_key: z.string().optional(),
});

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

export const proxyRouter = new Hono();

proxyRouter.post("/request", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const raw = await c.req.json().catch(() => null);
  const parsed = CreateProxyRequestSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const {
    upstream_url: upstreamUrl,
    consent_hint: consentHint,
    idempotency_key: idempotencyKey,
  } = parsed.data;

  let created: Awaited<ReturnType<typeof createProxyRequest>>;
  try {
    created = await createProxyRequest({
      userId: auth.userId,
      apiKeyId: auth.apiKeyId,
      apiKeyLabelSnapshot: auth.apiKeyLabel,
      upstreamUrl,
      consentHint: consentHint ?? undefined,
      idempotencyKey: idempotencyKey ?? undefined,
      approvalTtlMs: 2 * 60_000,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_upstream_url", message: msg }, 400);
  }

  if (created.isNew) {
    auditEvent({
      userId: auth.userId,
      requestId: created.requestId,
      actorType: "api_key",
      actorId: auth.apiKeyId,
      eventType: "proxy_request_created",
      event: {
        upstream_url: upstreamUrl,
        api_key_label: auth.apiKeyLabel,
      },
    });
  }

  const u = db()
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(auth.userId) as { telegram_user_id: number } | null;

  if (created.isNew && u?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const url = new URL(created.canonicalUpstreamUrl);
    const hashPrefix = created.requestHash.slice(0, 12);
    const text = [
      `API key: ${auth.apiKeyLabel}`,
      `Request: GET ${url.hostname}${url.pathname}`,
      url.search ? `Query: ${truncate(url.search, 300)}` : "Query: (none)",
      consentHint
        ? `Requester note (unverified): ${truncate(consentHint, 300)}`
        : "",
      `Hash: ${hashPrefix}`,
    ]
      .filter(Boolean)
      .join("\n");

    const kb = {
      inline_keyboard: [
        [
          { text: "Approve", callback_data: `r:approve:${created.requestId}` },
          { text: "Deny", callback_data: `r:deny:${created.requestId}` },
        ],
      ],
    };

    telegramApi()
      .sendMessage(u.telegram_user_id, text, { reply_markup: kb })
      .catch(() => {});
  }

  return c.json({
    request_id: created.requestId,
    status: created.status,
    approval_expires_at: created.approvalExpiresAt,
  });
});
