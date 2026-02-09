import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { consumeCachedResult } from "../cache/resultCache";
import { db } from "../db/client";
import { env } from "../env";
import { interpretUpstreamUrl } from "../proxy/interpret";
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

proxyRouter.get("/requests/:id", requireApiKey, (c) => {
  const auth = c.get("apiKeyAuth");
  const requestId = c.req.param("id");

  const row = db()
    .query(
      "SELECT id, status, approval_expires_at, result_state, error_code, error_message, upstream_http_status, upstream_content_type FROM proxy_requests WHERE id = ? AND user_id = ?;"
    )
    .get(requestId, auth.userId) as {
    id: string;
    status: string;
    approval_expires_at: string;
    result_state: string;
    error_code: string | null;
    error_message: string | null;
    upstream_http_status: number | null;
    upstream_content_type: string | null;
  } | null;

  if (!row) return c.json({ error: "not_found" }, 404);

  if (
    row.status === "PENDING_APPROVAL" ||
    row.status === "APPROVED" ||
    row.status === "EXECUTING"
  ) {
    c.header("Retry-After", "1");
    return c.json(
      {
        request_id: row.id,
        status: row.status,
        approval_expires_at: row.approval_expires_at,
      },
      202
    );
  }

  if (row.status === "DENIED") {
    return c.json({ error: "denied", request_id: row.id }, 403);
  }

  if (row.status === "EXPIRED") {
    return c.json({ error: "approval_expired", request_id: row.id }, 408);
  }

  if (row.status === "FAILED") {
    return c.json(
      {
        error: "failed",
        request_id: row.id,
        error_code: row.error_code,
        error_message: row.error_message,
      },
      502
    );
  }

  if (row.status === "SUCCEEDED") {
    const cached = consumeCachedResult(row.id);
    if (cached) {
      db()
        .query(
          "UPDATE proxy_requests SET result_state = 'CONSUMED', updated_at = ? WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);

      const headers = new Headers();
      headers.set("X-Proxy-Request-Id", row.id);
      if (cached.contentType) headers.set("Content-Type", cached.contentType);
      const ab = cached.body.buffer.slice(
        cached.body.byteOffset,
        cached.body.byteOffset + cached.body.byteLength
      );
      return new Response(ab, { status: cached.status, headers });
    }

    if (row.result_state === "CONSUMED") {
      return c.json({ error: "result_consumed", request_id: row.id }, 410);
    }

    if (row.result_state === "AVAILABLE") {
      db()
        .query(
          "UPDATE proxy_requests SET result_state = 'EXPIRED', updated_at = ? WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);
    }

    return c.json({ error: "result_expired", request_id: row.id }, 410);
  }

  return c.json({ error: "unknown_status", status: row.status }, 500);
});

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

    const interpreted = interpretUpstreamUrl(url);
    const text = [
      `API key: ${auth.apiKeyLabel}`,
      `Action: ${interpreted.summary}`,
      ...interpreted.details.map((d) => `- ${d}`),
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
