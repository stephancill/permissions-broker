import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { decryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { env } from "../env";
import { refreshAccessToken } from "../oauth/flow";
import { getProvider } from "../oauth/registry";
import { interpretUpstreamUrl } from "../proxy/interpret";
import { readBodyWithLimit } from "../proxy/readLimit";
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
      "SELECT id, status, approval_expires_at, error_code, error_message, upstream_http_status, upstream_content_type, upstream_bytes FROM proxy_requests WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(requestId, auth.userId, auth.apiKeyId) as {
    id: string;
    status: string;
    approval_expires_at: string;
    error_code: string | null;
    error_message: string | null;
    upstream_http_status: number | null;
    upstream_content_type: string | null;
    upstream_bytes: number | null;
  } | null;

  if (!row) return c.json({ error: "forbidden" }, 403);

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
    return c.json({
      request_id: row.id,
      status: row.status,
      error_code: row.error_code,
      error_message: row.error_message,
      upstream_http_status: row.upstream_http_status,
      upstream_content_type: row.upstream_content_type,
      upstream_bytes: row.upstream_bytes,
    });
  }

  if (row.status === "SUCCEEDED") {
    return c.json({
      request_id: row.id,
      status: row.status,
      upstream_http_status: row.upstream_http_status,
      upstream_content_type: row.upstream_content_type,
      upstream_bytes: row.upstream_bytes,
    });
  }

  return c.json({ error: "unknown_status", status: row.status }, 500);
});

proxyRouter.post("/requests/:id/execute", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const requestId = c.req.param("id");

  const row = db()
    .query(
      "SELECT id, user_id, api_key_id, status, approval_expires_at, upstream_url FROM proxy_requests WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(requestId, auth.userId, auth.apiKeyId) as {
    id: string;
    user_id: string;
    api_key_id: string;
    status: string;
    approval_expires_at: string;
    upstream_url: string;
  } | null;

  if (!row) return c.json({ error: "forbidden" }, 403);

  if (row.status === "PENDING_APPROVAL") {
    c.header("Retry-After", "1");
    return c.json({ error: "pending_approval", request_id: row.id }, 202);
  }

  if (row.status === "DENIED") {
    return c.json({ error: "denied", request_id: row.id }, 403);
  }

  if (row.status === "EXPIRED") {
    return c.json({ error: "approval_expired", request_id: row.id }, 408);
  }

  if (row.status === "EXECUTING") {
    c.header("Retry-After", "1");
    return c.json({ error: "executing", request_id: row.id }, 409);
  }

  if (row.status === "SUCCEEDED" || row.status === "FAILED") {
    return c.json({ error: "already_executed", request_id: row.id }, 410);
  }

  if (row.status !== "APPROVED") {
    return c.json({ error: "invalid_state", status: row.status }, 400);
  }

  // Handle edge case: approval expired but sweeper has not run.
  const exp = Date.parse(row.approval_expires_at);
  if (Number.isFinite(exp) && Date.now() > exp) {
    db()
      .query(
        "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' WHERE id = ? AND status = 'APPROVED';"
      )
      .run(new Date().toISOString(), row.id);
    return c.json({ error: "approval_expired", request_id: row.id }, 408);
  }

  const claimRun = db()
    .query(
      "UPDATE proxy_requests SET status = 'EXECUTING', updated_at = ? WHERE id = ? AND status = 'APPROVED' AND api_key_id = ?;"
    )
    .run(new Date().toISOString(), row.id, auth.apiKeyId);

  const claimed =
    typeof claimRun.changes === "number" ? claimRun.changes === 1 : false;

  if (!claimed) {
    c.header("Retry-After", "1");
    return c.json({ error: "executing", request_id: row.id }, 409);
  }

  try {
    // Test-only escape hatch: allow executing against a stub upstream without OAuth.
    // This is enabled by the test script (PB_TEST_BYPASS_OAUTH=1) and should not be used in production.
    if (env.NODE_ENV === "test" && env.PB_TEST_BYPASS_OAUTH) {
      const ctrl = new AbortController();
      const timeout = setTimeout(() => ctrl.abort(), 60_000);
      let res: Response;
      try {
        res = await fetch(row.upstream_url, {
          method: "GET",
          signal: ctrl.signal,
        });
      } finally {
        clearTimeout(timeout);
      }

      const contentType = res.headers.get("content-type");
      const body = await readBodyWithLimit(res.body, 1024 * 1024);
      const terminalStatus =
        res.status >= 200 && res.status < 300 ? "SUCCEEDED" : "FAILED";
      const errorCode =
        terminalStatus === "FAILED" ? `UPSTREAM_HTTP_${res.status}` : null;

      db()
        .query(
          "UPDATE proxy_requests SET status = ?, updated_at = ?, upstream_http_status = ?, upstream_content_type = ?, upstream_bytes = ?, error_code = ?, error_message = NULL WHERE id = ?;"
        )
        .run(
          terminalStatus,
          new Date().toISOString(),
          res.status,
          contentType,
          body.byteLength,
          errorCode,
          row.id
        );

      const headers = new Headers();
      headers.set("X-Proxy-Request-Id", row.id);
      if (contentType) headers.set("Content-Type", contentType);
      const ab = body.buffer.slice(
        body.byteOffset,
        body.byteOffset + body.byteLength
      );
      return new Response(ab, { status: res.status, headers });
    }

    const acct = db()
      .query(
        "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'google' AND status = 'active' LIMIT 1;"
      )
      .get(auth.userId) as { refresh_token_ciphertext: Uint8Array } | null;

    if (!acct) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'NO_LINKED_ACCOUNT' WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);
      return c.json({ error: "no_linked_account", request_id: row.id }, 409);
    }

    if (!env.APP_SECRET) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'APP_SECRET_NOT_CONFIGURED' WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);
      return c.json({ error: "server_misconfigured", request_id: row.id }, 500);
    }

    const refreshToken = await decryptUtf8(acct.refresh_token_ciphertext);
    const provider = getProvider("google");
    const token = await refreshAccessToken({ provider, refreshToken });

    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 60_000);
    let res: Response;
    try {
      res = await fetch(row.upstream_url, {
        method: "GET",
        headers: {
          authorization: `Bearer ${token.access_token}`,
        },
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    const contentType = res.headers.get("content-type");
    const body = await readBodyWithLimit(res.body, 1024 * 1024);

    const terminalStatus =
      res.status >= 200 && res.status < 300 ? "SUCCEEDED" : "FAILED";
    const errorCode =
      terminalStatus === "FAILED" ? `UPSTREAM_HTTP_${res.status}` : null;

    db()
      .query(
        "UPDATE proxy_requests SET status = ?, updated_at = ?, upstream_http_status = ?, upstream_content_type = ?, upstream_bytes = ?, error_code = ?, error_message = NULL WHERE id = ?;"
      )
      .run(
        terminalStatus,
        new Date().toISOString(),
        res.status,
        contentType,
        body.byteLength,
        errorCode,
        row.id
      );

    auditEvent({
      userId: auth.userId,
      requestId: row.id,
      actorType: "api_key",
      actorId: auth.apiKeyId,
      eventType: "proxy_request_executed",
      event: { upstream_status: res.status, bytes: body.byteLength },
    });

    const headers = new Headers();
    headers.set("X-Proxy-Request-Id", row.id);
    if (contentType) headers.set("Content-Type", contentType);

    const ab = body.buffer.slice(
      body.byteOffset,
      body.byteOffset + body.byteLength
    );
    return new Response(ab, { status: res.status, headers });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const errorCode =
      msg === "response_too_large" ? "RESPONSE_TOO_LARGE" : "UPSTREAM_FAILED";
    db()
      .query(
        "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = ?, error_message = ? WHERE id = ?;"
      )
      .run(new Date().toISOString(), errorCode, msg, row.id);
    return c.json({ error: "execution_failed", request_id: row.id }, 502);
  }
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
      "Approve to allow the agent to execute this request.",
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
