import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { decryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { env } from "../env";
import { interpretProxyRequest } from "../proxy/interpret";
import { getProxyProviderForUrl } from "../proxy/providerRegistry";
import { readBodyWithLimit } from "../proxy/readLimit";
import { createProxyRequest } from "../proxy/requests";
import { validateUpstreamUrl } from "../proxy/url";
import { telegramApi } from "../telegram/api";

const CreateProxyRequestSchema = z.object({
  upstream_url: z.string().min(1),
  method: z
    .enum(["GET", "POST", "PUT", "PATCH", "DELETE"])
    .optional()
    .default("GET"),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(),
  consent_hint: z.string().optional(),
  idempotency_key: z.string().optional(),
});

function normalizeHeaders(
  providerExtraAllowed: Set<string>,
  headers: Record<string, string> | undefined
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;

  for (const [kRaw, vRaw] of Object.entries(headers)) {
    const k = kRaw.trim().toLowerCase();
    const v = vRaw.trim();
    if (!k || !v) continue;
    if (k === "authorization") continue;
    if (k.length > 100 || v.length > 4000) continue;
    // Keep a small, explicit allowlist. Provider-specific keys are configured
    // by the provider implementation.
    if (
      k !== "accept" &&
      k !== "content-type" &&
      k !== "if-match" &&
      k !== "if-none-match" &&
      !providerExtraAllowed.has(k)
    ) {
      continue;
    }
    out[k] = v;
  }

  return out;
}

function encodeRequestBodyBase64(params: {
  method: string;
  headers: Record<string, string>;
  body: unknown | undefined;
}): { bodyBase64?: string; contentType?: string } {
  const method = params.method.toUpperCase();
  if (method === "GET" || method === "DELETE") {
    if (params.body != null)
      throw new Error("GET/DELETE must not include a body");
    return {};
  }

  const body = params.body;
  if (body == null) return {};

  const ctRaw = params.headers["content-type"];
  const ct = ctRaw ? ctRaw.split(";", 1)[0]?.trim().toLowerCase() : undefined;

  // If the caller didn't specify a content-type, pick a reasonable default.
  // Interpretability should come from content-type when present.
  const inferredCt =
    ct ?? (typeof body === "string" ? "text/plain" : "application/json");

  if (inferredCt === "application/json" || inferredCt.endsWith("+json")) {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    const bytes = new TextEncoder().encode(text);
    if (bytes.byteLength > 256 * 1024) throw new Error("body too large");
    return {
      bodyBase64: Buffer.from(bytes).toString("base64"),
      contentType: ctRaw ?? "application/json",
    };
  }

  const isTextual =
    inferredCt.startsWith("text/") ||
    inferredCt === "application/x-www-form-urlencoded" ||
    inferredCt.endsWith("+xml") ||
    inferredCt === "application/xml";

  if (isTextual) {
    if (typeof body !== "string") {
      throw new Error(
        "textual request bodies must be provided as a string (set content-type accordingly)"
      );
    }

    const bytes = new TextEncoder().encode(body);
    if (bytes.byteLength > 256 * 1024) throw new Error("body too large");
    return {
      bodyBase64: Buffer.from(bytes).toString("base64"),
      contentType: ctRaw ?? "text/plain; charset=utf-8",
    };
  }

  // Generic binary: the API accepts a base64 string and stores raw bytes.
  if (typeof body !== "string") {
    throw new Error(
      "binary request bodies must be provided as a base64 string (set content-type accordingly)"
    );
  }

  const trimmed = body.trim();
  const bytes = Buffer.from(trimmed, "base64");
  if (bytes.byteLength > 256 * 1024) throw new Error("body too large");
  return {
    bodyBase64: Buffer.from(bytes).toString("base64"),
    contentType: ctRaw,
  };
}

function decodeBodyForInterpret(params: {
  contentType: string | undefined;
  bodyBase64: string | undefined;
}): {
  bodyText?: string;
  bodyJson?: unknown;
  bodySummary?: string;
} {
  if (!params.bodyBase64) return {};

  const bytes = Buffer.from(params.bodyBase64, "base64");
  const ctRaw = params.contentType;
  const ct = ctRaw ? ctRaw.split(";", 1)[0]?.trim().toLowerCase() : "";

  const isJson = ct === "application/json" || ct.endsWith("+json");
  const isTextual =
    ct.startsWith("text/") ||
    ct === "application/x-www-form-urlencoded" ||
    ct.endsWith("+xml") ||
    ct === "application/xml";

  if (isJson || isTextual) {
    const text = new TextDecoder().decode(bytes);
    if (isJson) {
      try {
        return {
          bodyText: text,
          bodyJson: JSON.parse(text),
          bodySummary: text,
        };
      } catch {
        return { bodyText: text, bodySummary: text };
      }
    }

    return { bodyText: text, bodySummary: text };
  }

  const prefix = bytes.subarray(0, 24);
  const b64Prefix = Buffer.from(prefix).toString("base64");
  return {
    bodySummary: `<binary ${bytes.byteLength} bytes; base64_prefix=${b64Prefix}…>`,
  };
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatQueryForTelegram(url: URL): string {
  if (!url.search) return "";

  const pairs = [...url.searchParams.entries()];
  if (pairs.length === 0) return "";

  // Drop noisy/default params. If nothing meaningful remains, omit the query block.
  const dropKeys = new Set([
    "fields",
    "pagesize",
    "prettyprint",
    "alt",
    "key",
    "quotauser",
  ]);

  const filtered = pairs.filter(([k, v]) => {
    const kk = k.toLowerCase();
    if (dropKeys.has(kk)) return false;
    if (kk === "q") {
      const norm = v.replace(/\s+/g, "").toLowerCase();
      if (norm === "trashed=false") return false;
    }
    return true;
  });

  if (filtered.length === 0) return "";

  filtered.sort((a, b) =>
    a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])
  );

  const lines = filtered.map(([k, v]) => `${k}=${truncate(v, 200)}`);

  const rendered = truncate(lines.join("\n"), 600);
  return `<b>Query</b>:\n<pre>${escapeHtml(rendered)}</pre>`;
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
      "SELECT id, user_id, api_key_id, status, approval_expires_at, upstream_url, method, request_headers_json, request_body_base64 FROM proxy_requests WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(requestId, auth.userId, auth.apiKeyId) as {
    id: string;
    user_id: string;
    api_key_id: string;
    status: string;
    approval_expires_at: string;
    upstream_url: string;
    method: string;
    request_headers_json: string | null;
    request_body_base64: string | null;
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

      const outHeaders = new Headers();
      outHeaders.set("X-Proxy-Request-Id", row.id);
      if (contentType) outHeaders.set("Content-Type", contentType);
      const ab = body.buffer.slice(
        body.byteOffset,
        body.byteOffset + body.byteLength
      );
      return new Response(ab, { status: res.status, headers: outHeaders });
    }

    const url = new URL(row.upstream_url);
    const provider = getProxyProviderForUrl(url);

    const acct = db()
      .query(
        "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
      )
      .get(auth.userId, provider.id) as {
      refresh_token_ciphertext: Uint8Array;
    } | null;

    if (!acct) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'NO_LINKED_ACCOUNT' WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);
      return c.json(
        {
          error: "no_linked_account",
          provider: provider.id,
          request_id: row.id,
        },
        409
      );
    }

    if (!env.APP_SECRET) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'APP_SECRET_NOT_CONFIGURED' WHERE id = ?;"
        )
        .run(new Date().toISOString(), row.id);
      return c.json({ error: "server_misconfigured", request_id: row.id }, 500);
    }

    const storedToken = await decryptUtf8(acct.refresh_token_ciphertext);

    const accessToken = await provider.getAccessToken({
      storedToken,
    });

    let reqHeaders: Record<string, string> = {};
    if (row.request_headers_json) {
      try {
        reqHeaders = JSON.parse(row.request_headers_json) as Record<
          string,
          string
        >;
      } catch {
        reqHeaders = {};
      }
    }

    // Never allow caller-provided Authorization.
    delete (reqHeaders as Record<string, string>).authorization;

    provider.applyUpstreamRequestHeaderDefaults({ headers: reqHeaders });

    const upstreamHeaders = new Headers();
    for (const [k, v] of Object.entries(reqHeaders)) {
      upstreamHeaders.set(k, v);
    }
    upstreamHeaders.set("authorization", `Bearer ${accessToken}`);

    const method = (row.method || "GET").toUpperCase();
    const bodyBytes = row.request_body_base64
      ? Buffer.from(row.request_body_base64, "base64")
      : null;

    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 60_000);
    let res: Response;
    try {
      res = await fetch(row.upstream_url, {
        method,
        headers: upstreamHeaders,
        body: bodyBytes,
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

    const outHeaders = new Headers();
    outHeaders.set("X-Proxy-Request-Id", row.id);
    if (contentType) outHeaders.set("Content-Type", contentType);

    const ab = body.buffer.slice(
      body.byteOffset,
      body.byteOffset + body.byteLength
    );
    return new Response(ab, { status: res.status, headers: outHeaders });
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
    method,
    headers,
    body,
    consent_hint: consentHint,
    idempotency_key: idempotencyKey,
  } = parsed.data;

  let validatedUrl: URL;
  try {
    validatedUrl = validateUpstreamUrl(upstreamUrl);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_upstream_url", message: msg }, 400);
  }
  const provider = getProxyProviderForUrl(validatedUrl);

  const normalizedHeaders = normalizeHeaders(
    provider.extraAllowedRequestHeaders,
    headers
  );
  let bodyBase64: string | undefined;
  let impliedContentType: string | undefined;
  try {
    const enc = encodeRequestBodyBase64({
      method,
      headers: normalizedHeaders,
      body,
    });
    bodyBase64 = enc.bodyBase64;
    impliedContentType = enc.contentType;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_request", message: msg }, 400);
  }

  // If body implies a content-type and the caller didn't specify one, set it.
  if (impliedContentType && !normalizedHeaders["content-type"]) {
    normalizedHeaders["content-type"] = impliedContentType;
  }

  const decodedForInterpret = decodeBodyForInterpret({
    contentType: normalizedHeaders["content-type"],
    bodyBase64,
  });

  const created = await createProxyRequest({
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
    apiKeyLabelSnapshot: auth.apiKeyLabel,
    upstreamUrl,
    method,
    headers: normalizedHeaders,
    bodyBase64,
    consentHint: consentHint ?? undefined,
    idempotencyKey: idempotencyKey ?? undefined,
    approvalTtlMs: 2 * 60_000,
  });

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

    const interpreted = interpretProxyRequest({
      url,
      method,
      headers: normalizedHeaders,
      bodyJson: decodedForInterpret.bodyJson,
      bodyText: decodedForInterpret.bodyText,
    });

    const queryLine =
      interpreted.details.length === 0 ? formatQueryForTelegram(url) : "";

    const requesterNote = consentHint
      ? `<b>Requester note</b>: ${escapeHtml(truncate(consentHint, 300))}`
      : "";

    const text = [
      "<b>Permission request</b>",
      "",
      `<b>API key</b>: <code>${escapeHtml(auth.apiKeyLabel)}</code>`,
      `<b>Action</b>: ${escapeHtml(interpreted.summary)}`,
      ...interpreted.details.map((d: string) => `- ${escapeHtml(d)}`),
      "",
      `<b>Request</b>: <code>${escapeHtml(`${method} ${url.hostname}${url.pathname}`)}</code>`,
      queryLine,
      decodedForInterpret.bodySummary != null
        ? `<b>Body</b>: <pre>${escapeHtml(truncate(decodedForInterpret.bodySummary, 500))}</pre>`
        : "",
      "",
      "Approve to allow the agent to execute this request.",
      ...(requesterNote ? ["", requesterNote] : []),
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
      .sendMessage(u.telegram_user_id, text, {
        reply_markup: kb,
        parse_mode: "HTML",
      })
      .catch(() => {});
  }

  return c.json({
    request_id: created.requestId,
    status: created.status,
    approval_expires_at: created.approvalExpiresAt,
  });
});
