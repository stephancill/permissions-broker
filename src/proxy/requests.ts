import { ulid } from "ulid";

import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { canonicalizeUrl, validateUpstreamUrl } from "./url";

function nowIso(): string {
  return new Date().toISOString();
}

export async function createProxyRequest(params: {
  userId: string;
  apiKeyId: string;
  apiKeyLabelSnapshot: string;
  requesterIp?: string;
  upstreamUrl: string;
  method: string;
  headers?: Record<string, string>;
  // Request body bytes, base64-encoded.
  bodyBase64?: string;
  consentHint?: string;
  idempotencyKey?: string;
  approvalTtlMs: number;
}): Promise<{
  requestId: string;
  canonicalUpstreamUrl: string;
  requestHash: string;
  status: string;
  approvalExpiresAt: string;
  isNew: boolean;
}> {
  const url = validateUpstreamUrl(params.upstreamUrl);
  const canonicalUrl = canonicalizeUrl(url);

  const method = params.method.toUpperCase();
  const headers = params.headers ?? {};
  const headerPairs = Object.entries(headers).map(([k, v]) => [
    k.toLowerCase(),
    v,
  ]);
  headerPairs.sort((a, b) => a[0].localeCompare(b[0]));
  const canonicalHeaders = Object.fromEntries(headerPairs);

  const canonicalPayload = JSON.stringify({
    method,
    url: canonicalUrl,
    headers: canonicalHeaders,
    body_base64: params.bodyBase64 ?? null,
  });
  const requestHash = await sha256Hex(canonicalPayload);

  if (params.idempotencyKey) {
    const existing = db()
      .query(
        "SELECT id, upstream_url, request_hash, status, approval_expires_at FROM proxy_requests WHERE api_key_id = ? AND idempotency_key = ? LIMIT 1;"
      )
      .get(params.apiKeyId, params.idempotencyKey) as {
      id: string;
      upstream_url: string;
      request_hash: string;
      status: string;
      approval_expires_at: string;
    } | null;

    if (existing) {
      return {
        requestId: existing.id,
        canonicalUpstreamUrl: existing.upstream_url,
        requestHash: existing.request_hash,
        status: existing.status,
        approvalExpiresAt: existing.approval_expires_at,
        isNew: false,
      };
    }
  }

  const requestId = ulid();
  const now = nowIso();
  const approvalExpiresAt = new Date(
    Date.now() + params.approvalTtlMs
  ).toISOString();

  db()
    .query(
      "INSERT INTO proxy_requests (id, user_id, api_key_id, api_key_label_snapshot, requester_ip, upstream_url, method, request_headers_json, request_body_base64, request_hash, consent_hint, status, created_at, updated_at, approval_expires_at, idempotency_key, upstream_http_status, upstream_content_type, upstream_bytes, result_state, error_code, error_message) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'NONE', NULL, NULL);"
    )
    .run(
      requestId,
      params.userId,
      params.apiKeyId,
      params.apiKeyLabelSnapshot,
      params.requesterIp ?? null,
      canonicalUrl,
      method,
      JSON.stringify(canonicalHeaders),
      params.bodyBase64 ?? null,
      requestHash,
      params.consentHint ?? null,
      "PENDING_APPROVAL",
      now,
      now,
      approvalExpiresAt,
      params.idempotencyKey ?? null
    );

  return {
    requestId,
    canonicalUpstreamUrl: canonicalUrl,
    requestHash,
    status: "PENDING_APPROVAL",
    approvalExpiresAt,
    isNew: true,
  };
}

export function getProxyRequestForUser(params: {
  requestId: string;
  userId: string;
}): {
  id: string;
  user_id: string;
  api_key_label_snapshot: string;
  upstream_url: string;
  request_hash: string;
  consent_hint: string | null;
  status: string;
  approval_expires_at: string;
} | null {
  return db()
    .query(
      "SELECT id, user_id, api_key_label_snapshot, upstream_url, request_hash, consent_hint, status, approval_expires_at FROM proxy_requests WHERE id = ? AND user_id = ?;"
    )
    .get(params.requestId, params.userId) as {
    id: string;
    user_id: string;
    api_key_label_snapshot: string;
    upstream_url: string;
    request_hash: string;
    consent_hint: string | null;
    status: string;
    approval_expires_at: string;
  } | null;
}

export function decideProxyRequest(params: {
  requestId: string;
  userId: string;
  decision: "approved" | "denied";
  telegramUserId: number;
  telegramChatId: number;
  telegramMessageId: number;
}): { ok: true } | { ok: false; reason: string } {
  const row = db()
    .query(
      "SELECT status, approval_expires_at FROM proxy_requests WHERE id = ? AND user_id = ?;"
    )
    .get(params.requestId, params.userId) as {
    status: string;
    approval_expires_at: string;
  } | null;

  if (!row) return { ok: false, reason: "not_found" };
  if (row.status !== "PENDING_APPROVAL")
    return { ok: false, reason: "not_pending" };

  const exp = Date.parse(row.approval_expires_at);
  if (Number.isFinite(exp) && Date.now() > exp) {
    db()
      .query(
        "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' WHERE id = ? AND user_id = ? AND status = 'PENDING_APPROVAL';"
      )
      .run(nowIso(), params.requestId, params.userId);
    return { ok: false, reason: "expired" };
  }

  const now = nowIso();
  const newStatus = params.decision === "approved" ? "APPROVED" : "DENIED";
  const errorCode = params.decision === "denied" ? "DENIED" : null;

  try {
    db().transaction(() => {
      db()
        .query(
          "UPDATE proxy_requests SET status = ?, updated_at = ?, error_code = ?, error_message = NULL WHERE id = ? AND user_id = ? AND status = 'PENDING_APPROVAL';"
        )
        .run(newStatus, now, errorCode, params.requestId, params.userId);

      db()
        .query(
          "INSERT INTO approvals (request_id, telegram_chat_id, telegram_message_id, decision, decided_at, decided_by_telegram_user_id) VALUES (?, ?, ?, ?, ?, ?);"
        )
        .run(
          params.requestId,
          params.telegramChatId,
          params.telegramMessageId,
          params.decision,
          now,
          params.telegramUserId
        );
    })();
  } catch {
    return { ok: false, reason: "already_decided" };
  }

  return { ok: true };
}
