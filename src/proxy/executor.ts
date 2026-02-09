import { auditEvent } from "../audit/audit";
import { evictExpired, setCachedResult } from "../cache/resultCache";
import { decryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { env } from "../env";
import { refreshAccessToken } from "../oauth/flow";
import { getProvider } from "../oauth/registry";
import { readBodyWithLimit } from "./readLimit";

function nowIso(): string {
  return new Date().toISOString();
}

const MAX_RESPONSE_BYTES = 1024 * 1024;
const RESULT_TTL_MS = 2 * 60_000;

async function executeOnce(): Promise<boolean> {
  const row = db()
    .query(
      "SELECT id, user_id, upstream_url FROM proxy_requests WHERE status = 'APPROVED' ORDER BY created_at ASC LIMIT 1;"
    )
    .get() as { id: string; user_id: string; upstream_url: string } | null;

  if (!row) return false;

  const claimed = db()
    .query(
      "UPDATE proxy_requests SET status = 'EXECUTING', updated_at = ? WHERE id = ? AND status = 'APPROVED';"
    )
    .run(nowIso(), row.id).changes;

  if (claimed !== 1) return true;

  try {
    const acct = db()
      .query(
        "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'google' AND status = 'active' LIMIT 1;"
      )
      .get(row.user_id) as { refresh_token_ciphertext: Uint8Array } | null;

    if (!acct) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'NO_LINKED_ACCOUNT' WHERE id = ?;"
        )
        .run(nowIso(), row.id);
      return true;
    }

    if (!env.APP_SECRET) {
      db()
        .query(
          "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = 'APP_SECRET_NOT_CONFIGURED' WHERE id = ?;"
        )
        .run(nowIso(), row.id);
      return true;
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
    const body = await readBodyWithLimit(res.body, MAX_RESPONSE_BYTES);

    setCachedResult(
      row.id,
      {
        status: res.status,
        contentType,
        body,
      },
      RESULT_TTL_MS
    );

    db()
      .query(
        "UPDATE proxy_requests SET status = 'SUCCEEDED', updated_at = ?, upstream_http_status = ?, upstream_content_type = ?, upstream_bytes = ?, result_state = 'AVAILABLE' WHERE id = ?;"
      )
      .run(nowIso(), res.status, contentType, body.byteLength, row.id);

    auditEvent({
      userId: row.user_id,
      requestId: row.id,
      actorType: "system",
      actorId: "executor",
      eventType: "proxy_request_executed",
      event: { status: res.status, bytes: body.byteLength },
    });
  } catch (err) {
    const code = err instanceof Error ? err.message : "UPSTREAM_FAILED";
    db()
      .query(
        "UPDATE proxy_requests SET status = 'FAILED', updated_at = ?, error_code = ? WHERE id = ?;"
      )
      .run(nowIso(), code, row.id);
  }

  return true;
}

export async function startExecutorLoop(): Promise<void> {
  for (;;) {
    await executeOnce();
    evictExpired();
    await new Promise((r) => setTimeout(r, 250));
  }
}
