// Time-boxed approvals ("approve for N minutes"). They replace permanent
// always-allow rules: the broker cannot decrypt credentials without a
// passkey approval, so auto-approval reuses the DEK released by the approval
// that opened the window (the window's grant) until it expires.

import { ulid } from "ulid";

import { db } from "../db/client";

export const APPROVAL_WINDOW_MINUTES = [15, 60] as const;

function nowIso(): string {
  return new Date().toISOString();
}

export function getApprovalWindowScope(params: {
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
}): {
  apiKeyId: string;
  requesterIp: string;
  method: string;
  upstreamHost: string;
  upstreamPath: string;
} {
  // "Endpoint" means method + host + path (query is intentionally excluded).
  return {
    apiKeyId: params.apiKeyId,
    requesterIp: params.requesterIp,
    method: params.method.toUpperCase(),
    upstreamHost: params.url.hostname,
    upstreamPath: params.url.pathname || "/",
  };
}

export async function findActiveApprovalWindow(params: {
  userId: string;
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
}): Promise<{ id: string; grantId: string | null; expiresAt: string } | null> {
  const k = getApprovalWindowScope(params);
  const database = await db();
  const row = (await database
    .query(
      "SELECT id, grant_id, expires_at FROM approval_windows WHERE user_id = ? AND api_key_id = ? AND requester_ip = ? AND method = ? AND upstream_host = ? AND upstream_path = ? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1;"
    )
    .get(
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      nowIso()
    )) as { id: string; grant_id: string | null; expires_at: string } | null;

  return row
    ? { id: row.id, grantId: row.grant_id, expiresAt: row.expires_at }
    : null;
}

export async function createApprovalWindow(params: {
  windowId?: string;
  userId: string;
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
  grantId: string | null;
  expiresAt: string;
}): Promise<{ windowId: string }> {
  const k = getApprovalWindowScope(params);
  const windowId = params.windowId ?? ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO approval_windows (id, user_id, api_key_id, requester_ip, method, upstream_host, upstream_path, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    )
    .run(
      windowId,
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      params.grantId,
      nowIso(),
      params.expiresAt
    );
  return { windowId };
}
