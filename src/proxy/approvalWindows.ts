// Time-boxed approvals ("approve for N minutes"). They replace permanent
// always-allow rules: the broker cannot decrypt credentials without a
// passkey approval, so auto-approval reuses the DEK released by the approval
// that opened the window (the window's grant) until it expires.

import { ulid } from "ulid";

import { db } from "../db/client";

export const APPROVAL_WINDOW_MINUTES = [15, 60] as const;

// "endpoint": method + host + path. "provider": every request routed to the
// provider (advanced; still scoped to API key + requester IP).
export const APPROVAL_WINDOW_SCOPES = ["endpoint", "provider"] as const;
export type ApprovalWindowScope = (typeof APPROVAL_WINDOW_SCOPES)[number];

// Endpoint columns are NOT NULL; provider-scoped windows store this instead.
const ANY = "*";

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
  providerId: string;
}): Promise<{
  id: string;
  grantId: string | null;
  expiresAt: string;
  scope: ApprovalWindowScope;
} | null> {
  const k = getApprovalWindowScope(params);
  const database = await db();
  const row = (await database
    .query(
      "SELECT id, grant_id, expires_at, scope FROM approval_windows WHERE user_id = ? AND api_key_id = ? AND requester_ip = ? AND expires_at > ? AND ((scope = 'endpoint' AND method = ? AND upstream_host = ? AND upstream_path = ?) OR (scope = 'provider' AND provider_id = ?)) ORDER BY expires_at DESC LIMIT 1;"
    )
    .get(
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      nowIso(),
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      params.providerId
    )) as {
    id: string;
    grant_id: string | null;
    expires_at: string;
    scope: ApprovalWindowScope;
  } | null;

  return row
    ? {
        id: row.id,
        grantId: row.grant_id,
        expiresAt: row.expires_at,
        scope: row.scope,
      }
    : null;
}

export async function createApprovalWindow(params: {
  windowId?: string;
  userId: string;
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
  scope: ApprovalWindowScope;
  providerId: string | null;
  grantId: string | null;
  expiresAt: string;
}): Promise<{ windowId: string }> {
  if (params.scope === "provider" && !params.providerId) {
    throw new Error("provider-scoped approval window requires a provider id");
  }
  const endpoint = getApprovalWindowScope(params);
  const k =
    params.scope === "provider"
      ? { ...endpoint, method: ANY, upstreamHost: ANY, upstreamPath: ANY }
      : endpoint;
  const windowId = params.windowId ?? ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO approval_windows (id, user_id, api_key_id, requester_ip, method, upstream_host, upstream_path, scope, provider_id, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    )
    .run(
      windowId,
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      params.scope,
      params.providerId,
      params.grantId,
      nowIso(),
      params.expiresAt
    );
  return { windowId };
}
