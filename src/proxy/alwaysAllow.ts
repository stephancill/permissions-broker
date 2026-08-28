import { ulid } from "ulid";

import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export function getAlwaysAllowKey(params: {
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
  const method = params.method.toUpperCase();
  // "Endpoint" means method + host + path (query is intentionally excluded).
  const upstreamHost = params.url.hostname;
  const upstreamPath = params.url.pathname || "/";
  return {
    apiKeyId: params.apiKeyId,
    requesterIp: params.requesterIp,
    method,
    upstreamHost,
    upstreamPath,
  };
}

export async function hasAlwaysAllowRule(params: {
  userId: string;
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
}): Promise<boolean> {
  const k = getAlwaysAllowKey({
    apiKeyId: params.apiKeyId,
    requesterIp: params.requesterIp,
    method: params.method,
    url: params.url,
  });

  const database = await db();
  const row = (await database
    .query(
      "SELECT id FROM proxy_always_allow_rules WHERE user_id = ? AND api_key_id = ? AND requester_ip = ? AND method = ? AND upstream_host = ? AND upstream_path = ? AND revoked_at IS NULL LIMIT 1;"
    )
    .get(
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath
    )) as {
    id: string;
  } | null;

  return Boolean(row);
}

export async function upsertAlwaysAllowRule(params: {
  userId: string;
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
}): Promise<{ ruleId: string }> {
  const k = getAlwaysAllowKey({
    apiKeyId: params.apiKeyId,
    requesterIp: params.requesterIp,
    method: params.method,
    url: params.url,
  });
  const id = ulid();
  const now = nowIso();
  const database = await db();

  // If the rule already exists (even if previously revoked), re-enable it.
  await database
    .query(
      "INSERT INTO proxy_always_allow_rules (id, user_id, api_key_id, requester_ip, method, upstream_host, upstream_path, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) " +
        "ON CONFLICT(user_id, api_key_id, requester_ip, method, upstream_host, upstream_path) DO UPDATE SET revoked_at = NULL;"
    )
    .run(
      id,
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      now
    );

  // Fetch the canonical id (might be the pre-existing row).
  const row = (await database
    .query(
      "SELECT id FROM proxy_always_allow_rules WHERE user_id = ? AND api_key_id = ? AND requester_ip = ? AND method = ? AND upstream_host = ? AND upstream_path = ? AND revoked_at IS NULL LIMIT 1;"
    )
    .get(
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath
    )) as {
    id: string;
  } | null;

  return { ruleId: row?.id ?? id };
}
