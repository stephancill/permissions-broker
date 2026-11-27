import type { MiddlewareHandler } from "hono";

import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { requestOrigin } from "./requestOrigin";

export type ApiKeyAuth = {
  userId: string;
  apiKeyId: string;
  apiKeyLabel: string;
  keyType: "persistent" | "session";
  expiresAt: string | null;
};

declare module "hono" {
  interface ContextVariableMap {
    apiKeyAuth: ApiKeyAuth;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function parseBearer(authorization: string | undefined): string | null {
  if (!authorization) return null;
  const [scheme, token] = authorization.split(" ", 2);
  if (!scheme || !token) return null;
  if (scheme.toLowerCase() !== "bearer") return null;
  return token.trim() || null;
}

export const requireApiKey: MiddlewareHandler = async (c, next) => {
  const token = parseBearer(c.req.header("authorization"));
  if (!token) return c.json({ error: "missing_api_key" }, 401);

  const keyHash = await sha256Hex(token);
  const database = await db();
  const row = (await database
    .query(
      "SELECT id, user_id, label, key_type, expires_at FROM api_keys WHERE key_hash = ? LIMIT 1;"
    )
    .get(keyHash)) as {
    id: string;
    user_id: string;
    label: string;
    key_type: string;
    expires_at: string | null;
  } | null;

  if (!row) return c.json({ error: "invalid_api_key" }, 401);
  // Session keys stop working at expiry even before the sweeper deletes them.
  if (row.expires_at && Date.now() >= Date.parse(row.expires_at)) {
    return c.json({ error: "api_key_expired" }, 401);
  }

  const origin = requestOrigin(c);
  await database
    .query(
      "UPDATE api_keys SET last_used_at = ?, last_used_ip = ?, last_used_user_agent = ?, last_used_location = ? WHERE id = ?;"
    )
    .run(nowIso(), origin.ip, origin.userAgent, origin.location, row.id);

  c.set("apiKeyAuth", {
    userId: row.user_id,
    apiKeyId: row.id,
    apiKeyLabel: row.label,
    keyType: row.key_type === "session" ? "session" : "persistent",
    expiresAt: row.expires_at,
  });

  await next();
};
