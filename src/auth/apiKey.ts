import type { MiddlewareHandler } from "hono";

import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";

export type ApiKeyAuth = {
  userId: string;
  apiKeyId: string;
  apiKeyLabel: string;
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
  const row = db()
    .query(
      "SELECT id, user_id, label, revoked_at FROM api_keys WHERE key_hash = ? LIMIT 1;"
    )
    .get(keyHash) as {
    id: string;
    user_id: string;
    label: string;
    revoked_at: string | null;
  } | null;

  if (!row) return c.json({ error: "invalid_api_key" }, 401);
  if (row.revoked_at) return c.json({ error: "api_key_revoked" }, 403);

  db()
    .query("UPDATE api_keys SET last_used_at = ? WHERE id = ?;")
    .run(nowIso(), row.id);

  c.set("apiKeyAuth", {
    userId: row.user_id,
    apiKeyId: row.id,
    apiKeyLabel: row.label,
  });

  await next();
};
