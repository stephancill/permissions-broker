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

export function parseBearer(authorization: string | undefined): string | null {
  if (!authorization) return null;
  const [scheme, token] = authorization.split(" ", 2);
  if (!scheme || !token) return null;
  if (scheme.toLowerCase() !== "bearer") return null;
  return token.trim() || null;
}

export type ApiKeyAuthResult =
  | { ok: true; auth: ApiKeyAuth }
  | {
      ok: false;
      error: "missing_api_key" | "invalid_api_key" | "api_key_revoked";
    };

// Looks up a bearer token and records its use. Shared by requireApiKey and
// the MCP endpoint (which answers failures with an OAuth challenge instead).
export async function authenticateApiKey(
  authorization: string | undefined
): Promise<ApiKeyAuthResult> {
  const token = parseBearer(authorization);
  if (!token) return { ok: false, error: "missing_api_key" };

  const keyHash = await sha256Hex(token);
  const database = await db();
  const row = (await database
    .query(
      "SELECT id, user_id, label, revoked_at FROM api_keys WHERE key_hash = ? LIMIT 1;"
    )
    .get(keyHash)) as {
    id: string;
    user_id: string;
    label: string;
    revoked_at: string | null;
  } | null;

  if (!row) return { ok: false, error: "invalid_api_key" };
  if (row.revoked_at) return { ok: false, error: "api_key_revoked" };

  await database
    .query("UPDATE api_keys SET last_used_at = ? WHERE id = ?;")
    .run(nowIso(), row.id);

  return {
    ok: true,
    auth: { userId: row.user_id, apiKeyId: row.id, apiKeyLabel: row.label },
  };
}

export const requireApiKey: MiddlewareHandler = async (c, next) => {
  const result = await authenticateApiKey(c.req.header("authorization"));
  if (!result.ok) {
    return c.json(
      { error: result.error },
      result.error === "api_key_revoked" ? 403 : 401
    );
  }
  c.set("apiKeyAuth", result.auth);
  await next();
};
