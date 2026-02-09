import { randomBase64Url } from "../crypto/random";
import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export function createOauthState(params: {
  userId: string;
  provider: string;
  ttlMs: number;
  pkceVerifier?: string;
}): { state: string } {
  const state = randomBase64Url(32);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + params.ttlMs).toISOString();

  db()
    .query(
      "INSERT INTO oauth_states (state, user_id, provider, created_at, expires_at, used_at, pkce_verifier) VALUES (?, ?, ?, ?, ?, NULL, ?);"
    )
    .run(
      state,
      params.userId,
      params.provider,
      createdAt,
      expiresAt,
      params.pkceVerifier ?? null
    );

  return { state };
}

export function getOauthState(params: { state: string; provider: string }): {
  userId: string;
  pkceVerifier: string | null;
} {
  const row = db()
    .query(
      "SELECT user_id, pkce_verifier, expires_at, used_at FROM oauth_states WHERE state = ? AND provider = ?;"
    )
    .get(params.state, params.provider) as {
    user_id: string;
    pkce_verifier: string | null;
    expires_at: string;
    used_at: string | null;
  } | null;

  if (!row) throw new Error("invalid state");
  if (row.used_at) throw new Error("state already used");
  const expiresAt = Date.parse(row.expires_at);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt)
    throw new Error("state expired");

  return { userId: row.user_id, pkceVerifier: row.pkce_verifier };
}

export function markOauthStateUsed(state: string): void {
  db()
    .query("UPDATE oauth_states SET used_at = ? WHERE state = ?;")
    .run(nowIso(), state);
}
