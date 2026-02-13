import { ulid } from "ulid";

import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export function createConnectState(params: {
  userId: string;
  provider: string;
  ttlMs: number;
}): { state: string; expiresAt: string } {
  const state = `cs_${ulid()}`;
  const now = nowIso();
  const expiresAt = new Date(Date.now() + params.ttlMs).toISOString();

  db()
    .query(
      "INSERT INTO connect_states (state, user_id, provider, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL);"
    )
    .run(state, params.userId, params.provider, now, expiresAt);

  return { state, expiresAt };
}

export function getConnectState(params: { state: string; provider: string }): {
  userId: string;
} {
  const row = db()
    .query(
      "SELECT user_id, expires_at, used_at FROM connect_states WHERE state = ? AND provider = ? LIMIT 1;"
    )
    .get(params.state, params.provider) as {
    user_id: string;
    expires_at: string;
    used_at: string | null;
  } | null;

  if (!row) throw new Error("invalid state");

  const exp = Date.parse(row.expires_at);
  if (Number.isFinite(exp) && Date.now() > exp)
    throw new Error("expired state");
  if (row.used_at) throw new Error("used state");

  return { userId: row.user_id };
}

export function markConnectStateUsed(state: string): void {
  db()
    .query(
      "UPDATE connect_states SET used_at = ? WHERE state = ? AND used_at IS NULL;"
    )
    .run(nowIso(), state);
}
