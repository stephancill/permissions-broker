import { ulid } from "ulid";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import type { RequestOrigin } from "./requestOrigin";

// API key management for the PWA. The plaintext key is returned exactly once.
// Keys are deleted rather than revoked, so a label can be reused right away.
// Deleting cascades to the key's requests and sessions; audit_events keep
// the record.

export const ApiKeyLabelSchema = z
  .string()
  .transform((s) => s.trim().replace(/\s+/g, " "))
  .pipe(z.string().min(1).max(64));

export type ApiKeyType = "persistent" | "session";

// Session keys (device sign-in for agents) expire on their own.
export const SESSION_KEY_TTL_SECONDS = 6 * 60 * 60;

export type ApiKeyRow = {
  id: string;
  label: string;
  key_type: ApiKeyType;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_ip: string | null;
  created_user_agent: string | null;
  created_location: string | null;
  last_used_ip: string | null;
  last_used_user_agent: string | null;
  last_used_location: string | null;
};

const ROW_COLUMNS =
  "id, label, key_type, created_at, expires_at, last_used_at, created_ip, created_user_agent, created_location, last_used_ip, last_used_user_agent, last_used_location";

function nowIso(): string {
  return new Date().toISOString();
}

// Expired session keys can linger until the sweeper runs; they are not
// listed (or usable).
export async function listApiKeys(userId: string): Promise<ApiKeyRow[]> {
  const database = await db();
  return database
    .query(
      `SELECT ${ROW_COLUMNS} FROM api_keys WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC;`
    )
    .all<ApiKeyRow>(userId, nowIso());
}

export async function isLabelTaken(params: {
  userId: string;
  label: string;
}): Promise<boolean> {
  const database = await db();
  const row = await database
    .query("SELECT 1 AS x FROM api_keys WHERE user_id = ? AND label = ?;")
    .get(params.userId, params.label);
  return row != null;
}

// The label itself if it's free, otherwise "<label> 2", "<label> 3", ...
export async function suggestFreeLabel(params: {
  userId: string;
  label: string;
}): Promise<string> {
  const base = params.label.slice(0, 60);
  for (let n = 1; n < 100; n++) {
    const label = n === 1 ? params.label : `${base} ${n}`;
    if (!(await isLabelTaken({ userId: params.userId, label }))) return label;
  }
  return `${base.slice(0, 56)} ${ulid().slice(-6)}`;
}

export async function insertApiKey(params: {
  userId: string;
  label: string;
  keyType?: ApiKeyType;
  origin?: RequestOrigin;
}): Promise<{ id: string; keyPlain: string; expiresAt: string | null }> {
  const keyPlain = `pb_${randomBase64Url(32)}`;
  const id = ulid();
  const now = Date.now();
  const keyType = params.keyType ?? "persistent";
  const expiresAt =
    keyType === "session"
      ? new Date(now + SESSION_KEY_TTL_SECONDS * 1000).toISOString()
      : null;
  const database = await db();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at, key_type, expires_at, created_ip, created_user_agent, created_location) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?);"
    )
    .run(
      id,
      params.userId,
      params.label,
      await sha256Hex(keyPlain),
      new Date(now).toISOString(),
      new Date(now).toISOString(),
      keyType,
      expiresAt,
      params.origin?.ip ?? null,
      params.origin?.userAgent ?? null,
      params.origin?.location ?? null
    );
  return { id, keyPlain, expiresAt };
}

export function isUniqueLabelError(err: unknown): boolean {
  return (
    err instanceof Error && /UNIQUE constraint failed/i.test(err.message ?? "")
  );
}

export class ApiKeyError extends Error {}

export async function createApiKey(params: {
  userId: string;
  sessionId: string;
  label: string;
  origin?: RequestOrigin;
}): Promise<{ id: string; keyPlain: string }> {
  let created: { id: string; keyPlain: string };
  try {
    created = await insertApiKey(params);
  } catch (err) {
    if (isUniqueLabelError(err)) {
      throw new ApiKeyError(`A key labelled "${params.label}" already exists.`);
    }
    throw err;
  }
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_created",
    event: {
      apiKeyId: created.id,
      label: params.label,
      keyType: "persistent",
      ip: params.origin?.ip ?? null,
      location: params.origin?.location ?? null,
      userAgent: params.origin?.userAgent ?? null,
    },
  });
  return created;
}

async function getOwnedKey(params: {
  userId: string;
  apiKeyId: string;
}): Promise<ApiKeyRow> {
  const database = await db();
  const row = await database
    .query(`SELECT ${ROW_COLUMNS} FROM api_keys WHERE id = ? AND user_id = ?;`)
    .get<ApiKeyRow>(params.apiKeyId, params.userId);
  if (!row) throw new ApiKeyError("Key not found.");
  return row;
}

export async function renameApiKey(params: {
  userId: string;
  sessionId: string;
  apiKeyId: string;
  label: string;
}): Promise<void> {
  const row = await getOwnedKey(params);
  const database = await db();
  try {
    await database
      .query(
        "UPDATE api_keys SET label = ?, updated_at = ? WHERE id = ? AND user_id = ?;"
      )
      .run(params.label, nowIso(), row.id, params.userId);
  } catch (err) {
    if (isUniqueLabelError(err)) {
      throw new ApiKeyError(`A key labelled "${params.label}" already exists.`);
    }
    throw err;
  }
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_renamed",
    event: { apiKeyId: row.id, newLabel: params.label },
  });
}

export async function deleteApiKey(params: {
  userId: string;
  sessionId: string;
  apiKeyId: string;
}): Promise<void> {
  const row = await getOwnedKey(params);
  const database = await db();
  await database
    .query("DELETE FROM api_keys WHERE id = ? AND user_id = ?;")
    .run(row.id, params.userId);
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_deleted",
    event: { apiKeyId: row.id, label: row.label, keyType: row.key_type },
  });
}

// Issues a new secret for the same key: the old one stops working at once,
// while the key's id, label and history stay.
export async function rotateApiKey(params: {
  userId: string;
  sessionId: string;
  apiKeyId: string;
  origin?: RequestOrigin;
}): Promise<{ id: string; keyPlain: string; label: string }> {
  const row = await getOwnedKey(params);
  if (row.key_type === "session") {
    throw new ApiKeyError(
      "Session keys can't be rotated; delete it and sign in again."
    );
  }
  const keyPlain = `pb_${randomBase64Url(32)}`;
  const database = await db();
  await database
    .query(
      "UPDATE api_keys SET key_hash = ?, updated_at = ?, last_used_at = NULL, last_used_ip = NULL, last_used_user_agent = NULL, last_used_location = NULL, created_ip = ?, created_user_agent = ?, created_location = ? WHERE id = ? AND user_id = ?;"
    )
    .run(
      await sha256Hex(keyPlain),
      nowIso(),
      params.origin?.ip ?? null,
      params.origin?.userAgent ?? null,
      params.origin?.location ?? null,
      row.id,
      params.userId
    );
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_rotated",
    event: {
      apiKeyId: row.id,
      label: row.label,
      ip: params.origin?.ip ?? null,
      location: params.origin?.location ?? null,
    },
  });
  return { id: row.id, keyPlain, label: row.label };
}

export async function sweepExpiredApiKeys(): Promise<void> {
  const database = await db();
  await database
    .query(
      "DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < ?;"
    )
    .run(nowIso());
}
