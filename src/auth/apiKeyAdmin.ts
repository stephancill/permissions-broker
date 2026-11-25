import { ulid } from "ulid";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";

// API key management for the PWA. The plaintext key is returned exactly once.

export const ApiKeyLabelSchema = z
  .string()
  .transform((s) => s.trim().replace(/\s+/g, " "))
  .pipe(z.string().min(1).max(64));

export type ApiKeyRow = {
  id: string;
  label: string;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
};

function nowIso(): string {
  return new Date().toISOString();
}

export async function listApiKeys(userId: string): Promise<ApiKeyRow[]> {
  const database = await db();
  return database
    .query(
      "SELECT id, label, created_at, revoked_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY revoked_at IS NOT NULL, created_at DESC;"
    )
    .all<ApiKeyRow>(userId);
}

export async function insertApiKey(params: {
  userId: string;
  label: string;
}): Promise<{ id: string; keyPlain: string }> {
  const keyPlain = `pb_${randomBase64Url(32)}`;
  const id = ulid();
  const now = nowIso();
  const database = await db();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(id, params.userId, params.label, await sha256Hex(keyPlain), now, now);
  return { id, keyPlain };
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
    event: { apiKeyId: created.id, label: params.label },
  });
  return created;
}

async function getOwnedKey(params: {
  userId: string;
  apiKeyId: string;
}): Promise<ApiKeyRow> {
  const database = await db();
  const row = await database
    .query(
      "SELECT id, label, created_at, revoked_at, last_used_at FROM api_keys WHERE id = ? AND user_id = ?;"
    )
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
  if (row.revoked_at) throw new ApiKeyError("Revoked keys can't be renamed.");
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

export async function revokeApiKey(params: {
  userId: string;
  sessionId: string;
  apiKeyId: string;
}): Promise<void> {
  const row = await getOwnedKey(params);
  if (row.revoked_at) return;
  const database = await db();
  const now = nowIso();
  await database
    .query(
      "UPDATE api_keys SET revoked_at = ?, updated_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;"
    )
    .run(now, now, row.id, params.userId);
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_revoked",
    event: { apiKeyId: row.id },
  });
}

// Revokes the key and issues a new one under the same label. The old key is
// relabelled because labels are unique per user.
export async function rotateApiKey(params: {
  userId: string;
  sessionId: string;
  apiKeyId: string;
}): Promise<{ id: string; keyPlain: string; label: string }> {
  const row = await getOwnedKey(params);
  if (row.revoked_at) throw new ApiKeyError("Revoked keys can't be rotated.");

  const now = nowIso();
  const freedLabel = `${row.label} (revoked ${now.slice(0, 10)} ${row.id.slice(-6)})`;
  const database = await db();
  await database
    .query(
      "UPDATE api_keys SET revoked_at = ?, updated_at = ?, label = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;"
    )
    .run(now, now, freedLabel, row.id, params.userId);

  const created = await insertApiKey({
    userId: params.userId,
    label: row.label,
  });
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "api_key_rotated",
    event: { oldApiKeyId: row.id, newApiKeyId: created.id, label: row.label },
  });
  return { ...created, label: row.label };
}
