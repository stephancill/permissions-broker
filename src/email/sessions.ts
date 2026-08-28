import { ulid } from "ulid";

import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export type EmailSessionRow = {
  id: string;
  user_id: string;
  api_key_id: string;
  status: string;
  approval_expires_at: string;
  last_activity_at: string | null;
  consent_hint: string | null;
};

export async function createEmailSession(params: {
  userId: string;
  apiKeyId: string;
  consentHint?: string;
  approvalTtlMs: number;
}): Promise<{ sessionId: string; approvalExpiresAt: string }> {
  const sessionId = ulid();
  const now = nowIso();
  const approvalExpiresAt = new Date(
    Date.now() + params.approvalTtlMs
  ).toISOString();

  const database = await db();
  await database
    .query(
      "INSERT INTO email_sessions (id, user_id, api_key_id, status, created_at, updated_at, approval_expires_at, last_activity_at, consent_hint) " +
        "VALUES (?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, NULL, ?);"
    )
    .run(
      sessionId,
      params.userId,
      params.apiKeyId,
      now,
      now,
      approvalExpiresAt,
      params.consentHint ?? null
    );

  return { sessionId, approvalExpiresAt };
}

export async function getEmailSessionKeyScoped(params: {
  sessionId: string;
  userId: string;
  apiKeyId: string;
}): Promise<EmailSessionRow | null> {
  const database = await db();
  return (await database
    .query(
      "SELECT id, user_id, api_key_id, status, approval_expires_at, last_activity_at, consent_hint FROM email_sessions WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(
      params.sessionId,
      params.userId,
      params.apiKeyId
    )) as EmailSessionRow | null;
}

export async function setEmailSessionStatus(params: {
  sessionId: string;
  userId: string;
  status: string;
}): Promise<void> {
  const database = await db();
  await database
    .query(
      "UPDATE email_sessions SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?;"
    )
    .run(params.status, nowIso(), params.sessionId, params.userId);
}

export async function touchEmailSessionActivity(
  sessionId: string
): Promise<void> {
  const database = await db();
  await database
    .query(
      "UPDATE email_sessions SET last_activity_at = ?, updated_at = ? WHERE id = ?;"
    )
    .run(nowIso(), nowIso(), sessionId);
}
