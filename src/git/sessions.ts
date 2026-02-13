import { ulid } from "ulid";

import { encryptUtf8 } from "../crypto/aesgcm";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export type GitOperation = "clone" | "fetch" | "pull" | "push";

export type GitSessionRow = {
  id: string;
  user_id: string;
  api_key_id: string;
  provider: string;
  operation: GitOperation;
  repo_owner: string;
  repo_name: string;
  status: string;
  approval_expires_at: string;
  session_secret_hash: string;
  // Not selected by default in getGitSessionKeyScoped.
  allow_default_branch_push: number;
  deny_deletes: number;
  deny_tag_updates: number;
  default_branch_ref: string | null;
};

export async function createGitSession(params: {
  userId: string;
  apiKeyId: string;
  operation: GitOperation;
  repoOwner: string;
  repoName: string;
  approvalTtlMs: number;
}): Promise<{
  sessionId: string;
  sessionSecret: string;
  approvalExpiresAt: string;
}> {
  const sessionId = ulid();
  const sessionSecret = `gs_${randomBase64Url(32)}`;
  const sessionSecretHash = await sha256Hex(sessionSecret);
  const sessionSecretCiphertext = await encryptUtf8(sessionSecret);
  const now = nowIso();
  const approvalExpiresAt = new Date(
    Date.now() + params.approvalTtlMs
  ).toISOString();

  const allowDefault = 0;
  const denyDeletes = 1;
  const denyTags = 1;

  db()
    .query(
      "INSERT INTO git_sessions (id, user_id, api_key_id, provider, operation, repo_owner, repo_name, status, created_at, updated_at, approval_expires_at, last_activity_at, session_secret_hash, session_secret_ciphertext, allow_default_branch_push, deny_deletes, deny_tag_updates, default_branch_ref, error_code, error_message) " +
        "VALUES (?, ?, ?, 'github', ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, NULL, NULL);"
    )
    .run(
      sessionId,
      params.userId,
      params.apiKeyId,
      params.operation,
      params.repoOwner,
      params.repoName,
      now,
      now,
      approvalExpiresAt,
      sessionSecretHash,
      sessionSecretCiphertext,
      allowDefault,
      denyDeletes,
      denyTags
    );

  return { sessionId, sessionSecret, approvalExpiresAt };
}

export function getGitSessionKeyScoped(params: {
  sessionId: string;
  userId: string;
  apiKeyId: string;
}): GitSessionRow | null {
  return db()
    .query(
      "SELECT id, user_id, api_key_id, provider, operation, repo_owner, repo_name, status, approval_expires_at, session_secret_hash, allow_default_branch_push, deny_deletes, deny_tag_updates, default_branch_ref FROM git_sessions WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(
      params.sessionId,
      params.userId,
      params.apiKeyId
    ) as GitSessionRow | null;
}

export function getGitSessionSecretCiphertextKeyScoped(params: {
  sessionId: string;
  userId: string;
  apiKeyId: string;
}): Uint8Array | null {
  const row = db()
    .query(
      "SELECT session_secret_ciphertext FROM git_sessions WHERE id = ? AND user_id = ? AND api_key_id = ?;"
    )
    .get(params.sessionId, params.userId, params.apiKeyId) as {
    session_secret_ciphertext: Uint8Array;
  } | null;

  return row?.session_secret_ciphertext ?? null;
}

export async function validateGitSessionSecret(params: {
  sessionId: string;
  secret: string;
}): Promise<GitSessionRow | null> {
  const row = db()
    .query(
      "SELECT id, user_id, api_key_id, provider, operation, repo_owner, repo_name, status, approval_expires_at, session_secret_hash, allow_default_branch_push, deny_deletes, deny_tag_updates, default_branch_ref FROM git_sessions WHERE id = ?;"
    )
    .get(params.sessionId) as GitSessionRow | null;

  if (!row) return null;
  const h = await sha256Hex(params.secret);
  if (h !== row.session_secret_hash) return null;
  return row;
}

export function setGitSessionStatus(params: {
  sessionId: string;
  userId: string;
  status: string;
  allowDefaultBranchPush?: boolean;
}): void {
  const now = nowIso();
  if (typeof params.allowDefaultBranchPush === "boolean") {
    db()
      .query(
        "UPDATE git_sessions SET status = ?, allow_default_branch_push = ?, updated_at = ? WHERE id = ? AND user_id = ?;"
      )
      .run(
        params.status,
        params.allowDefaultBranchPush ? 1 : 0,
        now,
        params.sessionId,
        params.userId
      );
  } else {
    db()
      .query(
        "UPDATE git_sessions SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?;"
      )
      .run(params.status, now, params.sessionId, params.userId);
  }
}

export function touchGitSessionActivity(sessionId: string): void {
  const now = nowIso();
  db()
    .query(
      "UPDATE git_sessions SET last_activity_at = ?, updated_at = ? WHERE id = ?;"
    )
    .run(now, now, sessionId);
}

export function markGitSessionUsed(sessionId: string): void {
  db()
    .query(
      "UPDATE git_sessions SET status = 'USED', updated_at = ? WHERE id = ?;"
    )
    .run(nowIso(), sessionId);
}

export function storeDefaultBranchRef(params: {
  sessionId: string;
  ref: string;
}): void {
  db()
    .query(
      "UPDATE git_sessions SET default_branch_ref = ?, updated_at = ? WHERE id = ? AND default_branch_ref IS NULL;"
    )
    .run(params.ref, nowIso(), params.sessionId);
}
