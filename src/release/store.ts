import { ulid } from "ulid";

import { encryptUtf8 } from "../crypto/aesgcm";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import type { SessionScope } from "./ascAllowlist";

function nowIso(): string {
  return new Date().toISOString();
}

// Approval for a new session or policy.
export const RELEASE_APPROVAL_TTL_MS = 10 * 60_000;
// An approved session ends at this hard cap, or after this much inactivity.
export const RELEASE_SESSION_MAX_MS = 45 * 60_000;
export const RELEASE_SESSION_IDLE_MS = 15 * 60_000;

export type ReleasePolicyRow = {
  id: string;
  user_id: string;
  repository: string;
  workflow_path: string;
  ref: string;
  bundle_ids_json: string;
  status: string;
  created_at: string;
  approval_expires_at: string;
};

export async function createReleasePolicy(params: {
  userId: string;
  repository: string;
  workflowPath: string;
  ref: string;
  bundleIds: string[];
}): Promise<string> {
  const id = ulid();
  const now = nowIso();
  const database = await db();
  await database
    .query(
      "INSERT INTO release_policies (id, user_id, repository, workflow_path, ref, bundle_ids_json, status, created_at, updated_at, approval_expires_at) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?);"
    )
    .run(
      id,
      params.userId,
      params.repository,
      params.workflowPath,
      params.ref,
      JSON.stringify(params.bundleIds),
      now,
      now,
      new Date(Date.now() + RELEASE_APPROVAL_TTL_MS).toISOString()
    );
  return id;
}

export async function listReleasePolicies(
  userId: string
): Promise<ReleasePolicyRow[]> {
  const database = await db();
  return database
    .query(
      "SELECT id, user_id, repository, workflow_path, ref, bundle_ids_json, status, created_at, approval_expires_at FROM release_policies WHERE user_id = ? AND status IN ('ACTIVE', 'PENDING_APPROVAL') ORDER BY created_at DESC;"
    )
    .all<ReleasePolicyRow>(userId);
}

export async function getReleasePolicy(
  id: string
): Promise<ReleasePolicyRow | null> {
  const database = await db();
  return (await database
    .query(
      "SELECT id, user_id, repository, workflow_path, ref, bundle_ids_json, status, created_at, approval_expires_at FROM release_policies WHERE id = ?;"
    )
    .get(id)) as ReleasePolicyRow | null;
}

export async function findActivePolicy(params: {
  repository: string;
  workflowPath: string;
  ref: string;
}): Promise<ReleasePolicyRow | null> {
  const database = await db();
  return (await database
    .query(
      "SELECT id, user_id, repository, workflow_path, ref, bundle_ids_json, status, created_at, approval_expires_at FROM release_policies WHERE repository = ? AND workflow_path = ? AND ref = ? AND status = 'ACTIVE';"
    )
    .get(
      params.repository,
      params.workflowPath,
      params.ref
    )) as ReleasePolicyRow | null;
}

// Activates a pending policy, replacing an active one for the same workflow.
export async function activateReleasePolicy(params: {
  id: string;
  userId: string;
}): Promise<boolean> {
  const policy = await getReleasePolicy(params.id);
  if (
    !policy ||
    policy.user_id !== params.userId ||
    policy.status !== "PENDING_APPROVAL"
  ) {
    return false;
  }
  const database = await db();
  const now = nowIso();
  await database
    .query(
      "UPDATE release_policies SET status = 'REPLACED', updated_at = ? WHERE repository = ? AND workflow_path = ? AND ref = ? AND status = 'ACTIVE';"
    )
    .run(now, policy.repository, policy.workflow_path, policy.ref);
  const res = await database
    .query(
      "UPDATE release_policies SET status = 'ACTIVE', updated_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL';"
    )
    .run(now, params.id);
  return (res.changes ?? 0) === 1;
}

export async function removeReleasePolicy(params: {
  id: string;
  userId: string;
}): Promise<boolean> {
  const database = await db();
  const res = await database
    .query(
      "UPDATE release_policies SET status = 'REMOVED', updated_at = ? WHERE id = ? AND user_id = ? AND status IN ('ACTIVE', 'PENDING_APPROVAL');"
    )
    .run(nowIso(), params.id, params.userId);
  return (res.changes ?? 0) === 1;
}

export type ReleaseSessionRow = {
  id: string;
  user_id: string;
  policy_id: string;
  repository: string;
  workflow_ref: string;
  ref: string;
  sha: string;
  run_id: string;
  run_attempt: string;
  actor: string;
  bundle_ids_json: string;
  version: string;
  build_number: string;
  status: string;
  created_at: string;
  approval_expires_at: string;
  expires_at: string | null;
  last_activity_at: string | null;
  session_secret_hash: string;
  secret_delivered_at: string | null;
  app_ids_json: string | null;
  bundle_resource_ids_json: string;
  build_ids_json: string;
  build_upload_ids_json: string;
  build_upload_file_ids_json: string;
  signed_bundle_ids_json: string;
};

const SESSION_COLUMNS =
  "id, user_id, policy_id, repository, workflow_ref, ref, sha, run_id, run_attempt, actor, bundle_ids_json, version, build_number, status, created_at, approval_expires_at, expires_at, last_activity_at, session_secret_hash, secret_delivered_at, app_ids_json, bundle_resource_ids_json, build_ids_json, build_upload_ids_json, build_upload_file_ids_json, signed_bundle_ids_json";

export async function createReleaseSession(params: {
  userId: string;
  policyId: string;
  repository: string;
  workflowRef: string;
  ref: string;
  sha: string;
  runId: string;
  runAttempt: string;
  actor: string;
  bundleIds: string[];
  version: string;
  buildNumber: string;
}): Promise<{ sessionId: string; approvalExpiresAt: string }> {
  const id = ulid();
  const secret = `rs_${randomBase64Url(32)}`;
  const now = nowIso();
  const approvalExpiresAt = new Date(
    Date.now() + RELEASE_APPROVAL_TTL_MS
  ).toISOString();
  const database = await db();
  await database
    .query(
      `INSERT INTO release_sessions (id, user_id, policy_id, repository, workflow_ref, ref, sha, run_id, run_attempt, actor, bundle_ids_json, version, build_number, status, created_at, updated_at, approval_expires_at, session_secret_hash, session_secret_ciphertext) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, ?, ?);`
    )
    .run(
      id,
      params.userId,
      params.policyId,
      params.repository,
      params.workflowRef,
      params.ref,
      params.sha,
      params.runId,
      params.runAttempt,
      params.actor,
      JSON.stringify(params.bundleIds),
      params.version,
      params.buildNumber,
      now,
      now,
      approvalExpiresAt,
      await sha256Hex(secret),
      await encryptUtf8(secret)
    );
  return { sessionId: id, approvalExpiresAt };
}

export async function getReleaseSession(
  id: string
): Promise<ReleaseSessionRow | null> {
  const database = await db();
  return (await database
    .query(`SELECT ${SESSION_COLUMNS} FROM release_sessions WHERE id = ?;`)
    .get(id)) as ReleaseSessionRow | null;
}

// The secret is handed to the run once; afterwards only its hash remains.
export async function takeSessionSecretCiphertext(
  id: string
): Promise<Uint8Array | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT session_secret_ciphertext FROM release_sessions WHERE id = ? AND secret_delivered_at IS NULL AND session_secret_ciphertext IS NOT NULL;"
    )
    .get(id)) as { session_secret_ciphertext: Uint8Array } | null;
  if (!row) return null;
  const res = await database
    .query(
      "UPDATE release_sessions SET secret_delivered_at = ?, session_secret_ciphertext = NULL WHERE id = ? AND secret_delivered_at IS NULL;"
    )
    .run(nowIso(), id);
  return (res.changes ?? 0) === 1 ? row.session_secret_ciphertext : null;
}

export async function setReleaseSessionStatus(params: {
  id: string;
  from: string[];
  status: string;
  expiresAt?: string;
}): Promise<boolean> {
  const database = await db();
  const placeholders = params.from.map(() => "?").join(", ");
  const res = await database
    .query(
      `UPDATE release_sessions SET status = ?, updated_at = ?, expires_at = COALESCE(?, expires_at) WHERE id = ? AND status IN (${placeholders});`
    )
    .run(
      params.status,
      nowIso(),
      params.expiresAt ?? null,
      params.id,
      ...params.from
    );
  return (res.changes ?? 0) === 1;
}

export function sessionScope(params: {
  session: ReleaseSessionRow;
  certificateId: string;
}): SessionScope {
  const list = (json: string | null) =>
    json ? (JSON.parse(json) as string[]) : [];
  return {
    bundleIds: list(params.session.bundle_ids_json),
    certificateId: params.certificateId,
    appIds: list(params.session.app_ids_json),
    bundleResourceIds: list(params.session.bundle_resource_ids_json),
    buildIds: list(params.session.build_ids_json),
    buildUploadIds: list(params.session.build_upload_ids_json),
    buildUploadFileIds: list(params.session.build_upload_file_ids_json),
  };
}

const SCOPE_COLUMNS: Record<keyof SessionScope, string | null> = {
  bundleIds: null,
  certificateId: null,
  appIds: "app_ids_json",
  bundleResourceIds: "bundle_resource_ids_json",
  buildIds: "build_ids_json",
  buildUploadIds: "build_upload_ids_json",
  buildUploadFileIds: "build_upload_file_ids_json",
};

export async function saveLearnedScope(params: {
  id: string;
  learned: Partial<SessionScope>;
}): Promise<void> {
  const database = await db();
  for (const [key, value] of Object.entries(params.learned)) {
    const column = SCOPE_COLUMNS[key as keyof SessionScope];
    if (!column || !Array.isArray(value)) continue;
    await database
      .query(`UPDATE release_sessions SET ${column} = ? WHERE id = ?;`)
      .run(JSON.stringify(value), params.id);
  }
}

// Records a signature; false when this bundle was already signed in the session.
export async function recordSignedBundle(params: {
  session: ReleaseSessionRow;
  bundleId: string;
}): Promise<boolean> {
  const signed = JSON.parse(params.session.signed_bundle_ids_json) as string[];
  if (signed.includes(params.bundleId)) return false;
  const database = await db();
  const res = await database
    .query(
      "UPDATE release_sessions SET signed_bundle_ids_json = ? WHERE id = ? AND signed_bundle_ids_json = ?;"
    )
    .run(
      JSON.stringify([...signed, params.bundleId]),
      params.session.id,
      params.session.signed_bundle_ids_json
    );
  return (res.changes ?? 0) === 1;
}

export async function touchReleaseSession(id: string): Promise<void> {
  const database = await db();
  const now = nowIso();
  await database
    .query(
      "UPDATE release_sessions SET last_activity_at = ?, updated_at = ?, status = CASE WHEN status = 'APPROVED' THEN 'ACTIVE' ELSE status END WHERE id = ?;"
    )
    .run(now, now, id);
}

export async function cachedAscJwt(params: {
  id: string;
}): Promise<{ ciphertext: Uint8Array; expiresAt: string } | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT asc_jwt_ciphertext, asc_jwt_expires_at FROM release_sessions WHERE id = ?;"
    )
    .get(params.id)) as {
    asc_jwt_ciphertext: Uint8Array | null;
    asc_jwt_expires_at: string | null;
  } | null;
  if (!row?.asc_jwt_ciphertext || !row.asc_jwt_expires_at) return null;
  return {
    ciphertext: row.asc_jwt_ciphertext,
    expiresAt: row.asc_jwt_expires_at,
  };
}

export async function storeAscJwt(params: {
  id: string;
  token: string;
  expiresAt: string;
}): Promise<void> {
  const database = await db();
  await database
    .query(
      "UPDATE release_sessions SET asc_jwt_ciphertext = ?, asc_jwt_expires_at = ? WHERE id = ?;"
    )
    .run(await encryptUtf8(params.token), params.expiresAt, params.id);
}

export async function sweepReleaseState(): Promise<void> {
  const database = await db();
  const now = nowIso();
  const idleBefore = new Date(
    Date.now() - RELEASE_SESSION_IDLE_MS
  ).toISOString();
  await database
    .query(
      "UPDATE release_sessions SET status = 'EXPIRED', updated_at = ? WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(now, now);
  await database
    .query(
      "UPDATE release_sessions SET status = 'CLOSED', updated_at = ?, asc_jwt_ciphertext = NULL, session_secret_ciphertext = NULL WHERE status IN ('APPROVED', 'ACTIVE') AND (expires_at < ? OR COALESCE(last_activity_at, updated_at) < ?);"
    )
    .run(now, now, idleBefore);
  await database
    .query(
      "UPDATE release_policies SET status = 'EXPIRED', updated_at = ? WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(now, now);
  await database
    .query(
      "DELETE FROM credential_grants WHERE target_kind = 'release' AND target_id IN (SELECT id FROM release_sessions WHERE status IN ('CLOSED', 'EXPIRED', 'DENIED'));"
    )
    .run();
}
