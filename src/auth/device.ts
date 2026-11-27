import { ulid } from "ulid";

import { auditEvent } from "../audit/audit";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import {
  type ApiKeyType,
  insertApiKey,
  isUniqueLabelError,
} from "./apiKeyAdmin";
import type { RequestOrigin } from "./requestOrigin";

// OAuth 2.0 Device Authorization Grant (RFC 8628) for issuing API keys to
// CLIs. See docs/DEVICE_AUTHORIZATION.md.

export const DEVICE_CODE_TTL_SECONDS = 10 * 60;
export const DEVICE_POLL_INTERVAL_SECONDS = 5;
// RFC 8628 §3.5: each slow_down adds 5 seconds to the polling interval.
const SLOW_DOWN_STEP_SECONDS = 5;
// Keep finished rows briefly so late polls get expired_token, not invalid_grant.
const SWEEP_GRACE_MS = 60 * 60_000;

// RFC 8628 §6.1: base-20 consonants avoid ambiguous characters and words.
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LENGTH = 8;

export type DeviceAuthorizationRow = {
  id: string;
  user_code: string;
  client_id: string;
  label_hint: string | null;
  key_type: ApiKeyType;
  status: "PENDING" | "APPROVED" | "DENIED" | "CONSUMED";
  user_id: string | null;
  label: string | null;
  approved_session_id: string | null;
  interval_seconds: number;
  last_polled_at: string | null;
  created_at: string;
  expires_at: string;
};

export class DeviceAuthorizationError extends Error {}

function nowIso(): string {
  return new Date().toISOString();
}

function generateUserCode(): string {
  const out: string[] = [];
  while (out.length < USER_CODE_LENGTH) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      // Rejection sampling keeps the distribution uniform (240 = 12 * 20).
      if (b >= 240) continue;
      out.push(USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length] as string);
      if (out.length === USER_CODE_LENGTH) break;
    }
  }
  return `${out.slice(0, 4).join("")}-${out.slice(4).join("")}`;
}

// Accepts what a user might type (lowercase, spaces, missing dash).
export function normalizeUserCode(raw: string): string | null {
  const chars = raw.toUpperCase().replace(/[^A-Z]/g, "");
  if (chars.length !== USER_CODE_LENGTH) return null;
  for (const ch of chars) {
    if (!USER_CODE_ALPHABET.includes(ch)) return null;
  }
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

export async function createDeviceAuthorization(params: {
  clientId: string;
  labelHint: string | null;
  keyType: ApiKeyType;
}): Promise<{
  deviceCode: string;
  userCode: string;
  expiresIn: number;
  interval: number;
}> {
  const database = await db();
  const deviceCode = randomBase64Url(32);
  const deviceCodeHash = await sha256Hex(deviceCode);
  const now = Date.now();

  for (let attempt = 0; attempt < 5; attempt++) {
    const userCode = generateUserCode();
    try {
      await database
        .query(
          "INSERT INTO device_authorizations (id, device_code_hash, user_code, client_id, label_hint, key_type, status, interval_seconds, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?);"
        )
        .run(
          ulid(),
          deviceCodeHash,
          userCode,
          params.clientId,
          params.labelHint,
          params.keyType,
          DEVICE_POLL_INTERVAL_SECONDS,
          new Date(now).toISOString(),
          new Date(now + DEVICE_CODE_TTL_SECONDS * 1000).toISOString()
        );
      return {
        deviceCode,
        userCode,
        expiresIn: DEVICE_CODE_TTL_SECONDS,
        interval: DEVICE_POLL_INTERVAL_SECONDS,
      };
    } catch (err) {
      if (!(err instanceof Error && /UNIQUE/i.test(err.message))) throw err;
    }
  }
  throw new Error("could not allocate a unique user code");
}

const SELECT_COLUMNS =
  "id, user_code, client_id, label_hint, key_type, status, user_id, label, approved_session_id, interval_seconds, last_polled_at, created_at, expires_at";

// A code the signed-in user can still act on.
export async function getPendingDeviceAuthorization(
  userCode: string
): Promise<DeviceAuthorizationRow | null> {
  const database = await db();
  return database
    .query(
      `SELECT ${SELECT_COLUMNS} FROM device_authorizations WHERE user_code = ? AND status = 'PENDING' AND expires_at > ?;`
    )
    .get<DeviceAuthorizationRow>(userCode, nowIso());
}

async function requirePending(
  userCode: string
): Promise<DeviceAuthorizationRow> {
  const row = await getPendingDeviceAuthorization(userCode);
  if (!row) {
    throw new DeviceAuthorizationError(
      "That code is invalid, expired, or already used. Start the sign-in again."
    );
  }
  return row;
}

export async function approveDeviceAuthorization(params: {
  userCode: string;
  userId: string;
  sessionId: string;
  label: string;
}): Promise<void> {
  const row = await requirePending(params.userCode);
  const database = await db();

  // Labels are unique per user; fail now rather than at the CLI's next poll.
  const taken = await database
    .query("SELECT 1 AS x FROM api_keys WHERE user_id = ? AND label = ?;")
    .get(params.userId, params.label);
  if (taken) {
    throw new DeviceAuthorizationError(
      `A key labelled "${params.label}" already exists.`
    );
  }

  const res = await database
    .query(
      "UPDATE device_authorizations SET status = 'APPROVED', user_id = ?, label = ?, approved_session_id = ? WHERE id = ? AND status = 'PENDING' AND expires_at > ?;"
    )
    .run(params.userId, params.label, params.sessionId, row.id, nowIso());
  if (!res.changes) {
    throw new DeviceAuthorizationError("That code is no longer pending.");
  }
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "device_authorization_approved",
    event: {
      deviceAuthorizationId: row.id,
      clientId: row.client_id,
      label: params.label,
    },
  });
}

export async function denyDeviceAuthorization(params: {
  userCode: string;
  userId: string;
  sessionId: string;
}): Promise<void> {
  const row = await requirePending(params.userCode);
  const database = await db();
  await database
    .query(
      "UPDATE device_authorizations SET status = 'DENIED', user_id = ? WHERE id = ? AND status = 'PENDING';"
    )
    .run(params.userId, row.id);
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "device_authorization_denied",
    event: { deviceAuthorizationId: row.id, clientId: row.client_id },
  });
}

// RFC 8628 §3.5 token endpoint error codes.
export type DeviceTokenError =
  | "authorization_pending"
  | "slow_down"
  | "access_denied"
  | "expired_token"
  | "invalid_grant";

export type DeviceTokenResult =
  | {
      ok: true;
      accessToken: string;
      label: string;
      keyType: ApiKeyType;
      expiresAt: string | null;
    }
  | { ok: false; error: DeviceTokenError; description?: string };

export async function pollDeviceToken(params: {
  deviceCode: string;
  // The poller is the client that receives the key.
  origin: RequestOrigin;
}): Promise<DeviceTokenResult> {
  const database = await db();
  const row = await database
    .query(
      `SELECT ${SELECT_COLUMNS} FROM device_authorizations WHERE device_code_hash = ?;`
    )
    .get<DeviceAuthorizationRow>(await sha256Hex(params.deviceCode));
  if (!row) return { ok: false, error: "invalid_grant" };
  if (row.status === "CONSUMED") {
    return {
      ok: false,
      error: "invalid_grant",
      description: "device code already used",
    };
  }
  if (row.status === "DENIED") return { ok: false, error: "access_denied" };

  const now = Date.now();
  if (now >= Date.parse(row.expires_at)) {
    return { ok: false, error: "expired_token" };
  }

  const tooSoon =
    row.last_polled_at != null &&
    now - Date.parse(row.last_polled_at) < row.interval_seconds * 1000;
  await database
    .query(
      "UPDATE device_authorizations SET last_polled_at = ?, interval_seconds = ? WHERE id = ?;"
    )
    .run(
      new Date(now).toISOString(),
      tooSoon
        ? row.interval_seconds + SLOW_DOWN_STEP_SECONDS
        : row.interval_seconds,
      row.id
    );
  if (tooSoon) return { ok: false, error: "slow_down" };
  if (row.status === "PENDING") {
    return { ok: false, error: "authorization_pending" };
  }

  // APPROVED: claim the row first so concurrent polls mint at most one key.
  const claimed = await database
    .query(
      "UPDATE device_authorizations SET status = 'CONSUMED' WHERE id = ? AND status = 'APPROVED';"
    )
    .run(row.id);
  if (!claimed.changes || !row.user_id || !row.label) {
    return { ok: false, error: "invalid_grant" };
  }

  const keyType: ApiKeyType =
    row.key_type === "session" ? "session" : "persistent";
  let created: Awaited<ReturnType<typeof insertApiKey>>;
  try {
    created = await insertApiKey({
      userId: row.user_id,
      label: row.label,
      keyType,
      origin: params.origin,
    });
  } catch (err) {
    if (!isUniqueLabelError(err)) throw err;
    return {
      ok: false,
      error: "access_denied",
      description: `a key labelled "${row.label}" was created in the meantime`,
    };
  }
  await database
    .query("UPDATE device_authorizations SET api_key_id = ? WHERE id = ?;")
    .run(created.id, row.id);
  await auditEvent({
    userId: row.user_id,
    actorType: "session",
    actorId: row.approved_session_id ?? row.id,
    eventType: "api_key_created",
    event: {
      apiKeyId: created.id,
      label: row.label,
      keyType,
      expiresAt: created.expiresAt,
      via: "device_authorization",
      deviceAuthorizationId: row.id,
      clientId: row.client_id,
      ip: params.origin.ip,
      location: params.origin.location,
      userAgent: params.origin.userAgent,
    },
  });
  return {
    ok: true,
    accessToken: created.keyPlain,
    label: row.label,
    keyType,
    expiresAt: created.expiresAt,
  };
}

export async function sweepDeviceAuthorizations(): Promise<void> {
  const database = await db();
  await database
    .query("DELETE FROM device_authorizations WHERE expires_at < ?;")
    .run(new Date(Date.now() - SWEEP_GRACE_MS).toISOString());
}
