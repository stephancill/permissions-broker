import {
  type AuthenticationResponseJSON,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { ulid } from "ulid";

import { toBase64Url, toBytes } from "../crypto/bytes";
import { db } from "../db/client";
import { env } from "../env";

const CHALLENGE_TTL_MS = 5 * 60_000;

export type ChallengePurpose = "enroll" | "approve";

function nowIso(): string {
  return new Date().toISOString();
}

function baseUrl(): URL {
  if (!env.APP_BASE_URL) throw new Error("APP_BASE_URL not configured");
  return new URL(env.APP_BASE_URL);
}

// RP ID for new passkeys: the APP_BASE_URL host.
export function expectedRpId(): string {
  return baseUrl().hostname;
}

// The previous domain while migrating, if it differs from the current one.
export function legacyRpId(): string | null {
  const legacy = env.WEBAUTHN_LEGACY_RP_ID?.trim().toLowerCase();
  return legacy && legacy !== expectedRpId() ? legacy : null;
}

// RP ID a stored passkey was registered under (NULL rows predate rp_id).
export function passkeyRpId(stored: string | null): string {
  return stored ?? legacyRpId() ?? expectedRpId();
}

// Served at https://<legacy RP ID>/.well-known/webauthn: lets the current
// origin use passkeys registered under the legacy RP ID (WebAuthn Related
// Origin Requests).
export function relatedOriginsDocument(): { origins: string[] } | null {
  return legacyRpId() ? { origins: [expectedOrigin()] } : null;
}

export function expectedOrigin(): string {
  return baseUrl().origin;
}

export function appUrl(path: string): string {
  return `${baseUrl().origin}${path}`;
}

export function approvalPath(params: { kind: string; id: string }): string {
  return `/approve/${params.kind}/${encodeURIComponent(params.id)}`;
}

// The approval challenge commits to what is being approved, so the stored
// assertion is a user signature over the request and the chosen options.
export async function approvalChallenge(params: {
  kind: string;
  id: string;
  requestHash: string;
  options: unknown;
  nonce: string;
}): Promise<string> {
  const payload = JSON.stringify({
    kind: params.kind,
    id: params.id,
    request_hash: params.requestHash,
    options: params.options,
    nonce: params.nonce,
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(payload)
  );
  return toBase64Url(new Uint8Array(digest));
}

export async function storeChallenge(params: {
  userId: string;
  purpose: ChallengePurpose;
  challenge: string;
  nonce?: string;
  targetKind?: string;
  targetId?: string;
  options?: unknown;
}): Promise<{ nonce: string }> {
  const nonce = params.nonce ?? ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO webauthn_challenges (nonce, user_id, purpose, target_kind, target_id, options_json, challenge, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);"
    )
    .run(
      nonce,
      params.userId,
      params.purpose,
      params.targetKind ?? null,
      params.targetId ?? null,
      params.options === undefined ? null : JSON.stringify(params.options),
      params.challenge,
      nowIso(),
      new Date(Date.now() + CHALLENGE_TTL_MS).toISOString()
    );
  return { nonce };
}

export type StoredChallenge = {
  nonce: string;
  user_id: string;
  purpose: ChallengePurpose;
  target_kind: string | null;
  target_id: string | null;
  options_json: string | null;
  challenge: string;
};

// Single use: the first caller to consume a challenge wins.
export async function consumeChallenge(params: {
  nonce: string;
  userId: string;
  purpose: ChallengePurpose;
}): Promise<StoredChallenge | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT nonce, user_id, purpose, target_kind, target_id, options_json, challenge, expires_at, used_at FROM webauthn_challenges WHERE nonce = ? AND user_id = ? AND purpose = ?;"
    )
    .get(params.nonce, params.userId, params.purpose)) as
    | (StoredChallenge & { expires_at: string; used_at: string | null })
    | null;
  if (!row || row.used_at) return null;
  if (Date.now() > Date.parse(row.expires_at)) return null;

  const res = await database
    .query(
      "UPDATE webauthn_challenges SET used_at = ? WHERE nonce = ? AND used_at IS NULL;"
    )
    .run(nowIso(), params.nonce);
  if (res.changes !== 1) return null;
  return row;
}

// Challenges issued before the user is known: sign-in (usernameless) and
// sign-up (user_id is the prospective account id).
export type AuthChallengePurpose = "signin" | "signup";

export async function storeAuthChallenge(params: {
  purpose: AuthChallengePurpose;
  challenge: string;
  userId?: string;
  options?: unknown;
}): Promise<{ nonce: string }> {
  const nonce = ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO auth_challenges (nonce, purpose, user_id, challenge, options_json, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL);"
    )
    .run(
      nonce,
      params.purpose,
      params.userId ?? null,
      params.challenge,
      params.options === undefined ? null : JSON.stringify(params.options),
      nowIso(),
      new Date(Date.now() + CHALLENGE_TTL_MS).toISOString()
    );
  return { nonce };
}

export async function consumeAuthChallenge(params: {
  nonce: string;
  purpose: AuthChallengePurpose;
}): Promise<{
  user_id: string | null;
  challenge: string;
  options_json: string | null;
} | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT user_id, challenge, options_json, expires_at, used_at FROM auth_challenges WHERE nonce = ? AND purpose = ?;"
    )
    .get(params.nonce, params.purpose)) as {
    user_id: string | null;
    challenge: string;
    options_json: string | null;
    expires_at: string;
    used_at: string | null;
  } | null;
  if (!row || row.used_at) return null;
  if (Date.now() > Date.parse(row.expires_at)) return null;
  const res = await database
    .query(
      "UPDATE auth_challenges SET used_at = ? WHERE nonce = ? AND used_at IS NULL;"
    )
    .run(nowIso(), params.nonce);
  if (res.changes !== 1) return null;
  return row;
}

export async function userIdForCredential(
  credentialId: string
): Promise<string | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT p.user_id FROM user_passkeys p JOIN users u ON u.id = p.user_id WHERE p.credential_id = ? AND u.status = 'active';"
    )
    .get(credentialId)) as { user_id: string } | null;
  return row?.user_id ?? null;
}

// Whether any passkey still uses the legacy RP ID (sign-in offers it then).
export async function legacyPasskeysExist(): Promise<boolean> {
  const legacy = legacyRpId();
  if (!legacy) return false;
  const database = await db();
  const row = await database
    .query(
      "SELECT 1 AS ok FROM user_passkeys WHERE rp_id IS NULL OR rp_id = ? LIMIT 1;"
    )
    .get<{ ok: number }>(legacy);
  return row != null;
}

export type UserPasskey = {
  credential_id: string;
  rp_id: string;
  public_key: Uint8Array;
  sign_count: number;
  transports: string | null;
  prf_salt: string;
};

export async function getUserPasskey(
  userId: string
): Promise<UserPasskey | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT credential_id, rp_id, public_key, sign_count, transports, prf_salt FROM user_passkeys WHERE user_id = ?;"
    )
    .get(userId)) as
    | (Omit<UserPasskey, "rp_id"> & { rp_id: string | null })
    | null;
  return row
    ? {
        ...row,
        rp_id: passkeyRpId(row.rp_id),
        public_key: toBytes(row.public_key),
      }
    : null;
}

export async function getWrappedPrivateKey(
  userId: string
): Promise<Uint8Array | null> {
  const database = await db();
  const row = (await database
    .query("SELECT wrapped_private_key FROM user_keys WHERE user_id = ?;")
    .get(userId)) as { wrapped_private_key: Uint8Array } | null;
  return row ? toBytes(row.wrapped_private_key) : null;
}

export async function verifyPasskeyAssertion(params: {
  userId: string;
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
}): Promise<boolean> {
  const passkey = await getUserPasskey(params.userId);
  if (!passkey) return false;
  if (params.response.id !== passkey.credential_id) return false;

  let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verified = await verifyAuthenticationResponse({
      response: params.response,
      expectedChallenge: params.expectedChallenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: passkey.rp_id,
      requireUserVerification: true,
      credential: {
        id: passkey.credential_id,
        publicKey: passkey.public_key as Uint8Array<ArrayBuffer>,
        counter: passkey.sign_count,
      },
    });
  } catch {
    return false;
  }
  if (!verified.verified) return false;

  const database = await db();
  await database
    .query("UPDATE user_passkeys SET sign_count = ? WHERE user_id = ?;")
    .run(verified.authenticationInfo.newCounter, params.userId);
  return true;
}
