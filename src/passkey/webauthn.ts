import {
  type AuthenticationResponseJSON,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { ulid } from "ulid";

import {
  bytesEqual,
  fromBase64Url,
  toBase64Url,
  toBytes,
} from "../crypto/bytes";
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

export function expectedRpId(): string {
  return baseUrl().hostname;
}

export function expectedOrigin(): string {
  return baseUrl().origin;
}

export function appUrl(path: string): string {
  return `${baseUrl().origin}${path}`;
}

async function hmacKey(): Promise<CryptoKey> {
  if (!env.APP_SECRET) throw new Error("APP_SECRET not configured");
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`pb-link-v1:${env.APP_SECRET}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// Unguessable per-target token so approval pages (which embed the wrapped
// private key) are only reachable from the Telegram link.
export async function approvalLinkToken(params: {
  kind: string;
  id: string;
}): Promise<string> {
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(),
    new TextEncoder().encode(`approve:${params.kind}:${params.id}`)
  );
  return toBase64Url(new Uint8Array(sig));
}

export async function verifyApprovalLinkToken(params: {
  kind: string;
  id: string;
  token: string | undefined;
}): Promise<boolean> {
  if (!params.token) return false;
  const expected = fromBase64Url(await approvalLinkToken(params));
  return bytesEqual(expected, fromBase64Url(params.token));
}

export async function approvalUrl(params: {
  kind: string;
  id: string;
}): Promise<string> {
  const t = await approvalLinkToken(params);
  return appUrl(
    `/approve/${params.kind}/${encodeURIComponent(params.id)}?t=${t}`
  );
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

export type UserPasskey = {
  credential_id: string;
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
      "SELECT credential_id, public_key, sign_count, transports, prf_salt FROM user_passkeys WHERE user_id = ?;"
    )
    .get(userId)) as UserPasskey | null;
  return row ? { ...row, public_key: toBytes(row.public_key) } : null;
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
      expectedRPID: expectedRpId(),
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
