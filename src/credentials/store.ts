// Linked-account credential storage under passkey-gated encryption.
// See docs/PASSKEY_CREDENTIAL_ENCRYPTION.md.
//
// - Credentials are ECIES-encrypted to the user's public key; the server cannot
//   decrypt them on its own.
// - An approval releases a DEK for one credential, stored as a "grant"
//   (encrypted with APP_SECRET) scoped to the approval target and wiped on use
//   or expiry.
// - Every unlock re-encrypts the credential under a fresh ephemeral key and
//   updates all live grants for it, so a leaked DEK is useless against later
//   database snapshots.

import { ulid } from "ulid";

import { decryptUtf8, encryptUtf8 } from "../crypto/aesgcm";
import { fromBase64Url, toBase64Url, toBytes } from "../crypto/bytes";
import {
  CREDENTIAL_ENC_VERSION,
  decryptCredential,
  encryptCredential,
} from "../crypto/ecies";
import { db } from "../db/client";
import { parseCredential as parseImapCredential } from "../email/credential";

export type GrantTargetKind = "proxy" | "git" | "email" | "window";

export type CredentialErrorCode =
  | "NOT_ENROLLED"
  | "NO_GRANT"
  | "GRANT_EXPIRED"
  | "LEGACY_CREDENTIAL"
  | "DECRYPT_FAILED";

export class CredentialError extends Error {
  code: CredentialErrorCode;

  constructor(code: CredentialErrorCode, message: string) {
    super(message);
    this.name = "CredentialError";
    this.code = code;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

export type LinkedAccountRow = {
  id: string;
  user_id: string;
  provider: string;
  enc_version: number;
  credential_epk: Uint8Array | null;
  refresh_token_ciphertext: Uint8Array;
};

export async function getUserPublicKey(
  userId: string
): Promise<Uint8Array | null> {
  const database = await db();
  const row = (await database
    .query("SELECT public_key FROM user_keys WHERE user_id = ?;")
    .get(userId)) as { public_key: Uint8Array | ArrayBuffer } | null;
  return row ? toBytes(row.public_key) : null;
}

export async function isEnrolled(userId: string): Promise<boolean> {
  return (await getUserPublicKey(userId)) != null;
}

export async function getActiveLinkedAccount(params: {
  userId: string;
  provider: string;
}): Promise<LinkedAccountRow | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT id, user_id, provider, enc_version, credential_epk, refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(params.userId, params.provider)) as LinkedAccountRow | null;
  if (!row) return null;
  return {
    ...row,
    credential_epk: row.credential_epk ? toBytes(row.credential_epk) : null,
    refresh_token_ciphertext: toBytes(row.refresh_token_ciphertext),
  };
}

// Non-secret display metadata, so listing accounts never needs a decrypt.
export function deriveCredentialMetadata(params: {
  provider: string;
  plaintext: string;
}): Record<string, unknown> | null {
  if (params.provider === "imap") {
    const cred = parseImapCredential(params.plaintext);
    if (!cred) return null;
    return {
      imap: {
        email: cred.email,
        host: cred.host,
        port: cred.port,
        secure: cred.secure,
      },
    };
  }

  if (params.provider === "cloudflare") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(params.plaintext);
    } catch {
      return null;
    }
    const accounts =
      parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as { accounts?: unknown }).accounts
        : undefined;
    if (!Array.isArray(accounts)) return { cloudflare_accounts: [] };
    return {
      cloudflare_accounts: accounts
        .map((x) => {
          if (!x || typeof x !== "object" || Array.isArray(x)) return null;
          const a = x as Record<string, unknown>;
          const id = typeof a.id === "string" ? a.id : null;
          const name = typeof a.name === "string" ? a.name : undefined;
          return id ? { id, name } : null;
        })
        .filter((x) => x != null),
    };
  }

  return null;
}

async function encryptForAccount(params: {
  userId: string;
  linkedAccountId: string;
  plaintext: string;
}) {
  const publicKey = await getUserPublicKey(params.userId);
  if (!publicKey) {
    throw new CredentialError(
      "NOT_ENROLLED",
      "No passkey enrolled. Use /passkey in Telegram first."
    );
  }
  return encryptCredential({
    userPublicKey: publicKey,
    linkedAccountId: params.linkedAccountId,
    plaintext: params.plaintext,
  });
}

// Insert or replace the user's active credential for a provider.
export async function saveLinkedCredential(params: {
  userId: string;
  provider: string;
  providerUserId: string;
  scopes: string;
  plaintext: string;
}): Promise<{ linkedAccountId: string }> {
  const database = await db();
  const existing = (await database
    .query(
      "SELECT id FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(params.userId, params.provider)) as { id: string } | null;

  const linkedAccountId = existing?.id ?? ulid();
  const enc = await encryptForAccount({
    userId: params.userId,
    linkedAccountId,
    plaintext: params.plaintext,
  });
  const metadata = deriveCredentialMetadata({
    provider: params.provider,
    plaintext: params.plaintext,
  });
  const metadataJson = metadata ? JSON.stringify(metadata) : null;

  if (existing) {
    await database
      .query(
        "UPDATE linked_accounts SET provider_user_id = ?, scopes = ?, refresh_token_ciphertext = ?, credential_epk = ?, enc_version = ?, metadata_json = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
      )
      .run(
        params.providerUserId,
        params.scopes,
        enc.ciphertext,
        enc.epk,
        CREDENTIAL_ENC_VERSION,
        metadataJson,
        existing.id
      );
    // Outstanding grants hold DEKs for the replaced credential.
    await database
      .query("DELETE FROM credential_grants WHERE linked_account_id = ?;")
      .run(existing.id);
  } else {
    await database
      .query(
        "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, credential_epk, enc_version, metadata_json, status, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL);"
      )
      .run(
        linkedAccountId,
        params.userId,
        params.provider,
        params.providerUserId,
        params.scopes,
        enc.ciphertext,
        enc.epk,
        CREDENTIAL_ENC_VERSION,
        metadataJson,
        nowIso()
      );
  }

  return { linkedAccountId };
}

// Re-encrypt every legacy (APP_SECRET) credential of a user to their new
// public key. Runs once on first passkey enrollment.
export async function migrateLegacyCredentials(
  userId: string
): Promise<{ migrated: number; failed: number }> {
  const database = await db();
  const rows = (await database
    .query(
      "SELECT id, provider, refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND enc_version = 0 AND status = 'active';"
    )
    .all(userId)) as {
    id: string;
    provider: string;
    refresh_token_ciphertext: Uint8Array;
  }[];

  let migrated = 0;
  let failed = 0;
  for (const row of rows) {
    let plaintext: string;
    try {
      plaintext = await decryptUtf8(row.refresh_token_ciphertext);
    } catch {
      // Unreadable legacy credential: force a reconnect rather than keep it.
      await database
        .query(
          "UPDATE linked_accounts SET status = 'revoked', revoked_at = ? WHERE id = ?;"
        )
        .run(nowIso(), row.id);
      failed++;
      continue;
    }

    const enc = await encryptForAccount({
      userId,
      linkedAccountId: row.id,
      plaintext,
    });
    const metadata = deriveCredentialMetadata({
      provider: row.provider,
      plaintext,
    });
    await database
      .query(
        "UPDATE linked_accounts SET refresh_token_ciphertext = ?, credential_epk = ?, enc_version = ?, metadata_json = ? WHERE id = ? AND enc_version = 0;"
      )
      .run(
        enc.ciphertext,
        enc.epk,
        CREDENTIAL_ENC_VERSION,
        metadata ? JSON.stringify(metadata) : null,
        row.id
      );
    migrated++;
  }

  return { migrated, failed };
}

// Lost-passkey re-enrollment: credentials encrypted to the old keypair are
// unrecoverable, so revoke them and drop their grants.
export async function revokeUndecryptableCredentials(
  userId: string
): Promise<number> {
  const database = await db();
  await database
    .query(
      "DELETE FROM credential_grants WHERE linked_account_id IN (SELECT id FROM linked_accounts WHERE user_id = ? AND enc_version = ?);"
    )
    .run(userId, CREDENTIAL_ENC_VERSION);
  const res = await database
    .query(
      "UPDATE linked_accounts SET status = 'revoked', revoked_at = ? WHERE user_id = ? AND enc_version = ? AND status = 'active';"
    )
    .run(nowIso(), userId, CREDENTIAL_ENC_VERSION);
  return res.changes ?? 0;
}

async function encryptDek(dek: Uint8Array): Promise<Uint8Array> {
  return encryptUtf8(toBase64Url(dek));
}

async function decryptDek(ciphertext: Uint8Array): Promise<Uint8Array> {
  return fromBase64Url(await decryptUtf8(ciphertext));
}

// Store an approval-released DEK after checking it opens the current
// credential ciphertext.
export async function createGrant(params: {
  userId: string;
  linkedAccountId: string;
  targetKind: GrantTargetKind;
  targetId: string;
  dek: Uint8Array;
  expiresAt: string;
}): Promise<{ grantId: string }> {
  const database = await db();
  const acct = (await database
    .query(
      "SELECT refresh_token_ciphertext, enc_version FROM linked_accounts WHERE id = ? AND user_id = ? AND status = 'active';"
    )
    .get(params.linkedAccountId, params.userId)) as {
    refresh_token_ciphertext: Uint8Array;
    enc_version: number;
  } | null;
  if (!acct) throw new CredentialError("NO_GRANT", "linked account not found");
  if (acct.enc_version !== CREDENTIAL_ENC_VERSION) {
    throw new CredentialError(
      "LEGACY_CREDENTIAL",
      "credential has not been migrated to passkey encryption"
    );
  }

  try {
    await decryptCredential({
      dek: params.dek,
      linkedAccountId: params.linkedAccountId,
      ciphertext: toBytes(acct.refresh_token_ciphertext),
    });
  } catch {
    throw new CredentialError(
      "DECRYPT_FAILED",
      "approval key does not match the stored credential"
    );
  }

  const grantId = ulid();
  await database
    .query(
      "INSERT INTO credential_grants (id, user_id, linked_account_id, target_kind, target_id, dek_ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
    )
    .run(
      grantId,
      params.userId,
      params.linkedAccountId,
      params.targetKind,
      params.targetId,
      await encryptDek(params.dek),
      nowIso(),
      params.expiresAt
    );
  return { grantId };
}

export async function findGrantId(params: {
  targetKind: GrantTargetKind;
  targetId: string;
}): Promise<string | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT id FROM credential_grants WHERE target_kind = ? AND target_id = ? ORDER BY created_at DESC LIMIT 1;"
    )
    .get(params.targetKind, params.targetId)) as { id: string } | null;
  return row?.id ?? null;
}

export async function deleteGrant(grantId: string): Promise<void> {
  const database = await db();
  await database
    .query("DELETE FROM credential_grants WHERE id = ?;")
    .run(grantId);
}

export async function deleteGrantsForTarget(params: {
  targetKind: GrantTargetKind;
  targetId: string;
}): Promise<void> {
  const database = await db();
  await database
    .query(
      "DELETE FROM credential_grants WHERE target_kind = ? AND target_id = ?;"
    )
    .run(params.targetKind, params.targetId);
}

// Re-encrypt a credential (rotation or provider-issued replacement) and move
// all live grants for it onto the new DEK.
export async function storeRotatedCredential(params: {
  userId: string;
  linkedAccountId: string;
  provider: string;
  plaintext: string;
}): Promise<void> {
  const enc = await encryptForAccount({
    userId: params.userId,
    linkedAccountId: params.linkedAccountId,
    plaintext: params.plaintext,
  });
  const metadata = deriveCredentialMetadata({
    provider: params.provider,
    plaintext: params.plaintext,
  });

  const database = await db();
  await database
    .query(
      "UPDATE linked_accounts SET refresh_token_ciphertext = ?, credential_epk = ?, enc_version = ?, metadata_json = COALESCE(?, metadata_json) WHERE id = ?;"
    )
    .run(
      enc.ciphertext,
      enc.epk,
      CREDENTIAL_ENC_VERSION,
      metadata ? JSON.stringify(metadata) : null,
      params.linkedAccountId
    );
  await database
    .query(
      "UPDATE credential_grants SET dek_ciphertext = ? WHERE linked_account_id = ? AND expires_at > ?;"
    )
    .run(await encryptDek(enc.dek), params.linkedAccountId, nowIso());
}

type GrantRow = {
  id: string;
  user_id: string;
  linked_account_id: string;
  expires_at: string;
  dek_ciphertext: Uint8Array;
  refresh_token_ciphertext: Uint8Array;
  provider: string;
  status: string;
};

async function readGrant(grantId: string): Promise<GrantRow | null> {
  const database = await db();
  // Single statement so DEK and ciphertext come from one snapshot.
  return (await database
    .query(
      "SELECT g.id, g.user_id, g.linked_account_id, g.expires_at, g.dek_ciphertext, a.refresh_token_ciphertext, a.provider, a.status " +
        "FROM credential_grants g JOIN linked_accounts a ON a.id = g.linked_account_id WHERE g.id = ?;"
    )
    .get(grantId)) as GrantRow | null;
}

// Decrypt the credential behind a grant, then rotate it. A concurrent rotation
// can briefly pair a fresh ciphertext with a stale DEK, so retry a few times.
export async function unlockCredential(params: {
  grantId: string | null;
  userId: string;
}): Promise<{ plaintext: string; linkedAccountId: string; provider: string }> {
  if (!params.grantId) {
    throw new CredentialError("NO_GRANT", "no approval key for this request");
  }

  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    const g = await readGrant(params.grantId);
    if (!g || g.user_id !== params.userId || g.status !== "active") {
      throw new CredentialError("NO_GRANT", "no approval key for this request");
    }
    const exp = Date.parse(g.expires_at);
    if (Number.isFinite(exp) && Date.now() > exp) {
      await deleteGrant(g.id);
      throw new CredentialError("GRANT_EXPIRED", "approval key expired");
    }

    let plaintext: string;
    try {
      plaintext = await decryptCredential({
        dek: await decryptDek(toBytes(g.dek_ciphertext)),
        linkedAccountId: g.linked_account_id,
        ciphertext: toBytes(g.refresh_token_ciphertext),
      });
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
      continue;
    }

    await storeRotatedCredential({
      userId: params.userId,
      linkedAccountId: g.linked_account_id,
      provider: g.provider,
      plaintext,
    });
    return {
      plaintext,
      linkedAccountId: g.linked_account_id,
      provider: g.provider,
    };
  }

  throw new CredentialError(
    "DECRYPT_FAILED",
    `could not decrypt credential: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`
  );
}

export async function sweepCredentialGrants(): Promise<void> {
  const now = nowIso();
  const database = await db();
  await database
    .query("DELETE FROM credential_grants WHERE expires_at < ?;")
    .run(now);
  // Wipe keys for targets that can no longer use them.
  await database
    .query(
      "DELETE FROM credential_grants WHERE target_kind = 'proxy' AND target_id IN (SELECT id FROM proxy_requests WHERE status IN ('SUCCEEDED', 'FAILED', 'DENIED', 'EXPIRED'));"
    )
    .run();
  await database
    .query(
      "DELETE FROM credential_grants WHERE target_kind = 'git' AND target_id IN (SELECT id FROM git_sessions WHERE status IN ('USED', 'DENIED', 'EXPIRED'));"
    )
    .run();
  await database
    .query(
      "DELETE FROM credential_grants WHERE target_kind = 'email' AND target_id IN (SELECT id FROM email_sessions WHERE status IN ('DENIED', 'EXPIRED'));"
    )
    .run();
  await database
    .query("DELETE FROM webauthn_challenges WHERE expires_at < ?;")
    .run(now);
  await database
    .query("DELETE FROM approval_windows WHERE expires_at < ?;")
    .run(now);
}
