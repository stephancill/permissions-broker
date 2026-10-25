// ECIES envelope for linked-account credentials (see
// docs/PASSKEY_CREDENTIAL_ENCRYPTION.md). The server can encrypt to a user's
// public key but cannot decrypt: decryption needs the per-credential DEK, which
// only the user's passkey-unlocked private key can derive.
//
// The browser side of this scheme lives in src/passkey/clientCrypto.ts and must
// stay byte-compatible with this file.

import { bufferSource, concatBytes } from "./bytes";

export const CREDENTIAL_ENC_VERSION = 1;

const IV_BYTES = 12;
const P256 = { name: "ECDH", namedCurve: "P-256" } as const;

function utf8(s: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(s);
}

function credentialInfo(linkedAccountId: string): Uint8Array {
  return utf8(`pb-cred-v1:${linkedAccountId}`);
}

async function hkdf32(params: {
  ikm: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
}): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    bufferSource(params.ikm),
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: bufferSource(params.salt),
      info: bufferSource(params.info),
    },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    bufferSource(raw),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

export type EncryptedCredential = {
  // Uncompressed P-256 ephemeral public key (65 bytes).
  epk: Uint8Array;
  // iv || AES-GCM ciphertext
  ciphertext: Uint8Array;
  // The per-credential data-encryption key. Returned so callers can update
  // outstanding grants after a rotation; never persist it unencrypted.
  dek: Uint8Array;
};

export async function encryptCredential(params: {
  userPublicKey: Uint8Array;
  linkedAccountId: string;
  plaintext: string;
}): Promise<EncryptedCredential> {
  const recipient = await crypto.subtle.importKey(
    "raw",
    bufferSource(params.userPublicKey),
    P256,
    false,
    []
  );
  const ephemeral = (await crypto.subtle.generateKey(P256, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: recipient },
      ephemeral.privateKey,
      256
    )
  );
  const epk = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeral.publicKey)
  );

  const dek = await hkdf32({
    ikm: shared,
    salt: epk,
    info: credentialInfo(params.linkedAccountId),
  });

  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: utf8(params.linkedAccountId),
    },
    await importAesKey(dek),
    utf8(params.plaintext)
  );

  return { epk, ciphertext: concatBytes(iv, new Uint8Array(ct)), dek };
}

export async function decryptCredential(params: {
  dek: Uint8Array;
  linkedAccountId: string;
  ciphertext: Uint8Array;
}): Promise<string> {
  if (params.ciphertext.byteLength <= IV_BYTES) {
    throw new Error("credential ciphertext too short");
  }
  const iv = params.ciphertext.subarray(0, IV_BYTES);
  const ct = params.ciphertext.subarray(IV_BYTES);
  const pt = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bufferSource(iv),
      additionalData: utf8(params.linkedAccountId),
    },
    await importAesKey(params.dek),
    bufferSource(ct)
  );
  return new TextDecoder().decode(pt);
}
