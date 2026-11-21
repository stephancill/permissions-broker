// Minimal Web Push sender on WebCrypto (works on Workers and Bun):
// - RFC 8291 message encryption with the RFC 8188 aes128gcm content coding
// - RFC 8292 VAPID authentication (ES256 JWT)

import { concatBytes, fromBase64Url, toBase64Url } from "../crypto/bytes";

export type PushSubscriptionKeys = {
  endpoint: string;
  p256dh: string; // base64url, uncompressed P-256 point (65 bytes)
  auth: string; // base64url, 16 bytes
};

export type VapidKeys = {
  publicKey: string; // base64url, uncompressed P-256 point (65 bytes)
  privateKey: string; // base64url, 32-byte scalar
  subject: string; // mailto: or https:
};

const RECORD_SIZE = 4096;
const encoder = new TextEncoder();

function ab(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    ab(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, ab(data)));
}

// HKDF with a single output block (L <= 32), as used by RFC 8291/8188.
async function hkdf(params: {
  salt: Uint8Array;
  ikm: Uint8Array;
  info: Uint8Array;
  length: number;
}): Promise<Uint8Array> {
  const prk = await hmac(params.salt, params.ikm);
  const okm = await hmac(prk, concatBytes(params.info, new Uint8Array([1])));
  return okm.subarray(0, params.length);
}

export async function encryptPushPayload(params: {
  p256dh: Uint8Array;
  auth: Uint8Array;
  plaintext: Uint8Array;
  // Injectable for tests (RFC 8291 appendix A vector).
  serverKeyPair?: CryptoKeyPair;
  salt?: Uint8Array;
}): Promise<Uint8Array> {
  if (params.p256dh.byteLength !== 65 || params.p256dh[0] !== 4) {
    throw new Error("invalid p256dh key");
  }
  if (params.auth.byteLength !== 16) throw new Error("invalid auth secret");
  // One record; leave room for the delimiter and the 16-byte tag.
  if (params.plaintext.byteLength > RECORD_SIZE - 17) {
    throw new Error("push payload too large");
  }

  const serverKeys =
    params.serverKeyPair ??
    ((await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    )) as CryptoKeyPair);
  const serverPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", serverKeys.publicKey)
  );
  const clientPublic = await crypto.subtle.importKey(
    "raw",
    ab(params.p256dh),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const ecdhSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: clientPublic },
      serverKeys.privateKey,
      256
    )
  );

  const ikm = await hkdf({
    salt: params.auth,
    ikm: ecdhSecret,
    info: concatBytes(
      encoder.encode("WebPush: info\0"),
      params.p256dh,
      serverPublic
    ),
    length: 32,
  });

  const salt = params.salt ?? crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf({
    salt,
    ikm,
    info: encoder.encode("Content-Encoding: aes128gcm\0"),
    length: 16,
  });
  const nonce = await hkdf({
    salt,
    ikm,
    info: encoder.encode("Content-Encoding: nonce\0"),
    length: 12,
  });

  const key = await crypto.subtle.importKey(
    "raw",
    ab(cek),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  // 0x02: padding delimiter of the last (only) record.
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ab(nonce) },
      key,
      ab(concatBytes(params.plaintext, new Uint8Array([2])))
    )
  );

  const header = new Uint8Array(16 + 4 + 1);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE);
  header[20] = serverPublic.byteLength;
  return concatBytes(header, serverPublic, ciphertext);
}

async function importVapidPrivateKey(keys: VapidKeys): Promise<CryptoKey> {
  const pub = fromBase64Url(keys.publicKey);
  if (pub.byteLength !== 65 || pub[0] !== 4) {
    throw new Error("VAPID_PUBLIC_KEY must be an uncompressed P-256 point");
  }
  const d = fromBase64Url(keys.privateKey);
  if (d.byteLength !== 32) {
    throw new Error("VAPID_PRIVATE_KEY must be a 32-byte P-256 scalar");
  }
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: toBase64Url(pub.subarray(1, 33)),
      y: toBase64Url(pub.subarray(33, 65)),
      d: keys.privateKey,
      ext: false,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

export async function vapidAuthorization(params: {
  endpoint: string;
  keys: VapidKeys;
  ttlSeconds?: number;
}): Promise<string> {
  const aud = new URL(params.endpoint).origin;
  const exp =
    Math.floor(Date.now() / 1000) + (params.ttlSeconds ?? 12 * 60 * 60);
  const b64json = (v: unknown) =>
    toBase64Url(encoder.encode(JSON.stringify(v)));
  const signingInput = `${b64json({ typ: "JWT", alg: "ES256" })}.${b64json({
    aud,
    exp,
    sub: params.keys.subject,
  })}`;
  // WebCrypto ECDSA returns raw r||s, which is the JWS ES256 encoding.
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      await importVapidPrivateKey(params.keys),
      ab(encoder.encode(signingInput))
    )
  );
  return `vapid t=${signingInput}.${toBase64Url(sig)}, k=${params.keys.publicKey}`;
}

export type PushResult =
  | { ok: true; status: number }
  // gone: the subscription is dead and should be deleted.
  | { ok: false; status: number; gone: boolean; message: string };

export async function sendWebPush(params: {
  subscription: PushSubscriptionKeys;
  payload: unknown;
  vapid: VapidKeys;
  ttlSeconds: number;
  urgency?: "very-low" | "low" | "normal" | "high";
  topic?: string;
}): Promise<PushResult> {
  const body = await encryptPushPayload({
    p256dh: fromBase64Url(params.subscription.p256dh),
    auth: fromBase64Url(params.subscription.auth),
    plaintext: encoder.encode(JSON.stringify(params.payload)),
  });

  const headers: Record<string, string> = {
    authorization: await vapidAuthorization({
      endpoint: params.subscription.endpoint,
      keys: params.vapid,
    }),
    "content-encoding": "aes128gcm",
    "content-type": "application/octet-stream",
    ttl: String(params.ttlSeconds),
    urgency: params.urgency ?? "normal",
  };
  // Topic replaces an undelivered push with the same topic (<= 32 url-safe chars).
  if (params.topic) headers.topic = params.topic;

  const res = await fetch(params.subscription.endpoint, {
    method: "POST",
    headers,
    body: ab(body),
  });
  if (res.ok) return { ok: true, status: res.status };
  const message = (await res.text().catch(() => "")).slice(0, 300);
  return {
    ok: false,
    status: res.status,
    gone: res.status === 404 || res.status === 410,
    message,
  };
}
