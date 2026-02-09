import { env } from "../env";

const IV_BYTES = 12;

let _keyPromise: Promise<CryptoKey> | undefined;

async function getKey(): Promise<CryptoKey> {
  if (_keyPromise) return _keyPromise;

  if (!env.APP_SECRET) {
    throw new Error("APP_SECRET is required for token encryption");
  }

  _keyPromise = (async () => {
    const secretBytes = new TextEncoder().encode(env.APP_SECRET);
    const digest = await crypto.subtle.digest("SHA-256", secretBytes);
    return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  })();

  return _keyPromise;
}

export async function encryptUtf8(plaintext: string): Promise<Uint8Array> {
  const key = await getKey();
  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);

  const pt = new TextEncoder().encode(plaintext);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);

  const out = new Uint8Array(iv.byteLength + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.byteLength);
  return out;
}

export async function decryptUtf8(ciphertext: Uint8Array): Promise<string> {
  const key = await getKey();
  if (ciphertext.byteLength < IV_BYTES + 1) {
    throw new Error("ciphertext too short");
  }

  const iv = ciphertext.slice(0, IV_BYTES);
  const ct = ciphertext.slice(IV_BYTES);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}
