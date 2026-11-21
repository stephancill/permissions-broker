// Generates a VAPID key pair for Web Push.
// Usage: bun scripts/vapid_keys.ts
// Rotating these invalidates every existing push subscription (devices must
// re-enable notifications in the app).

import { toBase64Url } from "../src/crypto/bytes";

const pair = (await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"]
)) as CryptoKeyPair;

const publicKey = toBase64Url(
  new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))
);
const { d } = await crypto.subtle.exportKey("jwk", pair.privateKey);
if (!d) throw new Error("failed to export private key");

console.log(`VAPID_PUBLIC_KEY=${publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${d}`);
