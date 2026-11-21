import { expect, test } from "bun:test";

import { fromBase64Url, toBase64Url } from "../src/crypto/bytes";
import { isAllowedPushEndpoint } from "../src/push/notify";
import { encryptPushPayload, vapidAuthorization } from "../src/push/webpush";

// RFC 8291 Appendix A.
const VECTOR = {
  plaintext: "When I grow up, I want to be a watermelon",
  asPrivate: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
  asPublic:
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
  uaPublic:
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
  authSecret: "BTBZMqHH6r4Tts7J_aSIgg",
  salt: "DGv6ra1nlYgDCS1FRnbzlw",
  body: "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
};

async function importEcdhKeyPair(params: {
  publicKey: string;
  privateKey: string;
}): Promise<CryptoKeyPair> {
  const pub = fromBase64Url(params.publicKey);
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: toBase64Url(pub.subarray(1, 33)),
    y: toBase64Url(pub.subarray(33, 65)),
  };
  return {
    publicKey: await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    ),
    privateKey: await crypto.subtle.importKey(
      "jwk",
      { ...jwk, d: params.privateKey },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    ),
  };
}

test("aes128gcm encryption matches the RFC 8291 test vector", async () => {
  const body = await encryptPushPayload({
    p256dh: fromBase64Url(VECTOR.uaPublic),
    auth: fromBase64Url(VECTOR.authSecret),
    plaintext: new TextEncoder().encode(VECTOR.plaintext),
    serverKeyPair: await importEcdhKeyPair({
      publicKey: VECTOR.asPublic,
      privateKey: VECTOR.asPrivate,
    }),
    salt: fromBase64Url(VECTOR.salt),
  });
  expect(toBase64Url(body)).toBe(VECTOR.body);
});

test("VAPID authorization is a verifiable ES256 JWT for the push origin", async () => {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const publicKey = toBase64Url(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);

  const header = await vapidAuthorization({
    endpoint: "https://web.push.apple.com/QGuQyavXutnMH",
    keys: { publicKey, privateKey: jwk.d as string, subject: "mailto:a@b.c" },
  });
  const m = header.match(/^vapid t=([^,]+), k=(.+)$/);
  expect(m?.[2]).toBe(publicKey);
  const [h, p, s] = (m?.[1] ?? "").split(".");
  const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(p)));
  expect(claims.aud).toBe("https://web.push.apple.com");
  expect(claims.sub).toBe("mailto:a@b.c");
  expect(claims.exp).toBeGreaterThan(Date.now() / 1000);

  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pair.publicKey,
    new Uint8Array(fromBase64Url(s)),
    new TextEncoder().encode(`${h}.${p}`)
  );
  expect(ok).toBe(true);
});

test("only browser push services are accepted as endpoints", () => {
  expect(isAllowedPushEndpoint("https://web.push.apple.com/abc")).toBe(true);
  expect(isAllowedPushEndpoint("https://fcm.googleapis.com/fcm/send/x")).toBe(
    true
  );
  expect(isAllowedPushEndpoint("https://wns2-by3p.notify.windows.com/w")).toBe(
    true
  );
  expect(isAllowedPushEndpoint("http://web.push.apple.com/abc")).toBe(false);
  expect(isAllowedPushEndpoint("https://web.push.apple.com:8443/abc")).toBe(
    false
  );
  expect(isAllowedPushEndpoint("https://169.254.169.254/latest")).toBe(false);
  expect(isAllowedPushEndpoint("https://evil.example/notify.windows.com")).toBe(
    false
  );
});
