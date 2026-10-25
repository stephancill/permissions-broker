// Browser-side crypto for passkey enrollment and approvals, shipped inline in
// the enroll/approve pages (no external scripts on those pages). It must stay
// byte-compatible with src/crypto/ecies.ts; tests/passkey_crypto.test.ts runs
// this exact source against the server implementation.
//
// Plain ES2020 inside a string: no template literals, no TypeScript.
export const CLIENT_CRYPTO_JS = String.raw`
(function (root) {
  var enc = new TextEncoder();
  var P256 = { name: "ECDH", namedCurve: "P-256" };

  function b64u(buf) {
    var bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function unb64u(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  async function hkdf32(ikm, salt, info) {
    var key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: info },
      key,
      256
    );
    return new Uint8Array(bits);
  }

  // KEK: HKDF over the passkey PRF output, bound to the broker user id.
  async function deriveKek(prfOutput, userId) {
    var raw = await hkdf32(
      new Uint8Array(prfOutput),
      new Uint8Array(0),
      enc.encode("pb-kek-v1:" + userId)
    );
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  async function generateUserKeypair() {
    var pair = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
    var pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { publicKeyRaw: pub, privateKey: pair.privateKey };
  }

  async function wrapPrivateKey(kek, privateKey, userId) {
    var pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode("pb-userkey-v1:" + userId) },
      kek,
      pkcs8
    );
    return concat(iv, new Uint8Array(ct));
  }

  // extractable=true only when the key must be re-wrapped under a new passkey.
  async function unwrapPrivateKey(kek, wrapped, userId, extractable) {
    var iv = wrapped.subarray(0, 12);
    var ct = wrapped.subarray(12);
    var pkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode("pb-userkey-v1:" + userId) },
      kek,
      ct
    );
    return crypto.subtle.importKey("pkcs8", pkcs8, P256, !!extractable, ["deriveBits"]);
  }

  async function deriveDek(privateKey, epkRaw, linkedAccountId) {
    var epk = await crypto.subtle.importKey("raw", epkRaw, P256, false, []);
    var shared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, privateKey, 256)
    );
    return hkdf32(shared, epkRaw, enc.encode("pb-cred-v1:" + linkedAccountId));
  }

  function prfFirst(credential) {
    var ext = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
    var prf = ext && ext.prf;
    return prf && prf.results && prf.results.first ? prf.results.first : null;
  }

  function registrationToJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: b64u(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(r.clientDataJSON),
        attestationObject: b64u(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
      },
    };
  }

  function assertionToJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: b64u(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(r.clientDataJSON),
        authenticatorData: b64u(r.authenticatorData),
        signature: b64u(r.signature),
        userHandle: r.userHandle ? b64u(r.userHandle) : undefined,
      },
    };
  }

  // Telegram's in-app browser on iOS is a webview without passkey access.
  function isTelegramWebview() {
    return typeof root.TelegramWebviewProxy !== "undefined";
  }

  root.PB = {
    b64u: b64u,
    unb64u: unb64u,
    deriveKek: deriveKek,
    generateUserKeypair: generateUserKeypair,
    wrapPrivateKey: wrapPrivateKey,
    unwrapPrivateKey: unwrapPrivateKey,
    deriveDek: deriveDek,
    prfFirst: prfFirst,
    registrationToJSON: registrationToJSON,
    assertionToJSON: assertionToJSON,
    isTelegramWebview: isTelegramWebview,
  };
})(typeof window !== "undefined" ? window : globalThis);
`;
