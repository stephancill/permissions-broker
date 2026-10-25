// Minimal software WebAuthn authenticator for tests: ES256 credentials,
// "none" attestation, user verification always performed, and a PRF
// extension emulated as HMAC-SHA256(secret, salt) like CTAP hmac-secret.

import { isoCBOR } from "@simplewebauthn/server/helpers";

type CBORType = Parameters<typeof isoCBOR.encode>[0];

import { concatBytes, toBase64Url } from "../../src/crypto/bytes";

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(data))
  );
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

function derInt(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.subarray(i);
  if (v[0] & 0x80) v = concatBytes(new Uint8Array([0]), v);
  return concatBytes(new Uint8Array([0x02, v.length]), v);
}

// WebCrypto returns raw r||s; WebAuthn expects an ASN.1 DER signature.
function rawToDer(raw: Uint8Array): Uint8Array {
  const r = derInt(raw.subarray(0, 32));
  const s = derInt(raw.subarray(32, 64));
  return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

function clientData(params: {
  type: string;
  challenge: string;
  origin: string;
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: params.type,
      challenge: params.challenge,
      origin: params.origin,
      crossOrigin: false,
    })
  );
}

export type VirtualCredential = {
  id: Uint8Array;
  idB64: string;
  keyPair: CryptoKeyPair;
  prfSecret: Uint8Array;
  counter: number;
};

export function createVirtualAuthenticator(params: {
  rpId: string;
  origin: string;
}) {
  const credentials = new Map<string, VirtualCredential>();

  async function prf(credentialIdB64: string, salt: Uint8Array) {
    const cred = credentials.get(credentialIdB64);
    if (!cred) throw new Error("unknown credential");
    const key = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(cred.prfSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return crypto.subtle.sign("HMAC", key, new Uint8Array(salt));
  }

  async function create(opts: { challenge: string }) {
    const keyPair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const id = crypto.getRandomValues(new Uint8Array(16));
    const cred: VirtualCredential = {
      id,
      idB64: toBase64Url(id),
      keyPair,
      prfSecret: crypto.getRandomValues(new Uint8Array(32)),
      counter: 0,
    };
    credentials.set(cred.idB64, cred);

    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", keyPair.publicKey)
    );
    const cose = isoCBOR.encode(
      new Map<number, CBORType>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, raw.subarray(1, 33)],
        [-3, raw.subarray(33, 65)],
      ])
    );
    const authData = concatBytes(
      await sha256(new TextEncoder().encode(params.rpId)),
      new Uint8Array([FLAG_UP | FLAG_UV | FLAG_AT]),
      u32be(0),
      new Uint8Array(16),
      new Uint8Array([0, id.length]),
      id,
      cose
    );
    const attestationObject = isoCBOR.encode(
      new Map<string, CBORType>([
        ["fmt", "none"],
        ["attStmt", new Map<string, CBORType>()],
        ["authData", authData],
      ])
    );

    return {
      credential: cred,
      response: {
        id: cred.idB64,
        rawId: cred.idB64,
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: toBase64Url(
            clientData({
              type: "webauthn.create",
              challenge: opts.challenge,
              origin: params.origin,
            })
          ),
          attestationObject: toBase64Url(attestationObject),
          transports: ["internal"],
        },
      },
    };
  }

  async function get(opts: { credentialId: string; challenge: string }) {
    const cred = credentials.get(opts.credentialId);
    if (!cred) throw new Error("unknown credential");
    cred.counter++;

    const authData = concatBytes(
      await sha256(new TextEncoder().encode(params.rpId)),
      new Uint8Array([FLAG_UP | FLAG_UV]),
      u32be(cred.counter)
    );
    const cdj = clientData({
      type: "webauthn.get",
      challenge: opts.challenge,
      origin: params.origin,
    });
    const signed = concatBytes(authData, await sha256(cdj));
    const sigRaw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        cred.keyPair.privateKey,
        new Uint8Array(signed)
      )
    );

    return {
      id: cred.idB64,
      rawId: cred.idB64,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: toBase64Url(cdj),
        authenticatorData: toBase64Url(authData),
        signature: toBase64Url(rawToDer(sigRaw)),
      },
    };
  }

  return { create, get, prf };
}
