import { bufferSource } from "../crypto/bytes";
import {
  certificateSpki,
  DerError,
  derChildren,
  oidString,
  parseDer,
  pemToDer,
} from "./der";

// Release signing: the broker signs the CMS signed attributes stupid-app built
// for one CodeDirectory, after checking that the CodeDirectory names an
// approved bundle and team and that the attributes name only its digest.

const CODE_DIRECTORY_MAGIC = 0xfade0c02;
const HASH_TYPE_SHA256 = 2;

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_APPLE_CDHASH_PLIST = "1.2.840.113635.100.9.1";
const OID_APPLE_CDHASHES = "1.2.840.113635.100.9.2";

export class SigningRequestError extends Error {}

export type CodeDirectoryInfo = {
  identifier: string;
  teamId: string | null;
};

function readCString(bytes: Uint8Array, offset: number): string {
  if (offset <= 0 || offset >= bytes.length) {
    throw new SigningRequestError("CodeDirectory string offset out of range");
  }
  const end = bytes.indexOf(0, offset);
  if (end < 0)
    throw new SigningRequestError("unterminated CodeDirectory string");
  return new TextDecoder().decode(bytes.subarray(offset, end));
}

export function parseCodeDirectory(bytes: Uint8Array): CodeDirectoryInfo {
  if (bytes.length < 52)
    throw new SigningRequestError("CodeDirectory too short");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0) !== CODE_DIRECTORY_MAGIC) {
    throw new SigningRequestError("not a CodeDirectory");
  }
  if (view.getUint32(4) !== bytes.length) {
    throw new SigningRequestError("CodeDirectory length mismatch");
  }
  if (bytes[37] !== HASH_TYPE_SHA256) {
    throw new SigningRequestError("CodeDirectory is not SHA-256");
  }
  const version = view.getUint32(8);
  const teamOffset = version >= 0x20200 ? view.getUint32(48) : 0;
  return {
    identifier: readCString(bytes, view.getUint32(20)),
    teamId: teamOffset ? readCString(bytes, teamOffset) : null,
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// The attribute SET must hold exactly content type (id-data), message digest,
// the cdhash plist and the cdhashes attribute, all naming `digest`, in DER
// order. No signing time, timestamp or anything else.
export function checkSignedAttributes(params: {
  signedAttributes: Uint8Array;
  digest: Uint8Array;
}): void {
  let set: ReturnType<typeof parseDer>;
  try {
    set = parseDer(params.signedAttributes);
  } catch (err) {
    if (err instanceof DerError) throw new SigningRequestError(err.message);
    throw err;
  }
  if (set.tag !== 0x31)
    throw new SigningRequestError("attributes are not a SET");

  const seen = new Map<string, Uint8Array>();
  let previous: Uint8Array | null = null;
  for (const attribute of derChildren(set)) {
    if (previous && compareBytes(previous, attribute.encoded) >= 0) {
      throw new SigningRequestError("attributes are not in DER order");
    }
    previous = attribute.encoded;
    const fields = derChildren(attribute);
    if (fields.length !== 2 || fields[1].tag !== 0x31) {
      throw new SigningRequestError("malformed attribute");
    }
    const values = derChildren(fields[1]);
    if (values.length !== 1)
      throw new SigningRequestError("multi-valued attribute");
    const oid = oidString(fields[0]);
    if (seen.has(oid)) throw new SigningRequestError("duplicate attribute");
    seen.set(oid, values[0].encoded);
  }

  const expected = new Set([
    OID_CONTENT_TYPE,
    OID_MESSAGE_DIGEST,
    OID_APPLE_CDHASH_PLIST,
    OID_APPLE_CDHASHES,
  ]);
  if (
    seen.size !== expected.size ||
    [...seen.keys()].some((k) => !expected.has(k))
  ) {
    throw new SigningRequestError("unexpected signed attributes");
  }

  const contentType = parseDer(seen.get(OID_CONTENT_TYPE) as Uint8Array);
  if (oidString(contentType) !== OID_DATA) {
    throw new SigningRequestError("content type is not id-data");
  }

  const messageDigest = parseDer(seen.get(OID_MESSAGE_DIGEST) as Uint8Array);
  if (
    messageDigest.tag !== 0x04 ||
    !equal(messageDigest.content, params.digest)
  ) {
    throw new SigningRequestError(
      "message digest does not match the CodeDirectory"
    );
  }

  const cdhashes = parseDer(seen.get(OID_APPLE_CDHASHES) as Uint8Array);
  const pair = cdhashes.tag === 0x30 ? derChildren(cdhashes) : [];
  if (
    pair.length !== 2 ||
    oidString(pair[0]) !== OID_SHA256 ||
    pair[1].tag !== 0x04 ||
    !equal(pair[1].content, params.digest)
  ) {
    throw new SigningRequestError("cdhashes do not match the CodeDirectory");
  }

  const plistNode = parseDer(seen.get(OID_APPLE_CDHASH_PLIST) as Uint8Array);
  if (plistNode.tag !== 0x04)
    throw new SigningRequestError("malformed cdhash plist");
  const plist = new TextDecoder().decode(plistNode.content);
  const data = [...plist.matchAll(/<data>([\s\S]*?)<\/data>/g)].map((m) =>
    m[1].replace(/\s+/g, "")
  );
  const keys = [...plist.matchAll(/<key>([\s\S]*?)<\/key>/g)].map((m) => m[1]);
  if (
    data.length !== 1 ||
    data[0] !== bytesToBase64(params.digest.subarray(0, 20)) ||
    keys.length !== 1 ||
    keys[0] !== "cdhashes"
  ) {
    throw new SigningRequestError(
      "cdhash plist does not match the CodeDirectory"
    );
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", bufferSource(bytes))
  );
}

// Validates a signing request against the session and returns the bundle id
// it signs. Throws SigningRequestError when anything doesn't match.
export async function validateSigningRequest(params: {
  codeDirectory: Uint8Array;
  signedAttributes: Uint8Array;
  teamId: string;
  approvedBundleIds: string[];
}): Promise<{ bundleId: string; cdhash: string }> {
  const info = parseCodeDirectory(params.codeDirectory);
  if (!params.approvedBundleIds.includes(info.identifier)) {
    throw new SigningRequestError(
      `CodeDirectory identifier ${info.identifier} is not approved for this session`
    );
  }
  if (info.teamId !== params.teamId) {
    throw new SigningRequestError("CodeDirectory team does not match");
  }
  const digest = await sha256(params.codeDirectory);
  checkSignedAttributes({ signedAttributes: params.signedAttributes, digest });
  const cdhash = [...digest.subarray(0, 20)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return { bundleId: info.identifier, cdhash };
}

export async function importDistributionKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    bufferSource(pemToDer(pem, "PRIVATE KEY")),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

export async function signAttributes(params: {
  distributionKeyPem: string;
  signedAttributes: Uint8Array;
}): Promise<Uint8Array> {
  const key = await importDistributionKey(params.distributionKeyPem);
  return new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      bufferSource(params.signedAttributes)
    )
  );
}

// True when the private key belongs to the certificate: a test signature
// verifies with the certificate's public key.
export async function keyMatchesCertificate(params: {
  distributionKeyPem: string;
  certificateDer: Uint8Array;
}): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    bufferSource(certificateSpki(params.certificateDer)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const probe = crypto.getRandomValues(new Uint8Array(32));
  const signature = await signAttributes({
    distributionKeyPem: params.distributionKeyPem,
    signedAttributes: probe,
  });
  return crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    bufferSource(signature),
    bufferSource(probe)
  );
}
