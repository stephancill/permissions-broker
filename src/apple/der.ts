// Minimal DER reader: enough to walk X.509 certificates and the CMS signed
// attributes stupid-app sends for signing. Definite lengths only.

export type DerNode = {
  tag: number;
  // Content bytes (without tag and length).
  content: Uint8Array;
  // The whole encoding (tag, length and content).
  encoded: Uint8Array;
};

export class DerError extends Error {}

export function readDer(
  bytes: Uint8Array,
  offset = 0
): { node: DerNode; next: number } {
  if (offset + 2 > bytes.length) throw new DerError("truncated DER");
  const tag = bytes[offset];
  if ((tag & 0x1f) === 0x1f) throw new DerError("multi-byte DER tags");
  let lengthByte = bytes[offset + 1];
  let cursor = offset + 2;
  let length = lengthByte;
  if (lengthByte & 0x80) {
    const count = lengthByte & 0x7f;
    if (count === 0 || count > 4) throw new DerError("unsupported DER length");
    if (cursor + count > bytes.length) throw new DerError("truncated DER");
    length = 0;
    for (let i = 0; i < count; i++) {
      lengthByte = bytes[cursor + i];
      length = length * 256 + lengthByte;
    }
    cursor += count;
  }
  const end = cursor + length;
  if (end > bytes.length) throw new DerError("truncated DER");
  return {
    node: {
      tag,
      content: bytes.subarray(cursor, end),
      encoded: bytes.subarray(offset, end),
    },
    next: end,
  };
}

// The single DER value spanning all of `bytes`.
export function parseDer(bytes: Uint8Array): DerNode {
  const { node, next } = readDer(bytes, 0);
  if (next !== bytes.length) throw new DerError("trailing bytes after DER");
  return node;
}

export function derChildren(node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let offset = 0;
  while (offset < node.content.length) {
    const { node: child, next } = readDer(node.content, offset);
    out.push(child);
    offset = next;
  }
  return out;
}

export function oidString(node: DerNode): string {
  if (node.tag !== 0x06) throw new DerError("expected an OID");
  const b = node.content;
  if (b.length === 0) throw new DerError("empty OID");
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export function pemToDer(pem: string, label: string): Uint8Array {
  const match = pem.match(
    new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`)
  );
  if (!match) throw new DerError(`expected a PEM ${label}`);
  const b64 = match[1].replace(/\s+/g, "");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// SubjectPublicKeyInfo of an X.509 certificate.
export function certificateSpki(certificateDer: Uint8Array): Uint8Array {
  const certificate = parseDer(certificateDer);
  const [tbs] = derChildren(certificate);
  if (!tbs || tbs.tag !== 0x30) throw new DerError("malformed certificate");
  const fields = derChildren(tbs);
  // Optional explicit version [0] shifts the fields by one.
  const base = fields[0]?.tag === 0xa0 ? 1 : 0;
  const spki = fields[base + 5];
  if (!spki || spki.tag !== 0x30) throw new DerError("malformed certificate");
  return spki.encoded;
}
