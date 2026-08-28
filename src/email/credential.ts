// IMAP credential shape stored (encrypted at rest) in linked_accounts.
// `secure` means TLS is used for the whole connection (port 993). When `secure`
// is false, imapflow auto-upgrades to STARTTLS if the server advertises it.

export type ImapCredential = {
  email: string;
  password: string;
  host: string;
  port: number;
  secure: boolean;
};

export function serializeCredential(c: ImapCredential): string {
  return JSON.stringify({
    email: c.email,
    password: c.password,
    host: c.host,
    port: c.port,
    secure: c.secure === true,
  });
}

export function parseCredential(stored: string): ImapCredential | null {
  let j: unknown;
  try {
    j = JSON.parse(stored);
  } catch {
    return null;
  }
  if (!j || typeof j !== "object" || Array.isArray(j)) return null;

  const o = j as Record<string, unknown>;
  const email = typeof o.email === "string" ? o.email : null;
  const password = typeof o.password === "string" ? o.password : null;
  const host = typeof o.host === "string" ? o.host : null;
  const port = typeof o.port === "number" ? o.port : null;
  const secure = o.secure === true;

  if (!email || !password || !host || !port || !Number.isInteger(port)) {
    return null;
  }

  return { email, password, host, port, secure };
}
