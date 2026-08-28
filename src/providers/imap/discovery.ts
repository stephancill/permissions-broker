import { verifyImapConnection } from "../../email/client";

// Host auto-detection for generic IMAP connect flow.
// 1) Query the Thunderbird ISPDB autoconfig for the email domain (covers Gmail,
//    Outlook/Office 365, iCloud, Yahoo, Proton, and hundreds of others).
// 2) Fall back to domain heuristics (imap.<domain>, mail.<domain>, <domain>).
// 3) Verify each candidate by actually connecting and authenticating with the
//    user's credentials, returning the first that works.

export type ImapEndpoint = {
  host: string;
  port: number;
  secure: boolean;
};

export function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  if (at === -1) throw new Error("invalid email address");
  const domain = email
    .slice(at + 1)
    .trim()
    .toLowerCase();
  if (!domain || !domain.includes(".")) throw new Error("invalid email domain");
  return domain;
}

function extractTag(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, "i");
  const m = block.match(re);
  return m?.[1]?.trim() || null;
}

// Parse the first IMAP <incomingServer> block from an ISPDB autoconfig document.
function parseIspbImapEndpoint(xml: string): ImapEndpoint | null {
  const blocks =
    xml.match(
      /<incomingServer[^>]*type\s*=\s*"imap"[^>]*>[\s\S]*?<\/incomingServer>/gi
    ) ?? [];

  for (const block of blocks) {
    const host = extractTag(block, "hostname");
    if (!host) continue;
    const portRaw = extractTag(block, "port");
    const port = portRaw ? Number(portRaw) : 993;
    const socketType = (extractTag(block, "socketType") ?? "").toUpperCase();
    // SSL -> TLS for the whole connection; STARTTLS/plain -> imapflow upgrades.
    const secure = socketType !== "STARTTLS" && socketType !== "PLAIN";
    return { host, port, secure };
  }
  return null;
}

async function fetchIspbConfig(domain: string): Promise<ImapEndpoint | null> {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 8_000);
  try {
    const res = await fetch(
      `https://autoconfig.thunderbird.net/v1.1/${domain}`,
      {
        headers: { accept: "application/xml, text/xml" },
        signal: ctrl.signal,
      }
    );
    if (!res.ok) return null;
    const text = await res.text();
    return parseIspbImapEndpoint(text);
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function candidateEndpoints(domain: string): ImapEndpoint[] {
  const out: ImapEndpoint[] = [];
  for (const prefix of ["imap", "mail", "imaps", ""]) {
    const host = prefix ? `${prefix}.${domain}` : domain;
    out.push({ host, port: 993, secure: true });
    out.push({ host, port: 143, secure: false });
  }
  return out;
}

export async function discoverImapSettings(params: {
  email: string;
  password: string;
}): Promise<ImapEndpoint> {
  const domain = emailDomain(params.email);

  const candidates: ImapEndpoint[] = [];
  const isp = await fetchIspbConfig(domain);
  if (isp) candidates.push(isp);
  candidates.push(...candidateEndpoints(domain));

  // Deduplicate by host:port.
  const seen = new Set<string>();
  const unique: ImapEndpoint[] = [];
  for (const c of candidates) {
    const key = `${c.host}:${c.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(c);
  }

  // Keep probing bounded so the connect form stays responsive.
  const attempts = unique.slice(0, 6);
  const failures: string[] = [];
  for (const c of attempts) {
    try {
      await verifyImapConnection({
        host: c.host,
        port: c.port,
        secure: c.secure,
        email: params.email,
        password: params.password,
        connectionTimeout: 6_000,
        greetingTimeout: 5_000,
        socketTimeout: 8_000,
      });
      return c;
    } catch {
      failures.push(`${c.host}:${c.port}`);
    }
  }

  throw new Error(
    `Could not connect to any IMAP server for ${domain}. Tried: ${failures.join(", ")}`
  );
}
