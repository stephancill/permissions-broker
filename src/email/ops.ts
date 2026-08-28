import { simpleParser } from "mailparser";
import { ImapError, MAX_SOURCE_BYTES } from "./client";
import type { ImapClient, ImapCriteria, ImapFolder } from "./protocol";

// READ-ONLY OPERATIONS
// --------------------
// Only these three operations exist. Each opens the target mailbox read-only
// (IMAP EXAMINE) and the underlying protocol module issues only LIST / EXAMINE /
// SEARCH / read FETCHs. No write method is ever invoked.

export type EmailFolder = {
  path: string;
  delimiter: string;
  attributes: string[];
  specialUse?: string;
};

export async function listFolders(client: ImapClient): Promise<EmailFolder[]> {
  const folders: ImapFolder[] = await client.list();
  return folders.map((f) => ({
    path: f.path,
    delimiter: f.delimiter,
    attributes: [...f.attributes],
    ...(f.specialUse ? { specialUse: f.specialUse } : {}),
  }));
}

export type EmailSearchQuery = {
  subject?: string;
  from?: string;
  to?: string;
  since?: string; // yyyy-mm-dd (inclusive)
  before?: string; // yyyy-mm-dd (exclusive)
  unseen?: boolean;
  keyword?: string;
  bodyText?: string;
};

export type EmailSearchHit = {
  uid: number;
  date: string;
  subject: string;
  from: string;
};

// Maps a curated query into IMAP criteria. Kept as its own pure function so it
// can be unit-tested without a live IMAP connection.
export function buildSearchObject(query: EmailSearchQuery): ImapCriteria {
  const out: ImapCriteria = {};
  if (query.subject) out.subject = query.subject;
  if (query.from) out.from = query.from;
  if (query.to) out.to = query.to;
  if (query.since) out.since = new Date(`${query.since}T00:00:00Z`);
  if (query.before) out.before = new Date(`${query.before}T00:00:00Z`);
  if (query.unseen === true) out.unseen = true;
  if (query.unseen === false) out.unseen = false;
  if (query.keyword) out.keyword = query.keyword;
  if (query.bodyText) out.body = query.bodyText;
  return out;
}

export async function searchEmails(params: {
  client: ImapClient;
  mailbox: string;
  query: EmailSearchQuery;
  limit: number;
}): Promise<EmailSearchHit[]> {
  await params.client.examine(params.mailbox);
  const uids = await params.client.uidSearch(buildSearchObject(params.query));
  if (uids.length === 0) return [];

  const slice = uids.slice(0, params.limit);
  const meta = await params.client.fetchHeaders(slice);
  return slice.map((uid) => {
    const m = meta.get(uid);
    return {
      uid,
      date: m?.date ?? "",
      subject: m?.subject ?? "",
      from: m?.from ?? "",
    };
  });
}

export type EmailReadParts = {
  envelope?: boolean;
  text?: boolean;
  html?: boolean;
  raw?: boolean;
};

export type EmailReadResult = {
  uid: number;
  date: string;
  flags: string[];
  subject: string;
  from: string;
  to: string;
  cc: string;
  replyTo: string;
  messageId?: string;
  text?: string;
  html?: string;
  rawBase64?: string;
};

function extractAddresses(
  value: unknown
): Array<{ address?: string; name?: string }> {
  if (Array.isArray(value)) {
    const out: Array<{ address?: string; name?: string }> = [];
    for (const item of value) out.push(...extractAddresses(item));
    return out;
  }
  if (value && typeof value === "object") {
    const inner = (value as { value?: unknown }).value;
    if (Array.isArray(inner)) {
      const addresses: Array<{ address?: string; name?: string }> = [];
      for (const a of inner) {
        if (a && typeof a === "object") {
          const o = a as { address?: unknown; name?: unknown };
          addresses.push({
            address: typeof o.address === "string" ? o.address : undefined,
            name: typeof o.name === "string" ? o.name : undefined,
          });
        }
      }
      return addresses;
    }
  }
  return [];
}

function formatAddresses(value: unknown): string {
  return extractAddresses(value)
    .map((a) => a.address ?? a.name ?? "")
    .filter(Boolean)
    .join(", ");
}

export async function readEmail(params: {
  client: ImapClient;
  mailbox: string;
  uid: number;
  parts: EmailReadParts;
}): Promise<EmailReadResult> {
  await params.client.examine(params.mailbox);
  const got = await params.client.fetchOne({
    uid: params.uid,
    maxSourceBytes: MAX_SOURCE_BYTES,
  });
  if (!got.source) throw new ImapError("NOT_FOUND", "message not found");

  const parsed = await simpleParser(got.source);

  const result: EmailReadResult = {
    uid: got.uid,
    date: got.internalDate
      ? got.internalDate.toISOString()
      : parsed.date
        ? parsed.date.toISOString()
        : "",
    flags: got.flags,
    subject: parsed.subject ?? "",
    from: formatAddresses(parsed.from),
    to: formatAddresses(parsed.to),
    cc: formatAddresses(parsed.cc),
    replyTo: formatAddresses(parsed.replyTo),
    messageId: parsed.messageId || undefined,
  };

  if (params.parts.raw) {
    result.rawBase64 = got.source.toString("base64");
  }
  if (params.parts.text) result.text = parsed.text || undefined;
  if (params.parts.html) result.html = parsed.html || undefined;

  return result;
}
