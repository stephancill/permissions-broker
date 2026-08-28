import type { ImapFlow, MessageEnvelopeObject } from "imapflow";
import { simpleParser } from "mailparser";

import { ImapError, MAX_SOURCE_BYTES } from "./client";

// READ-ONLY OPERATIONS
// --------------------
// Only these three operations exist. Each opens the target mailbox in read-only
// mode (getMailboxLock(..., { readOnly: true }) => IMAP EXAMINE) and uses only
// list / search / fetch / fetchOne. No write method is ever invoked.

export type EmailFolder = {
  path: string;
  delimiter: string;
  attributes: string[];
  specialUse?: string;
};

export async function listFolders(client: ImapFlow): Promise<EmailFolder[]> {
  const list = await client.list();
  return list.map((m) => ({
    path: m.path,
    delimiter: m.delimiter,
    attributes: [...m.flags],
    ...(m.specialUse ? { specialUse: m.specialUse } : {}),
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

// Maps a curated query into an imapflow SearchObject. Kept as its own pure
// function so it can be unit-tested without a live IMAP connection.
export function buildSearchObject(
  query: EmailSearchQuery
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (query.subject) out.subject = query.subject;
  if (query.from) out.from = query.from;
  if (query.to) out.to = query.to;
  if (query.since) out.since = new Date(`${query.since}T00:00:00Z`);
  if (query.before) out.before = new Date(`${query.before}T00:00:00Z`);
  if (query.unseen === true) out.seen = false;
  if (query.unseen === false) out.seen = true;
  if (query.keyword) out.keyword = query.keyword;
  if (query.bodyText) out.body = query.bodyText;
  return out;
}

export async function searchEmails(params: {
  client: ImapFlow;
  mailbox: string;
  query: EmailSearchQuery;
  limit: number;
}): Promise<EmailSearchHit[]> {
  const lock = await params.client.getMailboxLock(params.mailbox, {
    readOnly: true,
  });
  try {
    const search = buildSearchObject(params.query);
    // An empty query matches everything in the mailbox.
    if (Object.keys(search).length === 0) search.all = true;
    const uids = await params.client.search(
      search as Parameters<typeof params.client.search>[0],
      { uid: true }
    );
    if (!uids || uids.length === 0) return [];

    const hits: EmailSearchHit[] = [];
    const slice = uids.slice(0, params.limit);
    for await (const msg of params.client.fetch(slice, {
      uid: true,
      envelope: true,
      internalDate: true,
    })) {
      hits.push({
        uid: msg.uid,
        date: msg.internalDate ? new Date(msg.internalDate).toISOString() : "",
        subject: msg.envelope?.subject ?? "",
        from: formatAddresses(msg.envelope?.from),
      });
    }
    return hits;
  } finally {
    lock.release();
  }
}

export function formatAddresses(
  addresses: MessageEnvelopeObject["from"] | undefined
): string {
  if (!addresses) return "";
  return addresses
    .map((a) => a.address ?? a.name ?? "")
    .filter(Boolean)
    .join(", ");
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

function serializeMessageId(
  e: MessageEnvelopeObject | undefined
): string | undefined {
  return e?.messageId || undefined;
}

export async function readEmail(params: {
  client: ImapFlow;
  mailbox: string;
  uid: number;
  parts: EmailReadParts;
}): Promise<EmailReadResult> {
  const lock = await params.client.getMailboxLock(params.mailbox, {
    readOnly: true,
  });
  try {
    const wantSource = Boolean(
      params.parts.text || params.parts.html || params.parts.raw
    );
    const msg = await params.client.fetchOne(
      String(params.uid),
      {
        uid: true,
        envelope: true,
        internalDate: true,
        size: true,
        flags: true,
        source: wantSource
          ? { start: 0, maxLength: MAX_SOURCE_BYTES }
          : undefined,
      },
      { uid: true }
    );

    if (!msg) throw new ImapError("NOT_FOUND", "message not found");

    const result: EmailReadResult = {
      uid: msg.uid,
      date: msg.internalDate ? new Date(msg.internalDate).toISOString() : "",
      flags: msg.flags ? [...msg.flags] : [],
      subject: msg.envelope?.subject ?? "",
      from: formatAddresses(msg.envelope?.from),
      to: formatAddresses(msg.envelope?.to),
      cc: formatAddresses(msg.envelope?.cc),
      replyTo: formatAddresses(msg.envelope?.replyTo),
      messageId: serializeMessageId(msg.envelope),
    };

    if (msg.source) {
      if (params.parts.raw) {
        result.rawBase64 = msg.source.toString("base64");
      }
      if (params.parts.text || params.parts.html) {
        const parsed = await simpleParser(msg.source);
        if (params.parts.text) result.text = parsed.text || undefined;
        if (params.parts.html) result.html = parsed.html || undefined;
      }
    }

    return result;
  } finally {
    lock.release();
  }
}
