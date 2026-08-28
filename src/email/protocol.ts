// Minimal, focused IMAP4rev1 client used by the broker's read-only email path.
//
// It deliberately implements ONLY read operations (CAPABILITY / AUTH / LOGIN /
// LIST / EXAMINE / SEARCH / FETCH(read parts) / LOGOUT) so read-only is
// enforced by construction. This exists because `imapflow`'s stream handling
// does not work on the Cloudflare Workers node:net/node:tls shim, while the raw
// socket APIs do.
//
// READ-ONLY SURFACE: this module never issues STORE/APPEND/COPY/EXPUNGE, flag
// manipulation, or mailbox create/delete/rename.

import net from "node:net";
import tls from "node:tls";

export type ImapFolder = {
  path: string;
  delimiter: string;
  attributes: string[];
  specialUse?: string;
};

export type ImapHeaderMeta = {
  subject: string;
  from: string;
  to: string;
  date: string;
  messageId?: string;
};

export type ImapCriteria = {
  subject?: string;
  from?: string;
  to?: string;
  since?: Date;
  before?: Date;
  unseen?: boolean;
  keyword?: string;
  body?: string;
  all?: boolean;
};

export type ImapCred = {
  host: string;
  port: number;
  secure: boolean;
  email: string;
  password: string;
};

type Token =
  | { type: "atom"; value: string }
  | { type: "literal"; value: Buffer }
  | { type: "list"; items: Token[] };

function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

function quotedString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function imapDate(d: Date): string {
  const months = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];
  return `${d.getUTCDate()}-${months[d.getUTCMonth()]}-${d.getUTCFullYear()}`;
}

export function compileSearchCriteria(q: ImapCriteria): string {
  const parts: string[] = [];
  if (q.all) parts.push("ALL");
  if (q.subject) parts.push(`SUBJECT ${quotedString(q.subject)}`);
  if (q.from) parts.push(`FROM ${quotedString(q.from)}`);
  if (q.to) parts.push(`TO ${quotedString(q.to)}`);
  if (q.since) parts.push(`SINCE ${imapDate(q.since)}`);
  if (q.before) parts.push(`BEFORE ${imapDate(q.before)}`);
  if (q.unseen === true) parts.push("UNSEEN");
  if (q.unseen === false) parts.push("SEEN");
  if (q.keyword) parts.push(`KEYWORD ${quotedString(q.keyword)}`);
  if (q.body) parts.push(`BODY ${quotedString(q.body)}`);
  if (parts.length === 0) return "ALL";
  return parts.join(" ");
}

type CommandResult = {
  status: string; // OK | NO | BAD | CONTINUE
  text: string;
  untagged: Token[][];
};

class ConnectionReader {
  private buffer = Buffer.alloc(0);
  private pos = 0;
  private waiters: Array<() => void> = [];
  private closed = false;

  constructor(socket: net.Socket) {
    socket.on("data", (chunk: Uint8Array) => {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
      const w = this.waiters.splice(0);
      for (const r of w) r();
    });
    socket.on("error", () => {
      this.closed = true;
      const w = this.waiters.splice(0);
      for (const r of w) r();
    });
    socket.on("close", () => {
      this.closed = true;
      const w = this.waiters.splice(0);
      for (const r of w) r();
    });
  }

  private async more(): Promise<void> {
    if (this.buffer.length - this.pos > 0 || this.closed) return;
    await new Promise<void>((resolve) => {
      this.waiters.push(() => resolve());
    });
  }

  // Waits until at least `minBytes` new bytes are available (or EOF), yielding
  // to the event loop between chunks so reading a large literal does not blow
  // the host's CPU budget.
  private async moreForChunk(minBytes: number): Promise<void> {
    if (this.buffer.length - this.pos >= minBytes || this.closed) return;
    await new Promise<void>((resolve) => {
      this.waiters.push(() => resolve());
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  private async readToken(): Promise<Token | null> {
    for (;;) {
      await this.more();
      const ch = this.buffer[this.pos];
      if (ch === undefined) return null;
      if (ch === 13 || ch === 10 || ch === 32 || ch === 9) {
        this.pos++;
        continue;
      }
      const first = ch;
      return this.readTokenFrom(first);
    }
  }

  private async readTokenFrom(ch: number): Promise<Token | null> {
    if (ch === 40) {
      // nested list
      this.pos++;
      const items: Token[] = [];
      for (;;) {
        await this.more();
        const c = this.buffer[this.pos];
        if (c === undefined) return null;
        if (c === 41) {
          this.pos++;
          return { type: "list", items };
        }
        if (c === 13 || c === 10 || c === 32 || c === 9) {
          this.pos++;
          continue;
        }
        const t = await this.readToken();
        if (!t) return null;
        items.push(t);
      }
    }

    if (ch === 34) {
      // quoted string -> atom token with unquoted value
      this.pos++;
      let out = "";
      for (;;) {
        await this.more();
        const c = this.buffer[this.pos];
        if (c === undefined) return null;
        if (c === 92) {
          this.pos++;
          await this.more();
          const e = this.buffer[this.pos];
          if (e === undefined) return null;
          out += String.fromCharCode(e);
          this.pos++;
          continue;
        }
        if (c === 34) {
          this.pos++;
          return { type: "atom", value: out };
        }
        out += String.fromCharCode(c);
        this.pos++;
      }
    }

    if (ch === 123) {
      // {N}\r\n literal
      const start = this.pos + 1;
      let end = start;
      for (;;) {
        await this.more();
        const c = this.buffer[end];
        if (c === undefined) return null;
        if (c === 125) break;
        end++;
      }
      const n = Number(this.buffer.subarray(start, end).toString("utf8"));
      if (!Number.isInteger(n) || n < 0) return null;
      this.pos = end + 1;
      if (this.buffer[this.pos] === 13 && this.buffer[this.pos + 1] === 10) {
        this.pos += 2;
      } else if (this.buffer[this.pos] === 10) {
        this.pos += 1;
      }
      // Accumulate the literal with periodic yields so the CPU stays within
      // host/Worker budget even for large messages.
      const parts: Buffer[] = [];
      if (this.buffer.length - this.pos > 0) {
        const take = Math.min(n, this.buffer.length - this.pos);
        parts.push(
          Buffer.from(this.buffer.subarray(this.pos, this.pos + take))
        );
        this.pos += take;
      }
      let got = parts[0]?.byteLength ?? 0;
      while (got < n) {
        await this.moreForChunk(64 * 1024);
        const take = Math.min(n - got, this.buffer.length - this.pos);
        parts.push(
          Buffer.from(this.buffer.subarray(this.pos, this.pos + take))
        );
        this.pos += take;
        got += take;
      }
      return { type: "literal", value: Buffer.concat(parts) };
    }

    // atom
    let out = "";
    for (;;) {
      const c = this.buffer[this.pos];
      if (
        c === undefined ||
        c === 32 ||
        c === 9 ||
        c === 40 ||
        c === 41 ||
        c === 13 ||
        c === 10
      ) {
        break;
      }
      out += String.fromCharCode(c);
      this.pos++;
    }
    return { type: "atom", value: out };
  }

  // Reads one IMAP response: top-level tokens ending at a CRLF outside of a
  // literal. Returns null on clean EOF.
  async readResponse(): Promise<Token[] | null> {
    const tokens: Token[] = [];
    for (;;) {
      const token = await this.readToken();
      if (!token) return tokens.length ? tokens : null;
      tokens.push(token);
      const c = this.buffer[this.pos];
      if (c === 13 || c === undefined) {
        if (c === 13) {
          this.pos++;
          if (this.buffer[this.pos] === 10) this.pos++;
        }
        return tokens;
      }
    }
  }
}

function tokenString(t: Token | undefined): string {
  if (!t) return "";
  if (t.type === "literal") return t.value.toString("utf8");
  if (t.type === "atom") return t.value;
  return t.items.map(tokenString).join(" ");
}

function isAtom(t: Token | undefined, value: string): boolean {
  return t?.type === "atom" && t.value === value;
}

function extractCapabilities(tokens: Token[]): Set<string> {
  const out = new Set<string>();
  const walk = (arr: Token[]) => {
    for (const t of arr) {
      if (t.type === "atom") {
        const u = t.value.toUpperCase();
        if (
          /^(IMAP4|AUTH=|STARTTLS|SASL-IR|LITERAL\+|LOGIN-REFERRALS)/.test(u) ||
          /^AUTH=[A-Z0-9]+]$/.test(u)
        ) {
          out.add(u);
        }
      } else if (t.type === "list") {
        walk(t.items);
      }
    }
  };
  walk(tokens);
  return out;
}

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

function parseImapDateTime(s: string): Date | null {
  const m = s.match(
    /^(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/
  );
  if (!m) return null;
  const month = MONTHS[m[2] ?? ""];
  if (month === undefined) return null;
  const zone = m[7] ?? "+0000";
  const sign = zone.startsWith("-") ? -1 : 1;
  const offsetMin = Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5));
  const dt = new Date(
    Date.UTC(
      Number(m[3]),
      month,
      Number(m[1]),
      Number(m[4]),
      Number(m[5]),
      Number(m[6])
    )
  );
  return new Date(dt.getTime() - sign * offsetMin * 60_000);
}

function parseFetch(tokens: Token[]): {
  uid?: number;
  flags?: string[];
  internalDate?: Date;
  headerLiteral?: Buffer;
  source?: Buffer;
} {
  const out: {
    uid?: number;
    flags?: string[];
    internalDate?: Date;
    headerLiteral?: Buffer;
    source?: Buffer;
  } = {};
  let list: Token[] | null = null;
  for (const t of tokens) {
    if (t.type === "list") {
      list = t.items;
      break;
    }
  }
  if (!list) return out;

  const normKey = (s: string): string =>
    s.split("<", 1)[0]?.toLowerCase().trim() ?? "";

  for (let i = 0; i < list.length; i++) {
    const key = normKey(tokenString(list[i]));
    const val = list[i + 1];
    if (key === "uid" && val?.type === "atom") {
      const n = Number(val.value);
      if (Number.isInteger(n)) out.uid = n;
      i++;
      continue;
    }
    if (key === "flags" && val?.type === "list") {
      out.flags = val.items.map(tokenString);
      i++;
      continue;
    }
    if (key.startsWith("internaldate") && val?.type === "atom") {
      const d = parseImapDateTime(val.value);
      if (d) out.internalDate = d;
      i++;
      continue;
    }
    if (key.startsWith("body[header]") && val?.type === "literal") {
      out.headerLiteral = val.value;
      i++;
      continue;
    }
    if (key.startsWith("body[")) {
      if (key.includes("[")) i++;
      if (val?.type === "literal") out.source = val.value;
      i++;
    }
  }
  return out;
}

export function parseHeaders(buf: Buffer): ImapHeaderMeta {
  const lines = buf.toString("utf8").replace(/\r\n/g, "\n").split("\n");
  const unfolded: string[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else {
      unfolded.push(line);
    }
  }
  const getHeader = (name: string): string => {
    const lower = name.toLowerCase();
    for (const line of unfolded) {
      const idx = line.indexOf(":");
      if (idx <= 0) continue;
      if (line.slice(0, idx).trim().toLowerCase() === lower) {
        return line.slice(idx + 1).trim();
      }
    }
    return "";
  };
  const addr = (raw: string): string => {
    const m = raw.match(/<([^>]+)>/);
    return m?.[1] ?? raw;
  };
  return {
    subject: getHeader("Subject"),
    from: addr(getHeader("From")),
    to: addr(getHeader("To")),
    date: getHeader("Date"),
    messageId: getHeader("Message-ID") || undefined,
  };
}

export class ImapClient {
  private cred: ImapCred;
  private socket: net.Socket | null = null;
  private reader: ConnectionReader | null = null;
  private tagCounter = 0;
  private capabilities = new Set<string>();
  private operationTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(cred: ImapCred) {
    this.cred = cred;
  }

  private get conn(): ConnectionReader {
    if (!this.reader) throw new Error("IMAP connection is not open");
    return this.reader;
  }

  private nextTag(): string {
    this.tagCounter += 1;
    return `A${this.tagCounter}`;
  }

  private armTimeout(ms: number): void {
    this.disarmTimeout();
    this.operationTimer = setTimeout(() => this.destroy(), ms);
  }

  private disarmTimeout(): void {
    if (this.operationTimer) {
      clearTimeout(this.operationTimer);
      this.operationTimer = null;
    }
  }

  private destroy(): void {
    try {
      this.socket?.destroy();
    } catch {
      // ignore
    }
  }

  private get capAuthPlain(): boolean {
    return this.capabilities.has("AUTH=PLAIN");
  }

  private get capStartTls(): boolean {
    return this.capabilities.has("STARTTLS");
  }

  async connect(timeoutMs = 20_000): Promise<void> {
    const host = this.cred.host;
    const common = {
      host,
      port: this.cred.port,
      ...(!isIpLiteral(host) ? { servername: host } : {}),
    };

    const socket = this.cred.secure ? tls.connect(common) : net.connect(common);
    this.socket = socket;
    this.reader = new ConnectionReader(socket);

    await new Promise<void>((resolve, reject) => {
      const event = this.cred.secure ? "secureConnect" : "connect";
      socket.once(event, () => resolve());
      socket.once("error", (err: Error) => reject(err));
    });

    // Greeting (may carry [CAPABILITY ...]).
    const greeting = await this.run(() => this.conn.readResponse(), timeoutMs);
    if (greeting) this.capabilities = extractCapabilities(greeting);

    // If capabilities are missing, ask explicitly.
    if (!this.capabilities.has("IMAP4")) {
      const res = await this.command("CAPABILITY");
      for (const r of res.untagged) {
        this.capabilities = new Set([
          ...this.capabilities,
          ...extractCapabilities(r),
        ]);
      }
    }

    // STARTTLS upgrade when configured plaintext and the server supports it.
    if (!this.cred.secure && this.capStartTls) {
      const res = await this.command("STARTTLS");
      if (res.status === "OK" && socket instanceof net.Socket) {
        const upgraded = tls.connect({ ...common, socket });
        this.socket = upgraded;
        this.reader = new ConnectionReader(upgraded);
        await new Promise<void>((resolve, reject) => {
          upgraded.once("secureConnect", () => resolve());
          upgraded.once("error", (err: Error) => reject(err));
        });
      }
    }

    await this.authenticate();
  }

  private async authenticate(): Promise<void> {
    const user = this.cred.email;
    const pass = this.cred.password;
    const b64 = Buffer.from(`\u0000${user}\u0000${pass}`, "utf8").toString(
      "base64"
    );

    if (this.capAuthPlain) {
      // 1) AUTHENTICATE PLAIN with SASL-IR (single line).
      const saslIr = await this.command(`AUTHENTICATE PLAIN ${b64}`);
      if (saslIr.status === "OK") return;
      if (saslIr.status === "CONTINUE") {
        // 2) Server wants the payload on a continuation line.
        this.socket?.write(`${b64}\r\n`);
        const done = await this.run(() => this.runUntilTagged(), 25_000);
        if (done && done.status === "OK") return;
        this.destroy();
        throw new Error("IMAP authentication failed");
      }
      if (!this.socket || this.socket.destroyed) {
        throw new Error("IMAP authentication failed");
      }
    }

    // 3) LOGIN fallback (works on older/limited servers).
    const loginRes = await this.command(
      `LOGIN ${quotedString(user)} ${quotedString(pass)}`
    );
    if (loginRes.status !== "OK") {
      throw new Error(loginRes.text || "IMAP authentication failed");
    }
  }

  async list(): Promise<ImapFolder[]> {
    const res = await this.command('LIST "" "*"');
    if (res.status !== "OK") throw new Error(`LIST failed: ${res.text}`);
    const folders: ImapFolder[] = [];
    const specialFlag = [
      "\\Inbox",
      "\\Sent",
      "\\Drafts",
      "\\Trash",
      "\\Junk",
      "\\Archive",
      "\\All",
      "\\Flagged",
    ];
    for (const r of res.untagged) {
      if (r.length >= 5 && isAtom(r[0], "*") && isAtom(r[1], "LIST")) {
        const attrs = r[2]?.type === "list" ? r[2].items.map(tokenString) : [];
        folders.push({
          path: tokenString(r[4]),
          delimiter: tokenString(r[3]),
          attributes: attrs,
          ...(attrs.find((f) => specialFlag.includes(f))
            ? { specialUse: attrs.find((f) => specialFlag.includes(f)) }
            : {}),
        });
      }
    }
    return folders;
  }

  async examine(mailbox: string): Promise<void> {
    const res = await this.command(`EXAMINE ${quotedString(mailbox)}`);
    if (res.status !== "OK") throw new Error(`EXAMINE failed: ${res.text}`);
  }

  async uidSearch(criteria: ImapCriteria): Promise<number[]> {
    const res = await this.command(
      `UID SEARCH ${compileSearchCriteria(criteria)}`
    );
    if (res.status !== "OK") throw new Error(`SEARCH failed: ${res.text}`);
    const uids: number[] = [];
    for (const r of res.untagged) {
      if (r.length >= 2 && isAtom(r[0], "*") && isAtom(r[1], "SEARCH")) {
        for (let i = 2; i < r.length; i++) {
          const n = Number(tokenString(r[i]));
          if (Number.isInteger(n)) uids.push(n);
        }
      }
    }
    return uids;
  }

  async fetchHeaders(uids: number[]): Promise<Map<number, ImapHeaderMeta>> {
    const map = new Map<number, ImapHeaderMeta>();
    if (uids.length === 0) return map;
    const res = await this.command(
      `UID FETCH ${uids.join(",")} (UID INTERNALDATE BODY.PEEK[HEADER])`
    );
    if (res.status !== "OK") throw new Error(`FETCH failed: ${res.text}`);
    for (const r of res.untagged) {
      const parsed = parseFetch(r);
      if (parsed.uid === undefined) continue;
      if (parsed.headerLiteral) {
        map.set(parsed.uid, parseHeaders(parsed.headerLiteral));
      } else {
        map.set(parsed.uid, {
          subject: "",
          from: "",
          to: "",
          date: parsed.internalDate ? parsed.internalDate.toISOString() : "",
        });
      }
    }
    return map;
  }

  async fetchOne(params: { uid: number; maxSourceBytes: number }): Promise<{
    uid: number;
    flags: string[];
    internalDate: Date | null;
    source: Buffer | null;
  }> {
    const res = await this.command(
      `UID FETCH ${params.uid} (UID FLAGS INTERNALDATE BODY.PEEK[]<0.${params.maxSourceBytes}>)`
    );
    if (res.status !== "OK") throw new Error(`FETCH failed: ${res.text}`);
    for (const r of res.untagged) {
      const parsed = parseFetch(r);
      if (parsed.uid === params.uid) {
        return {
          uid: params.uid,
          flags: parsed.flags ?? [],
          internalDate: parsed.internalDate ?? null,
          source: parsed.source ?? null,
        };
      }
    }
    return { uid: params.uid, flags: [], internalDate: null, source: null };
  }

  async logout(): Promise<void> {
    try {
      await this.command("LOGOUT");
    } finally {
      this.destroy();
    }
  }

  close(): void {
    this.destroy();
  }

  private async run<T>(fn: () => Promise<T>, ms: number): Promise<T> {
    this.armTimeout(ms);
    try {
      return await fn();
    } finally {
      this.disarmTimeout();
    }
  }

  private async command(line: string): Promise<CommandResult> {
    if (!this.socket || this.socket.destroyed) {
      throw new Error("IMAP connection is not open");
    }
    const tag = this.nextTag();
    this.socket.write(`${tag} ${line}\r\n`);
    const result = await this.run(() => this.runUntilTagged(tag), 25_000);
    if (!result) throw new Error("IMAP command timed out");
    return result;
  }

  private async runUntilTagged(tag = ""): Promise<CommandResult | null> {
    const untagged: Token[][] = [];
    for (;;) {
      const tokens = await this.conn.readResponse();
      if (!tokens) {
        throw new Error("IMAP connection closed before command completed");
      }
      if (tokens[0]?.type === "atom" && tokens[0].value === "+") {
        return { status: "CONTINUE", text: "", untagged };
      }
      if (tag && tokens[0]?.type === "atom" && tokens[0].value === tag) {
        return {
          status: tokenString(tokens[1]).toUpperCase(),
          text: tokens.slice(2).map(tokenString).join(" "),
          untagged,
        };
      }
      untagged.push(tokens);
    }
  }
}
