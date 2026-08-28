// Minimal local IMAP4rev1 test server for exercising the broker's read-only
// email path without a real mailbox. Plaintext only (no TLS), seeded with two
// sample messages. Implements just enough of the protocol for imapflow to
// LIST / EXAMINE (read-only) / SEARCH / FETCH against it. Dev tooling only.
//
//   bun scripts/imap_test_server.ts        # start standalone
//   import { startImapTestServer } from "./imap_test_server";  # embed in a harness

type ImapTestMessage = {
  seq: number;
  uid: number;
  flags: string[];
  internalDate: Date;
  date: string;
  subject: string;
  raw: string;
  mailbox: string;
};

function buildMessages(): ImapTestMessage[] {
  const mk = (params: {
    seq: number;
    uid: number;
    date: string;
    subject: string;
    from: string;
    to: string;
    messageId: string;
    text: string;
    seen?: boolean;
  }): ImapTestMessage => {
    const raw = [
      `Date: ${params.date}`,
      `From: ${params.from}`,
      `To: ${params.to}`,
      `Subject: ${params.subject}`,
      `Message-ID: ${params.messageId}`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 7bit",
      "",
      params.text,
      "",
    ].join("\r\n");
    return {
      seq: params.seq,
      uid: params.uid,
      flags: params.seen ? ["\\Seen"] : [],
      internalDate: new Date(params.date),
      date: params.date,
      subject: params.subject,
      raw,
      mailbox: "INBOX",
    };
  };

  return [
    mk({
      seq: 1,
      uid: 1,
      date: "Thu, 20 Aug 2026 09:12:00 +0000",
      subject: "Invoice #123 from ACME",
      from: "ACME Billing <billing@example.com>",
      to: "You <you@example.com>",
      messageId: "<invoice-123@example.com>",
      text: "Dear customer,\r\n\r\nPlease find attached invoice #123 for $1,234.56.\r\n\r\nThanks,\r\nACME",
      seen: true,
    }),
    mk({
      seq: 2,
      uid: 2,
      date: "Fri, 21 Aug 2026 16:45:00 +0000",
      subject: "Re: Invoice #123",
      from: "You <you@example.com>",
      to: "ACME Billing <billing@example.com>",
      messageId: "<re-invoice-123@example.com>",
      text: "Quick question about line items on invoice #123.\r\n",
    }),
  ];
}

type ConnState = {
  buffer: Buffer;
  authenticated: boolean;
  awaitingAuthPayload: boolean;
  pendingAuthTag: string | null;
  selected: string | null;
};

type SocketLike = {
  write(data: string | Uint8Array): number;
  end(): void;
};

function quoted(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function imapDateTime(d: Date): string {
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
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}-${months[d.getUTCMonth()]}-${d.getUTCFullYear()} ${p(
    d.getUTCHours()
  )}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

function resolveRange(seqSet: string, max: number): number[] {
  const out: number[] = [];
  for (const part of seqSet.split(",")) {
    const range = part.match(/^(\d+):(\d+)$/);
    if (range) {
      const start = Number(range[1]);
      const end = Number(range[2]);
      for (let i = start; i <= end && i <= max; i++) out.push(i);
    } else {
      const n = Number(part);
      if (Number.isInteger(n) && n >= 1 && n <= max) out.push(n);
    }
  }
  return [...new Set(out)].sort((a, b) => a - b);
}

export type ImapTestHandle = {
  host: string;
  port: number;
  stop(): void;
};

export function startImapTestServer(params?: {
  host?: string;
  port?: number;
  username?: string;
  password?: string;
}): Promise<ImapTestHandle> {
  const host = params?.host ?? "127.0.0.1";
  const port = params?.port ?? 0;
  const username = params?.username ?? "test@example.com";
  const password = params?.password ?? "testpass";
  const messages = buildMessages();

  const server = Bun.listen({
    hostname: host,
    port,
    socket: {
      open(socket) {
        const raw = socket as unknown as SocketLike & { data: unknown };
        raw.data = {
          buffer: Buffer.alloc(0),
          authenticated: false,
          awaitingAuthPayload: false,
          pendingAuthTag: null,
          selected: null,
        } satisfies ConnState;
        socket.write(
          `* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN] imaptest ready\r\n`
        );
      },
      data(socket, data) {
        const raw = socket as unknown as SocketLike & { data: ConnState };
        const state = raw.data;
        state.buffer = Buffer.concat([state.buffer, Buffer.from(data)]);

        // Complete an in-progress AUTH PLAIN continuation once the SASL
        // payload line arrives, then continue with any buffered commands.
        if (state.awaitingAuthPayload) {
          const ascii = state.buffer.toString("utf8");
          const idx = ascii.indexOf("\r\n");
          if (idx === -1) return; // wait for the full line
          state.buffer = Buffer.from(ascii.slice(idx + 2), "utf8");
          state.awaitingAuthPayload = false;
          state.authenticated = true;
          socket.write(`${state.pendingAuthTag} OK authenticated\r\n`);
          state.pendingAuthTag = null;
        }

        const text = state.buffer.toString("utf8");
        if (!text.includes("\r\n")) return;
        const lines = text.split("\r\n");
        const last = lines.pop();
        state.buffer = last ? Buffer.from(last, "utf8") : Buffer.alloc(0);
        for (const line of lines) {
          if (line.trim()) handleLine(socket, state, line);
        }
      },
      close() {
        // connection closed
      },
      error(_socket, err) {
        console.error("imap test server socket error:", err.message);
      },
    },
  });

  function handleLine(
    socket: SocketLike,
    state: ConnState,
    line: string
  ): void {
    const space = line.indexOf(" ");
    const tag = space === -1 ? line : line.slice(0, space);
    const rest = space === -1 ? "" : line.slice(space + 1).trim();

    if (/^NOOP$/i.test(rest)) {
      socket.write(`${tag} OK NOOP completed\r\n`);
      return;
    }
    if (/^LOGOUT$/i.test(rest)) {
      socket.write(`* BYE logging out\r\n${tag} OK LOGOUT completed\r\n`);
      socket.end();
      return;
    }
    if (/^CAPABILITY$/i.test(rest)) {
      socket.write(
        `* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n${tag} OK CAPABILITY completed\r\n`
      );
      return;
    }
    if (/^(CLOSE|UNSELECT)$/i.test(rest)) {
      state.selected = null;
      socket.write(`${tag} OK done\r\n`);
      return;
    }

    const login = rest.match(/^LOGIN\s+(\S+)\s+(\S+)$/i);
    if (login) {
      const user = (login[1] ?? "").replace(/^"|"$/g, "");
      const pass = (login[2] ?? "").replace(/^"|"$/g, "");
      if (user === username && pass === password) {
        state.authenticated = true;
        socket.write(`${tag} OK LOGIN completed\r\n`);
      } else {
        socket.write(
          `${tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n`
        );
      }
      return;
    }

    const auth = rest.match(/^AUTHENTICATE\s+PLAIN(?:\s+(\S+))?$/i);
    if (auth) {
      if (auth[1]) {
        state.authenticated = true;
        socket.write(`${tag} OK authenticated\r\n`);
      } else {
        state.awaitingAuthPayload = true;
        state.pendingAuthTag = tag;
        socket.write(`+ \r\n`);
      }
      return;
    }

    if (!state.authenticated) {
      socket.write(`${tag} NO please authenticate first\r\n`);
      return;
    }

    // LIST <ref> <pattern> — tokens may be quoted.
    const list = rest.match(/^LIST\s+("(?:[^"]*)"|\S+)\s+("(?:[^"]*)"|\S+)$/i);
    if (list) {
      const pattern = (list[2] ?? "").replace(/^"|"$/g, "");
      const folders = [
        `* LIST (\\HasNoChildren \\Inbox) "/" "INBOX"`,
        `* LIST (\\HasNoChildren) "/" "Archive"`,
      ];
      if (pattern === "") {
        // Root hierarchy marker (not selectable); clients probe the delimiter.
        socket.write(
          `* LIST (\\Noselect) "/" ""\r\n${tag} OK LIST completed\r\n`
        );
      } else {
        socket.write(`${folders.join("\r\n")}\r\n${tag} OK LIST completed\r\n`);
      }
      return;
    }

    const lsub = rest.match(/^LSUB\s+("(?:[^"]*)"|\S+)\s+("(?:[^"]*)"|\S+)$/i);
    if (lsub) {
      const pattern = (lsub[2] ?? "").replace(/^"|"$/g, "");
      const folders = [
        `* LSUB (\\HasNoChildren \\Inbox) "/" "INBOX"`,
        `* LSUB (\\HasNoChildren) "/" "Archive"`,
      ];
      socket.write(
        `${pattern === "" ? "" : `${folders.join("\r\n")}\r\n`}${tag} OK LSUB completed\r\n`
      );
      return;
    }

    const select = rest.match(/^(EXAMINE|SELECT)\s+(\S+)$/i);
    if (select) {
      const name = (select[2] ?? "").replace(/^"|"$/g, "");
      const count = messages.filter((m) => m.mailbox === name).length;
      state.selected = name;
      const command = (select[1] ?? "").toUpperCase();
      const readOnly = command === "EXAMINE";
      socket.write(
        `${[
          `* ${count} EXISTS`,
          `* 0 RECENT`,
          `* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)`,
          `* OK [UIDVALIDITY 1] UIDs valid`,
          `* OK [UIDNEXT ${count + 1}] predicted next UID`,
          `${tag} OK [${readOnly ? "READ-ONLY" : "READ-WRITE"}] ${command} completed`,
        ].join("\r\n")}\r\n`
      );
      return;
    }

    const fetch = rest.match(/^(?:UID\s+)?FETCH\s+(\S+)\s+\(([\s\S]*)\)$/i);
    if (fetch) {
      sendFetch(socket, state, tag, fetch[1] ?? "", fetch[2] ?? "");
      return;
    }

    if (/^(?:UID\s+)?SEARCH/i.test(rest)) {
      const count = messages.filter(
        (m) => m.mailbox === (state.selected ?? "INBOX")
      ).length;
      const seqs = Array.from({ length: count }, (_, i) => i + 1);
      socket.write(
        `* SEARCH ${seqs.join(" ")}\r\n${tag} OK SEARCH completed\r\n`
      );
      return;
    }

    // Unknown command: respond NO so the client surfaces the gap loudly.
    socket.write(`${tag} NO command not implemented\r\n`);
  }

  function headersOf(m: ImapTestMessage): string {
    return m.raw.split("\r\n\r\n", 1)[0] ?? m.raw;
  }

  function sendFetch(
    socket: SocketLike,
    state: ConnState,
    tag: string,
    seqSet: string,
    items: string
  ): void {
    const mailboxMessages = messages.filter(
      (m) => m.mailbox === (state.selected ?? "INBOX")
    );
    const wanted = resolveRange(seqSet, mailboxMessages.length);
    const wantHeader = /BODY(?:\.PEEK)?\[HEADER\]/i.test(items);
    const hasBody = /BODY(?:\.PEEK)?\[\]/i.test(items);

    const responses = wanted.map((seq) => {
      const m = mailboxMessages[seq - 1];
      if (!m) return null;
      const parts: string[] = [];
      if (/UID/i.test(items)) parts.push(`UID ${m.uid}`);
      if (/FLAGS/i.test(items)) parts.push(`FLAGS (${m.flags.join(" ")})`);
      if (/INTERNALDATE/i.test(items))
        parts.push(`INTERNALDATE ${quoted(imapDateTime(m.internalDate))}`);
      if (/RFC822\.SIZE/i.test(items))
        parts.push(`RFC822.SIZE ${Buffer.byteLength(m.raw)}`);
      if (wantHeader) {
        const headers = headersOf(m);
        parts.push(
          `BODY[HEADER] {${Buffer.byteLength(headers)}}\r\n${headers}`
        );
      } else if (hasBody) {
        parts.push(`BODY[] {${Buffer.byteLength(m.raw)}}\r\n${m.raw}`);
      }
      return `* ${seq} FETCH (${parts.join(" ")})`;
    });

    socket.write(
      `${[...responses.filter(Boolean), `${tag} OK FETCH completed`].join("\r\n")}\r\n`
    );
  }

  return Promise.resolve({
    host: server.hostname,
    port: server.port,
    stop: () => {
      try {
        server.stop();
      } catch {
        // ignore
      }
    },
  });
}

if (import.meta.main) {
  const h = await startImapTestServer({
    port: Number(process.env.IMAP_TEST_PORT ?? 11430),
  });
  console.log(
    `imap test server listening on imap://${h.host}:${h.port} (user: test@example.com / testpass)`
  );
}
