import { ImapFlow } from "imapflow";

import type { ImapCredential } from "./credential";

// READ-ONLY SURFACE
// ----------------
// This module is the only place that talks to an IMAP server. It must be the
// sole owner of outbound IMAP connections. The operations in `ops.ts` call
// read-only methods only (list / search / fetch / fetchOne) and open every
// mailbox with `getMailboxLock(path, { readOnly: true })`, which issues IMAP
// `EXAMINE` — so the server itself rejects any mutation even if a bug/code path
// attempted one. Never add write methods here (append/copy/store/delete/flags/
// mailbox create/rename/delete).

export type ImapErrorCode =
  | "CONNECT_FAILED"
  | "AUTH_FAILED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "OPERATION_FAILED"
  | "BODY_TOO_LARGE";

export class ImapError extends Error {
  code: ImapErrorCode;

  constructor(code: ImapErrorCode, message: string) {
    super(message);
    this.name = "ImapError";
    this.code = code;
  }
}

type ConnectParams = {
  host: string;
  port: number;
  secure: boolean;
  email: string;
  password: string;
};

function isIpLiteral(host: string): boolean {
  // SNI (servername) must not be set for IP literals; Node rejects it.
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

const CONNECTION_TIMEOUT_MS = 15_000;
const GREETING_TIMEOUT_MS = 10_000;
const SOCKET_TIMEOUT_MS = 20_000;
const MAX_SOURCE_BYTES = 1024 * 1024; // 1 MiB cap on fetched message source

type Timeouts = {
  connectionTimeout?: number;
  greetingTimeout?: number;
  socketTimeout?: number;
};

export function buildImapClient(c: ConnectParams): ImapFlow {
  return new ImapFlow({
    host: c.host,
    port: c.port,
    secure: c.secure,
    ...(isIpLiteral(c.host) ? {} : { servername: c.host }),
    disableAutoIdle: true,
    disableCompression: true,
    logger: false,
    connectionTimeout: CONNECTION_TIMEOUT_MS,
    greetingTimeout: GREETING_TIMEOUT_MS,
    socketTimeout: SOCKET_TIMEOUT_MS,
    maxLineLength: 64 * 1024,
    maxLiteralSize: MAX_SOURCE_BYTES,
    maxResponseSize: MAX_SOURCE_BYTES * 2,
    auth: { user: c.email, pass: c.password },
  });
}

function classifyConnectError(err: unknown): ImapError {
  const e = err as { message?: unknown; response?: unknown };
  const msg = typeof e.message === "string" ? e.message : String(e.message);
  const response = typeof e.response === "string" ? e.response : "";
  const haystack = `${msg} ${response}`.toLowerCase();
  if (
    /(authentication failed|authenticationfailed|invalid credentials|invalid login|aupq|authenticationerror)/.test(
      haystack
    )
  ) {
    return new ImapError("AUTH_FAILED", "IMAP authentication failed");
  }
  return new ImapError("CONNECT_FAILED", `IMAP connection failed: ${msg}`);
}

// Runs `fn` against a fresh authenticated connection, then always closes it.
// Each operation gets its own connection so there are no long-lived sockets to
// manage and each request stays well within host/Worker limits.
export async function withImapConnection<T>(
  credential: ImapCredential,
  fn: (client: ImapFlow) => Promise<T>
): Promise<T> {
  const client = buildImapClient(credential);

  try {
    await client.connect();
  } catch (err) {
    try {
      client.close();
    } catch {
      // ignore
    }
    throw classifyConnectError(err);
  }

  try {
    return await fn(client);
  } finally {
    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        // ignore
      }
    }
  }
}

// Verifies a candidate endpoint by connecting and authenticating. Throws an
// ImapError on failure. Used by connect-flow host auto-detection (which passes
// tighter timeouts so probing many candidates stays fast).
export async function verifyImapConnection(
  params: ConnectParams & Timeouts
): Promise<void> {
  const client = new ImapFlow({
    host: params.host,
    port: params.port,
    secure: params.secure,
    ...(isIpLiteral(params.host) ? {} : { servername: params.host }),
    disableAutoIdle: true,
    disableCompression: true,
    logger: false,
    connectionTimeout: params.connectionTimeout ?? CONNECTION_TIMEOUT_MS,
    greetingTimeout: params.greetingTimeout ?? GREETING_TIMEOUT_MS,
    socketTimeout: params.socketTimeout ?? SOCKET_TIMEOUT_MS,
    maxLineLength: 64 * 1024,
    verifyOnly: true,
    auth: { user: params.email, pass: params.password },
  });

  try {
    await client.connect();
  } catch (err) {
    throw classifyConnectError(err);
  } finally {
    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        // ignore
      }
    }
  }
}

export { MAX_SOURCE_BYTES };
