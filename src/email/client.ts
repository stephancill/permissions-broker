import type { ImapCredential } from "./credential";
import { ImapClient } from "./protocol";

// READ-ONLY SURFACE
// ----------------
// This module is the only place that talks to an IMAP server and the sole owner
// of outbound IMAP connections. The underlying client (`protocol.ts`) implements
// ONLY read operations (LIST / EXAMINE / SEARCH / read FETCHs), so read-only is
// enforced by construction. Never add write methods here (append/copy/store/
// delete/flags/mailbox create/rename/delete).

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

type VerifyParams = ConnectParams & {
  connectionTimeout?: number;
};

const MAX_SOURCE_BYTES = 1024 * 1024; // 1 MiB cap on fetched message source

function classifyConnectError(err: unknown): ImapError {
  const e = err as { message?: unknown; response?: unknown };
  const msg = typeof e.message === "string" ? e.message : String(e.message);
  const response = typeof e.response === "string" ? e.response : "";
  const haystack = `${msg} ${response}`.toLowerCase();
  if (
    /(authentication failed|authenticationfailed|invalid credentials|invalid login|aupq|authenticationerror|no \[authentication)/.test(
      haystack
    )
  ) {
    return new ImapError("AUTH_FAILED", "IMAP authentication failed");
  }
  return new ImapError("CONNECT_FAILED", `IMAP connection failed: ${msg}`);
}

export function buildImapClient(credential: ImapCredential): ImapClient {
  return new ImapClient({
    host: credential.host,
    port: credential.port,
    secure: credential.secure,
    email: credential.email,
    password: credential.password,
  });
}

// Runs `fn` against a fresh authenticated connection, then always closes it.
// Each operation gets its own connection so there are no long-lived sockets to
// manage and each request stays well within host/Worker limits.
export async function withImapConnection<T>(
  credential: ImapCredential,
  fn: (client: ImapClient) => Promise<T>
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
  params: VerifyParams
): Promise<void> {
  const client = new ImapClient({
    host: params.host,
    port: params.port,
    secure: params.secure,
    email: params.email,
    password: params.password,
  });

  try {
    await client.connect(params.connectionTimeout ?? 12_000);
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
