import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { type ApiKeyAuth, requireApiKey } from "../auth/apiKey";
import { decryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { type ImapError, withImapConnection } from "../email/client";
import { type ImapCredential, parseCredential } from "../email/credential";
import { listFolders, readEmail, searchEmails } from "../email/ops";
import {
  createEmailSession,
  type EmailSessionRow,
  getEmailSessionKeyScoped,
  setEmailSessionStatus,
  touchEmailSessionActivity,
} from "../email/sessions";
import { env } from "../env";
import { telegramApi } from "../telegram/api";

const SESSION_TTL_MS = 10 * 60_000;
const DEFAULT_RESULTS_LIMIT = 50;
const MAX_RESULTS_LIMIT = 200;

const CreateSessionSchema = z.object({
  consent_hint: z.string().optional(),
});

const SearchSchema = z.object({
  mailbox: z.string().min(1).max(512),
  query: z
    .object({
      subject: z.string().max(512).optional(),
      from: z.string().max(512).optional(),
      to: z.string().max(512).optional(),
      since: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/)
        .optional(),
      before: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/)
        .optional(),
      unseen: z.boolean().optional(),
      keyword: z.string().max(256).optional(),
      body_text: z.string().max(2048).optional(),
    })
    .optional(),
  results_limit: z.number().int().min(1).max(MAX_RESULTS_LIMIT).optional(),
});

const ReadSchema = z.object({
  mailbox: z.string().min(1).max(512),
  uid: z.number().int().positive(),
  parts: z
    .object({
      envelope: z.boolean().optional(),
      text: z.boolean().optional(),
      html: z.boolean().optional(),
      raw: z.boolean().optional(),
    })
    .optional(),
});

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

const PARTS_DEFAULT = { envelope: true };

type LoadResult =
  | { ok: true; session: EmailSessionRow; credential: ImapCredential }
  | { ok: false; response: Response };

async function loadAuthorizedSession(
  c: Context,
  auth: ApiKeyAuth,
  sessionId: string
): Promise<LoadResult> {
  const session = await getEmailSessionKeyScoped({
    sessionId,
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
  });
  if (!session)
    return { ok: false, response: c.json({ error: "forbidden" }, 403) };

  if (session.status === "PENDING_APPROVAL") {
    const exp = Date.parse(session.approval_expires_at);
    if (Number.isFinite(exp) && Date.now() > exp) {
      await setEmailSessionStatus({
        sessionId,
        userId: auth.userId,
        status: "EXPIRED",
      });
      return {
        ok: false,
        response: c.json(
          { error: "approval_expired", session_id: sessionId },
          408
        ),
      };
    }
    return {
      ok: false,
      response: c.json(
        { error: "pending_approval", session_id: sessionId },
        202
      ),
    };
  }

  if (session.status === "DENIED")
    return { ok: false, response: c.json({ error: "denied" }, 403) };
  if (session.status === "EXPIRED")
    return { ok: false, response: c.json({ error: "approval_expired" }, 408) };
  if (session.status !== "APPROVED" && session.status !== "ACTIVE") {
    return {
      ok: false,
      response: c.json({ error: "invalid_state", status: session.status }, 400),
    };
  }

  const database = await db();
  const acct = (await database
    .query(
      "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'imap' AND status = 'active' LIMIT 1;"
    )
    .get(auth.userId)) as { refresh_token_ciphertext: Uint8Array } | null;

  if (!acct)
    return { ok: false, response: c.json({ error: "no_linked_imap" }, 409) };
  if (!env.APP_SECRET)
    return {
      ok: false,
      response: c.json({ error: "server_misconfigured" }, 500),
    };

  let credential: ImapCredential;
  try {
    const stored = await decryptUtf8(acct.refresh_token_ciphertext);
    const parsed = parseCredential(stored);
    if (!parsed)
      return {
        ok: false,
        response: c.json({ error: "invalid_imap_credential" }, 500),
      };
    credential = parsed;
  } catch {
    return {
      ok: false,
      response: c.json({ error: "invalid_imap_credential" }, 500),
    };
  }

  if (session.status === "APPROVED") {
    await setEmailSessionStatus({
      sessionId,
      userId: auth.userId,
      status: "ACTIVE",
    });
    session.status = "ACTIVE";
  }
  await touchEmailSessionActivity(session.id);

  return { ok: true, session, credential };
}

function mapImapError(c: Context, err: unknown): Response {
  const imap = err as ImapError;
  const code = imap?.code;
  switch (code) {
    case "NOT_FOUND":
      return c.json({ error: "not_found", message: imap.message }, 404);
    case "BODY_TOO_LARGE":
      return c.json({ error: "response_too_large" }, 413);
    case "AUTH_FAILED":
      return c.json({ error: "auth_failed", message: imap.message }, 502);
    case "CONNECT_FAILED":
    case "OPERATION_FAILED":
    case "FORBIDDEN":
      return c.json({ error: "execution_failed", message: imap.message }, 502);
    default:
      return c.json({ error: "execution_failed", message: String(err) }, 502);
  }
}

export const emailRouter = new Hono();

// Create an email read session (Telegram approval required).
emailRouter.post("/sessions", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const raw = await c.req.json().catch(() => null);
  const parsed = CreateSessionSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const database = await db();
  const connected = (await database
    .query(
      "SELECT 1 AS ok FROM linked_accounts WHERE user_id = ? AND provider = 'imap' AND status = 'active' LIMIT 1;"
    )
    .get(auth.userId)) as { ok: number } | null;
  if (!connected) return c.json({ error: "no_linked_imap" }, 409);

  const consentHint = parsed.data.consent_hint;
  const created = await createEmailSession({
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
    consentHint,
    approvalTtlMs: SESSION_TTL_MS,
  });

  await auditEvent({
    userId: auth.userId,
    actorType: "api_key",
    actorId: auth.apiKeyId,
    eventType: "email_session_created",
    event: {},
  });

  const u = (await database
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(auth.userId)) as { telegram_user_id: number } | null;

  if (u?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const lines: string[] = [];
    lines.push("<b>Email read session request</b>");
    lines.push("");
    lines.push(`<b>API key</b>: <code>${escapeHtml(auth.apiKeyLabel)}</code>`);
    lines.push(`<b>Provider</b>: <code>imap</code>`);
    lines.push("<b>Access</b>: <code>READ ONLY</code>");
    if (consentHint) {
      lines.push("");
      lines.push(
        `<b>Requester note</b>: ${escapeHtml(truncate(consentHint, 300))}`
      );
    }
    lines.push("");
    lines.push(
      "Approving lets the agent list folders, search, and read messages for up to 10 minutes."
    );

    const kb = {
      inline_keyboard: [
        [
          {
            text: "Approve",
            callback_data: `es:approve:${created.sessionId}`,
          },
          { text: "Deny", callback_data: `es:deny:${created.sessionId}` },
        ],
      ],
    };

    await telegramApi()
      .sendMessage(u.telegram_user_id, lines.join("\n"), {
        reply_markup: kb,
        parse_mode: "HTML",
      })
      .catch(() => {});
  }

  return c.json({
    session_id: created.sessionId,
    status: "PENDING_APPROVAL",
    approval_expires_at: created.approvalExpiresAt,
    read_only: true,
  });
});

// Poll session status.
emailRouter.get("/sessions/:id", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const row = await getEmailSessionKeyScoped({
    sessionId,
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
  });
  if (!row) return c.json({ error: "forbidden" }, 403);

  if (row.status === "PENDING_APPROVAL") {
    const exp = Date.parse(row.approval_expires_at);
    if (Number.isFinite(exp) && Date.now() > exp) {
      await setEmailSessionStatus({
        sessionId,
        userId: auth.userId,
        status: "EXPIRED",
      });
      return c.json({ session_id: row.id, status: "EXPIRED" }, 200);
    }
  }

  return c.json({
    session_id: row.id,
    status: row.status,
    approval_expires_at: row.approval_expires_at,
    read_only: true,
  });
});

// List mailbox folders.
emailRouter.get("/sessions/:id/folders", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const res = await loadAuthorizedSession(c, auth, sessionId);
  if (!res.ok) return res.response;

  try {
    const folders = await withImapConnection(res.credential, (client) =>
      listFolders(client)
    );
    await auditEvent({
      userId: auth.userId,
      actorType: "api_key",
      actorId: auth.apiKeyId,
      eventType: "email_list_folders",
      event: { sessionId },
    });
    return c.json({ folders });
  } catch (err) {
    return mapImapError(c, err);
  }
});

// Search messages in a mailbox.
emailRouter.post("/sessions/:id/search", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const res = await loadAuthorizedSession(c, auth, sessionId);
  if (!res.ok) return res.response;

  const raw = await c.req.json().catch(() => null);
  const parsed = SearchSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const { mailbox, query } = parsed.data;
  const resultsLimit = parsed.data.results_limit ?? DEFAULT_RESULTS_LIMIT;

  try {
    const matches = await withImapConnection(res.credential, (client) =>
      searchEmails({
        client,
        mailbox,
        query: {
          subject: query?.subject,
          from: query?.from,
          to: query?.to,
          since: query?.since,
          before: query?.before,
          unseen: query?.unseen,
          keyword: query?.keyword,
          bodyText: query?.body_text,
        },
        limit: resultsLimit,
      })
    );
    await auditEvent({
      userId: auth.userId,
      actorType: "api_key",
      actorId: auth.apiKeyId,
      eventType: "email_search",
      event: { sessionId, mailbox, matches: matches.length },
    });
    return c.json({
      mailbox,
      results_limit: resultsLimit,
      total: matches.length,
      matches,
    });
  } catch (err) {
    return mapImapError(c, err);
  }
});

// Read a single message by UID.
emailRouter.post("/sessions/:id/read", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const res = await loadAuthorizedSession(c, auth, sessionId);
  if (!res.ok) return res.response;

  const raw = await c.req.json().catch(() => null);
  const parsed = ReadSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const { mailbox, uid } = parsed.data;
  const parts = parsed.data.parts ?? PARTS_DEFAULT;

  try {
    const message = await withImapConnection(res.credential, (client) =>
      readEmail({ client, mailbox, uid, parts })
    );
    await auditEvent({
      userId: auth.userId,
      actorType: "api_key",
      actorId: auth.apiKeyId,
      eventType: "email_read",
      event: { sessionId, mailbox, uid, parts: Object.keys(parts) },
    });
    return c.json(message);
  } catch (err) {
    return mapImapError(c, err);
  }
});
