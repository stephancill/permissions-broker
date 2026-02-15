import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { decryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { env } from "../env";
import {
  extractSymrefHeadFromInfoRefs,
  isAllZeroSha,
  parseReceivePackCommands,
} from "../git/pktline";
import {
  createGitSession,
  getGitSessionKeyScoped,
  getGitSessionSecretCiphertextKeyScoped,
  markGitSessionUsed,
  storeDefaultBranchRef,
  touchGitSessionActivity,
  validateGitSessionSecret,
} from "../git/sessions";
import {
  readPrefixUntilFlush,
  streamFromPrefixAndReader,
  withByteLimit,
} from "../git/stream";
import { telegramApi } from "../telegram/api";

const CreateSessionSchema = z.object({
  operation: z.enum(["clone", "fetch", "pull", "push"]),
  repo: z.string().min(3),
  consent_hint: z.string().optional(),
});

function isReadOperation(op: string): boolean {
  return op === "clone" || op === "fetch" || op === "pull";
}

function nowIso(): string {
  return new Date().toISOString();
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function parseRepo(repo: string): { owner: string; name: string } {
  const trimmed = repo.trim();
  const parts = trimmed.split("/");
  if (parts.length !== 2) throw new Error("invalid repo format");
  const [owner, name] = parts;
  if (!owner || !name) throw new Error("invalid repo format");
  return { owner, name };
}

function baseUrl(): string {
  if (!env.APP_BASE_URL) throw new Error("APP_BASE_URL not configured");
  return env.APP_BASE_URL.replace(/\/$/, "");
}

function basicAuthHeader(token: string): string {
  const raw = `x-access-token:${token}`;
  const b64 = Buffer.from(raw, "utf8").toString("base64");
  return `Basic ${b64}`;
}

function upstreamGitHubUrl(params: {
  owner: string;
  repo: string;
  path: string;
  query: string;
}): string {
  const repo = params.repo.endsWith(".git")
    ? params.repo
    : `${params.repo}.git`;
  const url = new URL(
    `https://github.com/${params.owner}/${repo}${params.path}`
  );
  url.search = params.query;
  return url.toString();
}

function isAllowedGitPath(path: string): boolean {
  return (
    path === "/info/refs" ||
    path === "/git-upload-pack" ||
    path === "/git-receive-pack"
  );
}

async function readBodyBytes(params: {
  body: ReadableStream<Uint8Array> | null;
  maxBytes: number;
}): Promise<Uint8Array | null> {
  if (!params.body) return null;
  const limited = withByteLimit(params.body, params.maxBytes);
  const ab = await new Response(limited).arrayBuffer();
  return new Uint8Array(ab);
}

function methodAllowed(path: string, method: string): boolean {
  if (path === "/info/refs") return method === "GET";
  if (path === "/git-upload-pack") return method === "POST";
  if (path === "/git-receive-pack") return method === "POST";
  return false;
}

function serviceFromQuery(query: string): string | null {
  const u = new URL(
    `https://x.invalid${query.startsWith("?") ? query : `?${query}`}`
  );
  return u.searchParams.get("service");
}

async function getGitHubToken(userId: string): Promise<string | null> {
  const row = db()
    .query(
      "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'github' AND status = 'active' LIMIT 1;"
    )
    .get(userId) as { refresh_token_ciphertext: Uint8Array } | null;
  if (!row) return null;
  return decryptUtf8(row.refresh_token_ciphertext);
}

export const gitRouter = new Hono();

// Agent/app endpoints
gitRouter.post("/sessions", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const raw = await c.req.json().catch(() => null);
  const parsed = CreateSessionSchema.safeParse(raw);
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  // GitHub token is required for push. For clone of public repos,
  // allow unauthenticated proxying.
  const connected = db()
    .query(
      "SELECT 1 AS ok FROM linked_accounts WHERE user_id = ? AND provider = 'github' AND status = 'active' LIMIT 1;"
    )
    .get(auth.userId) as { ok: number } | null;
  if (!connected && parsed.data.operation === "push") {
    return c.json({ error: "no_linked_github" }, 409);
  }

  let owner: string;
  let name: string;
  try {
    ({ owner, name } = parseRepo(parsed.data.repo));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_repo", message: msg }, 400);
  }

  const created = await createGitSession({
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
    operation: parsed.data.operation,
    repoOwner: owner,
    repoName: name,
    approvalTtlMs: 2 * 60_000,
  });

  auditEvent({
    userId: auth.userId,
    actorType: "api_key",
    actorId: auth.apiKeyId,
    eventType: "git_session_created",
    event: {
      operation: parsed.data.operation,
      repo: `${owner}/${name}`,
    },
  });

  // Telegram prompt
  const u = db()
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(auth.userId) as { telegram_user_id: number } | null;

  if (u?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const consentHint = parsed.data.consent_hint;
    const lines: string[] = [];
    lines.push("<b>Git session request</b>");
    lines.push("");
    lines.push(`<b>API key</b>: <code>${escapeHtml(auth.apiKeyLabel)}</code>`);
    lines.push(`<b>Provider</b>: <code>github</code>`);
    lines.push(`<b>Repo</b>: <code>${escapeHtml(`${owner}/${name}`)}</code>`);

    if (isReadOperation(parsed.data.operation)) {
      const op = parsed.data.operation.toUpperCase();
      lines.push(`<b>Operation</b>: <code>${escapeHtml(op)}</code> (read)`);
      if (!connected) {
        lines.push(
          "<i>Note:</i> no GitHub account linked; this will only work for public repos."
        );
      }
    } else {
      lines.push("<b>Operation</b>: <code>PUSH</code> (write)");
      lines.push(
        "<i>Safety:</i> <code>Allow</code> blocks pushing to the repo default branch. Use <code>Allow (main)</code> to allow it."
      );
    }

    if (consentHint) {
      lines.push("");
      lines.push(
        `<b>Requester note</b>: ${escapeHtml(truncate(consentHint, 300))}`
      );
      lines.push("");
    }

    lines.push("Approve to allow the agent to use this git session.");

    const kb =
      parsed.data.operation === "push"
        ? {
            inline_keyboard: [
              [
                {
                  text: "Allow",
                  callback_data: `gs:approve_push_block:${created.sessionId}`,
                },
                {
                  text: "Allow (main)",
                  callback_data: `gs:approve_push_allow:${created.sessionId}`,
                },
              ],
              [{ text: "Deny", callback_data: `gs:deny:${created.sessionId}` }],
            ],
          }
        : {
            inline_keyboard: [
              [
                {
                  text: `Approve ${parsed.data.operation}`,
                  callback_data: `gs:approve_clone:${created.sessionId}`,
                },
                { text: "Deny", callback_data: `gs:deny:${created.sessionId}` },
              ],
            ],
          };

    telegramApi()
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
  });
});

gitRouter.get("/sessions/:id", requireApiKey, (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const row = getGitSessionKeyScoped({
    sessionId,
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
  });
  if (!row) return c.json({ error: "forbidden" }, 403);

  if (
    row.status === "PENDING_APPROVAL" ||
    row.status === "APPROVED" ||
    row.status === "ACTIVE"
  ) {
    const exp = Date.parse(row.approval_expires_at);
    if (
      Number.isFinite(exp) &&
      Date.now() > exp &&
      row.status === "PENDING_APPROVAL"
    ) {
      return c.json({ session_id: row.id, status: "EXPIRED" }, 200);
    }
  }

  return c.json({
    session_id: row.id,
    status: row.status,
    operation: row.operation,
    repo: `${row.repo_owner}/${row.repo_name}`,
    approval_expires_at: row.approval_expires_at,
    default_branch_ref: row.default_branch_ref,
    allow_default_branch_push: Boolean(row.allow_default_branch_push),
  });
});

gitRouter.get("/sessions/:id/remote", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const sessionId = c.req.param("id");
  const row = getGitSessionKeyScoped({
    sessionId,
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
  });
  if (!row) return c.json({ error: "forbidden" }, 403);

  if (row.status !== "APPROVED" && row.status !== "ACTIVE") {
    if (row.status === "PENDING_APPROVAL")
      return c.json({ status: row.status }, 202);
    if (row.status === "DENIED") return c.json({ error: "denied" }, 403);
    if (row.status === "EXPIRED") return c.json({ error: "expired" }, 408);
    if (row.status === "USED") return c.json({ error: "used" }, 410);
  }

  if (!env.APP_SECRET) return c.json({ error: "server_misconfigured" }, 500);

  const ct = getGitSessionSecretCiphertextKeyScoped({
    sessionId,
    userId: auth.userId,
    apiKeyId: auth.apiKeyId,
  });
  if (!ct) return c.json({ error: "forbidden" }, 403);
  const secret = await decryptUtf8(ct);
  const remoteUrl = `${baseUrl()}/v1/git/session/${row.id}/${secret}/github/${row.repo_owner}/${row.repo_name}.git`;
  return c.json({ remote_url: remoteUrl });
});

// Git CLI proxy endpoints
gitRouter.all("/session/:id/:secret/github/:owner/:repo/*", async (c) => {
  const sessionId = c.req.param("id");
  const secret = c.req.param("secret");
  const owner = c.req.param("owner");
  const repoRaw = c.req.param("repo");
  const repo = repoRaw.endsWith(".git") ? repoRaw.slice(0, -4) : repoRaw;

  // Derive the sub-path (e.g. /info/refs) from the full pathname.
  // This is more robust than relying on Hono's splat param behavior.
  const pathname = new URL(c.req.url).pathname;
  const prefix = `/v1/git/session/${sessionId}/${secret}/github/${owner}/${repoRaw}`;
  let rest = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : "";
  if (!rest) {
    const restParam = (c.req.param("*") ?? "").toString();
    const restPath = (restParam.split("?", 1)[0] ?? "").trim();
    rest = restPath
      ? restPath.startsWith("/")
        ? restPath
        : `/${restPath}`
      : "";
  }

  const sess = await validateGitSessionSecret({ sessionId, secret });
  if (!sess) return c.text("forbidden", 403);
  if (sess.provider !== "github") return c.text("forbidden", 403);
  if (sess.repo_owner !== owner || sess.repo_name !== repo)
    return c.text("forbidden", 403);

  const path = rest;
  if (!isAllowedGitPath(path)) return c.text("not found", 404);
  if (!methodAllowed(path, c.req.method))
    return c.text("method not allowed", 405);

  // Enforce session state.
  if (sess.status === "DENIED") return c.text("denied", 403);
  if (sess.status === "EXPIRED") return c.text("expired", 408);
  if (sess.status === "USED") return c.text("used", 410);
  if (sess.status !== "APPROVED" && sess.status !== "ACTIVE") {
    return c.text("not ready", 409);
  }

  if (sess.status === "APPROVED") {
    db()
      .query(
        "UPDATE git_sessions SET status = 'ACTIVE', updated_at = ? WHERE id = ? AND status = 'APPROVED';"
      )
      .run(nowIso(), sess.id);
  }

  // Enforce operation/service pairing
  const service =
    path === "/info/refs"
      ? serviceFromQuery(c.req.url.split("?", 2)[1] ?? "")
      : null;
  if (path === "/info/refs") {
    if (!service) return c.text("missing service", 400);
    if (isReadOperation(sess.operation) && service !== "git-upload-pack") {
      return c.text("forbidden", 403);
    }
    if (sess.operation === "push" && service !== "git-receive-pack") {
      return c.text("forbidden", 403);
    }
  }

  if (isReadOperation(sess.operation) && path === "/git-receive-pack")
    return c.text("forbidden", 403);
  if (sess.operation === "push" && path === "/git-upload-pack")
    return c.text("forbidden", 403);

  touchGitSessionActivity(sess.id);

  // For push, enforce one-time use by flipping to USED on the first
  // receive-pack request.
  // For clone/fetch, Git protocol v2 may issue multiple upload-pack POSTs
  // (ls-refs, then fetch), so we can't mark USED on upload-pack.
  if (path === "/git-receive-pack") {
    markGitSessionUsed(sess.id);
  }

  const token = await getGitHubToken(sess.user_id);
  if (!token && sess.operation === "push") {
    return c.text("no github token", 409);
  }

  const upstream = upstreamGitHubUrl({
    owner,
    repo,
    path,
    query: new URL(c.req.url).search,
  });

  const headers = new Headers();
  if (token) {
    headers.set("authorization", basicAuthHeader(token));
  }
  const ct = c.req.header("content-type");
  if (ct) headers.set("content-type", ct);
  const accept = c.req.header("accept");
  if (accept) headers.set("accept", accept);
  const ua = c.req.header("user-agent");
  if (ua) headers.set("user-agent", ua);
  const gitProto = c.req.header("git-protocol");
  if (gitProto) headers.set("git-protocol", gitProto);

  // Push protections: inspect receive-pack command section (prefix) before forwarding.
  let body: ReadableStream<Uint8Array> | null = null;
  if (path === "/git-receive-pack") {
    if (!c.req.raw.body) return c.text("missing body", 400);
    const prefixRead = await readPrefixUntilFlush({
      body: c.req.raw.body as unknown as ReadableStream<Uint8Array>,
      maxPrefixBytes: 256 * 1024,
    });
    const prefixBytes = prefixRead.prefixChunks.reduce(
      (n, ch) => n + ch.byteLength,
      0
    );
    const prefix = new Uint8Array(prefixBytes);
    let off = 0;
    for (const ch of prefixRead.prefixChunks) {
      prefix.set(ch, off);
      off += ch.byteLength;
    }

    const cmds = parseReceivePackCommands(prefix);
    for (const cmd of cmds) {
      if (isAllZeroSha(cmd.newSha)) {
        return c.text("ref deletion is not allowed", 403);
      }
      if (cmd.ref.startsWith("refs/tags/")) {
        return c.text("tag updates are not allowed", 403);
      }
      if (
        sess.default_branch_ref &&
        cmd.ref === sess.default_branch_ref &&
        !sess.allow_default_branch_push
      ) {
        return c.text(
          "default branch push is not allowed for this session",
          403
        );
      }
    }

    body = streamFromPrefixAndReader({
      prefixChunks: prefixRead.prefixChunks,
      reader: prefixRead.reader,
    });
  } else if (path === "/git-upload-pack") {
    body = c.req.raw.body
      ? (c.req.raw.body as unknown as ReadableStream<Uint8Array>)
      : null;
  }

  // GitHub's smart HTTP endpoints are sensitive to transfer encoding.
  // Buffer request bodies up to a hard cap and forward with Content-Length.
  // This keeps implementation simple and avoids chunked upload surprises.
  const bodyBytes = await readBodyBytes({
    body,
    maxBytes: 50 * 1024 * 1024,
  });
  if (bodyBytes) headers.set("content-length", String(bodyBytes.byteLength));

  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 10 * 60_000);
  let res: Response;
  try {
    res = await fetch(upstream, {
      method: c.req.method,
      headers,
      body: bodyBytes as unknown as RequestInit["body"],
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timeout);
  }

  if (path === "/info/refs" && sess.operation === "push") {
    // Attempt to store default branch ref for later enforcement.
    try {
      const buf = new Uint8Array(await res.clone().arrayBuffer());
      const headRef = extractSymrefHeadFromInfoRefs(buf.slice(0, 64 * 1024));
      if (headRef) storeDefaultBranchRef({ sessionId: sess.id, ref: headRef });
    } catch {
      // ignore
    }
  }

  const outHeaders = new Headers();
  const outCt = res.headers.get("content-type");
  if (outCt) outHeaders.set("content-type", outCt);
  const cacheControl = res.headers.get("cache-control");
  if (cacheControl) outHeaders.set("cache-control", cacheControl);

  const responseBody = withByteLimit(
    res.body,
    200 * 1024 * 1024
  ) as unknown as ConstructorParameters<typeof Response>[0];
  return new Response(responseBody, {
    status: res.status,
    headers: outHeaders,
  });
});
