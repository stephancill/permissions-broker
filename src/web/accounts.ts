import { Hono } from "hono";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { getConnectState, markConnectStateUsed } from "../connect/state";
import {
  CredentialError,
  isEnrolled,
  saveLinkedCredential,
} from "../credentials/store";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { verifyImapConnection } from "../email/client";
import { serializeCredential } from "../email/credential";
import { env } from "../env";
import { exchangeAuthorizationCode } from "../oauth/flow";
import type { OAuthProviderConfig } from "../oauth/provider";
import { getProvider } from "../oauth/registry";
import { getOauthState, markOauthStateUsed } from "../oauth/state";
import { discoverImapSettings } from "../providers/imap/discovery";

type CloudflareAccountMetadata = {
  id: string;
  name?: string;
};

type ImapAccountMetadata = {
  email: string;
  host: string;
  port: number;
  secure: boolean;
};

const NOT_ENROLLED_MESSAGE =
  "Set up a passkey first: send /passkey to the Telegram bot, then reconnect.";

export const accountRouter = new Hono();

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderCloudflareConnectForm(params: { state: string }): string {
  const state = escapeHtml(params.state);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Connect Cloudflare</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 20px; margin: 0 0 12px; }
      p { color: #333; line-height: 1.4; }
      label { display: block; margin: 12px 0 6px; font-weight: 600; }
      input { width: 100%; padding: 10px; font-size: 14px; }
      button { margin-top: 16px; padding: 10px 14px; font-size: 14px; }
      .note { font-size: 13px; color: #444; }
      code { background: #f3f3f3; padding: 2px 4px; }
    </style>
  </head>
  <body>
    <h1>Connect Cloudflare</h1>
    <p>The token is encrypted to your passkey; the broker can only use it after you approve a request with your passkey.</p>
    <p class="note">Create a narrowly scoped token in Cloudflare: <code>My Profile &gt; API Tokens</code>. Wrangler commonly needs account-level Workers, KV, D1, R2, Pages, or Zone permissions depending on the command.</p>
    <form method="post" action="/v1/accounts/connect/cloudflare">
      <input type="hidden" name="state" value="${state}" />
      <label>Cloudflare API token</label>
      <input name="api_token" type="password" autocomplete="off" required />
      <label>Account ID (optional)</label>
      <input name="account_id" type="text" autocomplete="off" />
      <label>Account name (optional)</label>
      <input name="account_name" type="text" autocomplete="off" />
      <button type="submit">Connect</button>
    </form>
  </body>
</html>`;
}

function renderCloudflareConnectResult(params: {
  ok: boolean;
  message: string;
}): string {
  const msg = escapeHtml(params.message);
  const title = params.ok ? "Connected" : "Connection failed";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 20px; margin: 0 0 12px; }
      p { color: #333; line-height: 1.4; }
    </style>
  </head>
  <body>
    <h1>${escapeHtml(title)}</h1>
    <p>${msg}</p>
    <p>You can return to Telegram.</p>
  </body>
</html>`;
}

function renderImapConnectForm(params: { state: string }): string {
  const state = escapeHtml(params.state);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Connect Email (IMAP)</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 20px; margin: 0 0 12px; }
      p { color: #333; line-height: 1.4; }
      label { display: block; margin: 12px 0 6px; font-weight: 600; }
      input { width: 100%; padding: 10px; font-size: 14px; }
      button { margin-top: 16px; padding: 10px 14px; font-size: 14px; }
      .note { font-size: 13px; color: #444; }
      code { background: #f3f3f3; padding: 2px 4px; }
    </style>
  </head>
  <body>
    <h1>Connect Email (read-only IMAP)</h1>
    <p>Your IMAP credentials are encrypted to your passkey. Agents can only read your mail and only after you approve with your passkey — never modify or delete anything.</p>
    <p class="note">Prefer an <b>app-specific password</b> where your provider offers one (e.g. Gmail, iCloud, Outlook). The IMAP server is auto-detected from your email address.</p>
    <form method="post" action="/v1/accounts/connect/imap">
      <input type="hidden" name="state" value="${state}" />
      <label>Email address</label>
      <input name="email" type="email" autocomplete="username" required />
      <label>Password / app password</label>
      <input name="password" type="password" autocomplete="current-password" required />
      <label>IMAP host (optional; auto-detected when empty)</label>
      <input name="host" type="text" autocomplete="off" placeholder="imap.example.com" />
      <label>IMAP port (optional; default 993)</label>
      <input name="port" type="number" autocomplete="off" placeholder="993" />
      <button type="submit">Connect</button>
    </form>
  </body>
</html>`;
}

function renderImapConnectResult(params: {
  ok: boolean;
  message: string;
}): string {
  const msg = escapeHtml(params.message);
  const title = params.ok ? "Connected" : "Connection failed";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 20px; margin: 0 0 12px; }
      p { color: #333; line-height: 1.4; }
    </style>
  </head>
  <body>
    <h1>${escapeHtml(title)}</h1>
    <p>${msg}</p>
    <p>You can return to Telegram.</p>
  </body>
</html>`;
}

async function verifyCloudflareToken(apiToken: string): Promise<string> {
  const res = await fetch(
    "https://api.cloudflare.com/client/v4/user/tokens/verify",
    {
      headers: {
        authorization: `Bearer ${apiToken}`,
        accept: "application/json",
      },
    }
  );
  const body = (await res.json().catch(() => null)) as unknown;
  if (!res.ok) throw new Error("Cloudflare token verification failed");
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Cloudflare token verification returned invalid JSON");
  }

  const o = body as Record<string, unknown>;
  if (o.success !== true)
    throw new Error("Cloudflare token verification failed");
  const result = o.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return "unknown";
  }
  const id = (result as Record<string, unknown>).id;
  return typeof id === "string" && id ? id : "unknown";
}

async function listCloudflareAccounts(
  apiToken: string
): Promise<CloudflareAccountMetadata[]> {
  const res = await fetch("https://api.cloudflare.com/client/v4/accounts", {
    headers: {
      authorization: `Bearer ${apiToken}`,
      accept: "application/json",
    },
  });
  if (!res.ok) return [];
  const body = (await res.json().catch(() => null)) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) return [];
  const result = (body as Record<string, unknown>).result;
  if (!Array.isArray(result)) return [];
  return result
    .map((x) => {
      if (!x || typeof x !== "object" || Array.isArray(x)) return null;
      const account = x as Record<string, unknown>;
      const id = typeof account.id === "string" ? account.id : null;
      const name = typeof account.name === "string" ? account.name : undefined;
      return id ? { id, name } : null;
    })
    .filter((x) => x != null);
}

accountRouter.get("/", requireApiKey, async (c) => {
  const auth = c.get("apiKeyAuth");
  const database = await db();
  const rows = (await database
    .query(
      "SELECT provider, provider_user_id, scopes, status, created_at, revoked_at, metadata_json FROM linked_accounts WHERE user_id = ? ORDER BY created_at DESC;"
    )
    .all(auth.userId)) as {
    provider: string;
    provider_user_id: string;
    scopes: string;
    status: string;
    created_at: string;
    revoked_at: string | null;
    metadata_json: string | null;
  }[];

  // Display metadata is stored in plaintext at connect time; credentials are
  // never decrypted to list accounts.
  const accounts = rows.map(({ metadata_json, ...r }) => {
    if (!metadata_json || r.status !== "active") return r;
    try {
      const metadata = JSON.parse(metadata_json) as {
        cloudflare_accounts?: CloudflareAccountMetadata[];
        imap?: ImapAccountMetadata;
      };
      return { ...r, metadata };
    } catch {
      return r;
    }
  });

  return c.json({ accounts });
});

accountRouter.get("/callback/:provider", async (c) => {
  const providerId = c.req.param("provider");
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  let provider: OAuthProviderConfig;
  try {
    provider = getProvider(providerId);
  } catch {
    return c.text("unknown provider", 404);
  }

  if (!env.APP_BASE_URL) return c.text("APP_BASE_URL not configured", 500);
  const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/${providerId}`;

  const { userId, pkceVerifier } = await getOauthState({
    state,
    provider: providerId,
  });
  if (!pkceVerifier) return c.text("missing pkce verifier", 400);

  let tokenResult: Awaited<ReturnType<typeof exchangeAuthorizationCode>>;
  try {
    tokenResult = await exchangeAuthorizationCode({
      provider,
      redirectUri,
      currentUrl: new URL(c.req.url),
      expectedState: state,
      codeVerifier: pkceVerifier,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.text(`oauth exchange failed: ${msg}`, 400);
  }

  await markOauthStateUsed(state);

  const refreshToken = tokenResult.refresh_token;
  const accessToken = tokenResult.access_token;
  const scope = tokenResult.scope;

  const scopes = scope ?? provider.scopes.join(" ");

  const database = await db();
  const existing = (await database
    .query(
      "SELECT id FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(userId, providerId)) as { id: string } | null;

  const tokenToStore = refreshToken ?? accessToken;
  if (!tokenToStore && !existing) {
    return c.text(
      "No token returned. Try removing app access in your provider account and reconnect.",
      400
    );
  }

  if (tokenToStore) {
    try {
      await saveLinkedCredential({
        userId,
        provider: providerId,
        providerUserId: "unknown",
        scopes,
        plaintext: tokenToStore,
      });
    } catch (err) {
      if (err instanceof CredentialError && err.code === "NOT_ENROLLED") {
        return c.text(NOT_ENROLLED_MESSAGE, 409);
      }
      throw err;
    }
  } else if (existing) {
    await database
      .query(
        "UPDATE linked_accounts SET scopes = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
      )
      .run(scopes, existing.id);
  }

  await auditEvent({
    userId,
    actorType: "system",
    actorId: "oauth_callback",
    eventType: "linked_account_updated",
    event: { provider: providerId, scopes },
  });

  const telegram = (await database
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(userId)) as { telegram_user_id: number } | null;

  if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const { createBot } = await import("../telegram/bot");
    const bot = createBot();
    await bot.api
      .sendMessage(
        telegram.telegram_user_id,
        `Connected ${providerId}. Scopes: ${scopes}`
      )
      .catch(() => {});
  }

  return c.text("Connected. You can return to Telegram.");
});

// Cloudflare API token connect (broker-hosted form; non-OAuth)
accountRouter.get("/connect/cloudflare", async (c) => {
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  try {
    const { userId } = await getConnectState({ state, provider: "cloudflare" });
    if (!(await isEnrolled(userId))) {
      return c.html(
        renderCloudflareConnectResult({
          ok: false,
          message: NOT_ENROLLED_MESSAGE,
        }),
        409
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(
      renderCloudflareConnectResult({ ok: false, message: msg }),
      400
    );
  }

  return c.html(renderCloudflareConnectForm({ state }));
});

accountRouter.post("/connect/cloudflare", async (c) => {
  const body = await c.req.parseBody();
  const stateRaw = body.state;
  const apiTokenRaw = body.api_token;
  const accountIdRaw = body.account_id;
  const accountNameRaw = body.account_name;

  const state = typeof stateRaw === "string" ? stateRaw.trim() : "";
  const apiToken = typeof apiTokenRaw === "string" ? apiTokenRaw.trim() : "";
  const accountId = typeof accountIdRaw === "string" ? accountIdRaw.trim() : "";
  const accountName =
    typeof accountNameRaw === "string" ? accountNameRaw.trim() : "";

  if (!state || !apiToken) {
    return c.html(
      renderCloudflareConnectResult({ ok: false, message: "missing fields" }),
      400
    );
  }

  let userId: string;
  try {
    ({ userId } = await getConnectState({ state, provider: "cloudflare" }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(
      renderCloudflareConnectResult({ ok: false, message: msg }),
      400
    );
  }

  try {
    const tokenId = await verifyCloudflareToken(apiToken);
    const discoveredAccounts = await listCloudflareAccounts(apiToken);
    const accountsById = new Map<string, CloudflareAccountMetadata>();
    for (const account of discoveredAccounts)
      accountsById.set(account.id, account);
    if (accountId) {
      accountsById.set(accountId, {
        id: accountId,
        name: accountName || accountsById.get(accountId)?.name,
      });
    }
    const accounts = [...accountsById.values()];

    const providerUserId =
      tokenId === "unknown" ? await sha256Hex(apiToken) : tokenId;
    const scopes = accounts.length
      ? `api_token accounts=${accounts.map((x) => x.id).join(",")}`
      : "api_token";

    await saveLinkedCredential({
      userId,
      provider: "cloudflare",
      providerUserId,
      scopes,
      plaintext: JSON.stringify({ apiToken, accounts }),
    });

    const database = await db();
    await markConnectStateUsed(state);

    await auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_cloudflare",
      eventType: "linked_account_updated",
      event: { provider: "cloudflare", scopes },
    });

    const telegram = (await database
      .query("SELECT telegram_user_id FROM users WHERE id = ?;")
      .get(userId)) as { telegram_user_id: number } | null;
    if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
      const { createBot } = await import("../telegram/bot");
      const bot = createBot();
      await bot.api
        .sendMessage(telegram.telegram_user_id, "Connected cloudflare.")
        .catch(() => {});
    }

    return c.html(
      renderCloudflareConnectResult({
        ok: true,
        message: "Cloudflare connected.",
      })
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(
      renderCloudflareConnectResult({ ok: false, message: msg }),
      400
    );
  }
});

// IMAP email connect (broker-hosted form; non-OAuth, read-only)
accountRouter.get("/connect/imap", async (c) => {
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  try {
    const { userId } = await getConnectState({ state, provider: "imap" });
    if (!(await isEnrolled(userId))) {
      return c.html(
        renderImapConnectResult({ ok: false, message: NOT_ENROLLED_MESSAGE }),
        409
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderImapConnectResult({ ok: false, message: msg }), 400);
  }

  return c.html(renderImapConnectForm({ state }));
});

accountRouter.post("/connect/imap", async (c) => {
  const body = await c.req.parseBody();
  const stateRaw = body.state;
  const emailRaw = body.email;
  const passwordRaw = body.password;
  const hostRaw = body.host;
  const portRaw = body.port;

  const state = typeof stateRaw === "string" ? stateRaw.trim() : "";
  const email =
    typeof emailRaw === "string" ? emailRaw.trim().toLowerCase() : "";
  const password = typeof passwordRaw === "string" ? passwordRaw : "";
  const host = typeof hostRaw === "string" ? hostRaw.trim() : "";
  const portInput = typeof portRaw === "string" ? portRaw.trim() : "";

  if (!state || !email || !password) {
    return c.html(
      renderImapConnectResult({ ok: false, message: "missing fields" }),
      400
    );
  }
  if (!email.includes("@")) {
    return c.html(
      renderImapConnectResult({ ok: false, message: "invalid email address" }),
      400
    );
  }

  let userId: string;
  try {
    ({ userId } = await getConnectState({ state, provider: "imap" }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderImapConnectResult({ ok: false, message: msg }), 400);
  }

  try {
    let endpoint: { host: string; port: number; secure: boolean };
    if (host) {
      const port = portInput ? Number(portInput) : 993;
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return c.html(
          renderImapConnectResult({ ok: false, message: "invalid port" }),
          400
        );
      }
      const secure = port !== 143;
      // Verify the manual override before storing anything.
      await verifyImapConnection({ host, port, secure, email, password });
      endpoint = { host, port, secure };
    } else {
      endpoint = await discoverImapSettings({ email, password });
    }

    await saveLinkedCredential({
      userId,
      provider: "imap",
      providerUserId: await sha256Hex(email),
      scopes: "read",
      plaintext: serializeCredential({
        email,
        password,
        host: endpoint.host,
        port: endpoint.port,
        secure: endpoint.secure,
      }),
    });

    const database = await db();
    await markConnectStateUsed(state);

    await auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_imap",
      eventType: "linked_account_updated",
      event: { provider: "imap", scopes: "read" },
    });

    const telegram = (await database
      .query("SELECT telegram_user_id FROM users WHERE id = ?;")
      .get(userId)) as { telegram_user_id: number } | null;
    if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
      const { createBot } = await import("../telegram/bot");
      const bot = createBot();
      await bot.api
        .sendMessage(
          telegram.telegram_user_id,
          `Connected imap (${endpoint.host}).`
        )
        .catch(() => {});
    }

    return c.html(
      renderImapConnectResult({
        ok: true,
        message: `Email connected (${endpoint.host}). Return to Telegram.`,
      })
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderImapConnectResult({ ok: false, message: msg }), 400);
  }
});
