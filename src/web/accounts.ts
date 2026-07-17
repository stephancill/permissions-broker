import { Hono } from "hono";
import { ulid } from "ulid";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { getConnectState, markConnectStateUsed } from "../connect/state";
import { decryptUtf8, encryptUtf8 } from "../crypto/aesgcm";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { env } from "../env";
import { exchangeAuthorizationCode } from "../oauth/flow";
import type { OAuthProviderConfig } from "../oauth/provider";
import { getProvider } from "../oauth/registry";
import { getOauthState, markOauthStateUsed } from "../oauth/state";
import { discoverIcloudCaldavBounds } from "../providers/icloud/discovery";

type CloudflareAccountMetadata = {
  id: string;
  name?: string;
};

function nowIso(): string {
  return new Date().toISOString();
}

export const accountRouter = new Hono();

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderIcloudConnectForm(params: { state: string }): string {
  const state = escapeHtml(params.state);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Connect iCloud</title>
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
    <h1>Connect iCloud (CalDAV)</h1>
    <p>This will store an app-specific password encrypted at rest and use it only after Telegram approvals.</p>
    <p class="note">Create an app-specific password at <code>appleid.apple.com</code> (Apple ID &gt; Sign-In and Security).</p>
    <form method="post" action="/v1/accounts/connect/icloud">
      <input type="hidden" name="state" value="${state}" />
      <label>Apple ID email</label>
      <input name="username" type="email" autocomplete="username" required />
      <label>App-specific password</label>
      <input name="app_password" type="password" autocomplete="current-password" required />
      <button type="submit">Connect</button>
    </form>
  </body>
</html>`;
}

function renderIcloudConnectResult(params: {
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
    <p>This will store a Cloudflare API token encrypted at rest and use it only after Telegram approvals.</p>
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

function parseCloudflareAccounts(
  storedCredential: string
): CloudflareAccountMetadata[] {
  const parsed = JSON.parse(storedCredential) as { accounts?: unknown };
  if (!Array.isArray(parsed.accounts)) return [];
  return parsed.accounts
    .map((x) => {
      if (!x || typeof x !== "object" || Array.isArray(x)) return null;
      const account = x as Record<string, unknown>;
      const id = typeof account.id === "string" ? account.id : null;
      const name = typeof account.name === "string" ? account.name : undefined;
      return id ? { id, name } : null;
    })
    .filter((x) => x != null);
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
  const rows = db()
    .query(
      "SELECT provider, provider_user_id, scopes, status, created_at, revoked_at FROM linked_accounts WHERE user_id = ? ORDER BY created_at DESC;"
    )
    .all(auth.userId) as {
    provider: string;
    provider_user_id: string;
    scopes: string;
    status: string;
    created_at: string;
    revoked_at: string | null;
  }[];

  const accounts: Array<
    (typeof rows)[number] & {
      metadata?: {
        caldav_hosts?: string[];
        caldav_path_prefixes?: string[];
        cloudflare_accounts?: CloudflareAccountMetadata[];
      };
    }
  > = [];

  for (const r of rows) {
    if (r.provider !== "icloud" && r.provider !== "cloudflare") {
      accounts.push(r);
      continue;
    }

    if (r.provider === "cloudflare") {
      try {
        if (!env.APP_SECRET) {
          accounts.push(r);
          continue;
        }

        const row = db()
          .query(
            "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'cloudflare' AND provider_user_id = ? AND status = 'active' LIMIT 1;"
          )
          .get(auth.userId, r.provider_user_id) as {
          refresh_token_ciphertext: Uint8Array;
        } | null;
        if (!row) {
          accounts.push(r);
          continue;
        }

        const s = await decryptUtf8(row.refresh_token_ciphertext);
        accounts.push({
          ...r,
          metadata: { cloudflare_accounts: parseCloudflareAccounts(s) },
        });
      } catch {
        accounts.push(r);
      }
      continue;
    }

    // Best-effort: expose non-secret CalDAV bounds so agents can form requests.
    // Do not expose the Apple ID or app-specific password.
    try {
      if (!env.APP_SECRET) {
        accounts.push(r);
        continue;
      }

      const row = db()
        .query(
          "SELECT refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = 'icloud' AND provider_user_id = ? AND status = 'active' LIMIT 1;"
        )
        .get(auth.userId, r.provider_user_id) as {
        refresh_token_ciphertext: Uint8Array;
      } | null;
      if (!row) {
        accounts.push(r);
        continue;
      }

      const s = await decryptUtf8(row.refresh_token_ciphertext);
      const j = JSON.parse(s) as {
        allowedHosts?: unknown;
        allowedPathPrefixes?: unknown;
      };
      const allowedHosts = Array.isArray(j.allowedHosts)
        ? (j.allowedHosts.filter((x) => typeof x === "string") as string[])
        : undefined;
      const allowedPathPrefixes = Array.isArray(j.allowedPathPrefixes)
        ? (j.allowedPathPrefixes.filter(
            (x) => typeof x === "string"
          ) as string[])
        : undefined;

      accounts.push({
        ...r,
        metadata: {
          caldav_hosts: allowedHosts,
          caldav_path_prefixes: allowedPathPrefixes,
        },
      });
    } catch {
      accounts.push(r);
    }
  }

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
  if (!env.APP_SECRET) return c.text("APP_SECRET not configured", 500);
  const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/${providerId}`;

  const { userId, pkceVerifier } = getOauthState({
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

  markOauthStateUsed(state);

  const refreshToken = tokenResult.refresh_token;
  const accessToken = tokenResult.access_token;
  const scope = tokenResult.scope;

  const scopes = scope ?? provider.scopes.join(" ");

  const existing = db()
    .query(
      "SELECT id, refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(userId, providerId) as {
    id: string;
    refresh_token_ciphertext: Uint8Array;
  } | null;

  const tokenToStore = refreshToken ?? accessToken;
  if (!tokenToStore && !existing) {
    return c.text(
      "No token returned. Try removing app access in your provider account and reconnect.",
      400
    );
  }

  const providerUserId = "unknown";
  const now = nowIso();

  if (existing) {
    if (tokenToStore) {
      const ct = await encryptUtf8(tokenToStore);
      db()
        .query(
          "UPDATE linked_accounts SET scopes = ?, refresh_token_ciphertext = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(scopes, ct, existing.id);
    } else {
      db()
        .query(
          "UPDATE linked_accounts SET scopes = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(scopes, existing.id);
    }
  } else {
    const ct = await encryptUtf8(tokenToStore as string);
    db()
      .query(
        "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NULL);"
      )
      .run(ulid(), userId, providerId, providerUserId, scopes, ct, now);
  }

  auditEvent({
    userId,
    actorType: "system",
    actorId: "oauth_callback",
    eventType: "linked_account_updated",
    event: { provider: providerId, scopes },
  });

  const telegram = db()
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(userId) as { telegram_user_id: number } | null;

  if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const { createBot } = await import("../telegram/bot");
    const bot = createBot();
    bot.api
      .sendMessage(
        telegram.telegram_user_id,
        `Connected ${providerId}. Scopes: ${scopes}`
      )
      .catch(() => {});
  }

  return c.text("Connected. You can return to Telegram.");
});

// iCloud CalDAV connect (broker-hosted form; non-OAuth)
accountRouter.get("/connect/icloud", async (c) => {
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  try {
    getConnectState({ state, provider: "icloud" });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderIcloudConnectResult({ ok: false, message: msg }), 400);
  }

  return c.html(renderIcloudConnectForm({ state }));
});

accountRouter.post("/connect/icloud", async (c) => {
  if (!env.APP_SECRET) {
    return c.html(
      renderIcloudConnectResult({
        ok: false,
        message: "APP_SECRET not configured",
      }),
      500
    );
  }

  const body = await c.req.parseBody();
  const stateRaw = body.state;
  const usernameRaw = body.username;
  const appPasswordRaw = body.app_password;

  const state = typeof stateRaw === "string" ? stateRaw.trim() : "";
  const username = typeof usernameRaw === "string" ? usernameRaw.trim() : "";
  const appSpecificPassword =
    typeof appPasswordRaw === "string" ? appPasswordRaw.trim() : "";

  if (!state || !username || !appSpecificPassword) {
    return c.html(
      renderIcloudConnectResult({ ok: false, message: "missing fields" }),
      400
    );
  }

  let userId: string;
  try {
    ({ userId } = getConnectState({ state, provider: "icloud" }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderIcloudConnectResult({ ok: false, message: msg }), 400);
  }

  try {
    const bounds = await discoverIcloudCaldavBounds({
      username,
      appSpecificPassword,
    });

    const providerUserId = await sha256Hex(username.toLowerCase());
    const credentialJson = JSON.stringify({
      username,
      appSpecificPassword,
      allowedHosts: bounds.allowedHosts,
      allowedPathPrefixes: bounds.allowedPathPrefixes,
    });
    const ct = await encryptUtf8(credentialJson);
    const now = nowIso();

    const existing = db()
      .query(
        "SELECT id FROM linked_accounts WHERE user_id = ? AND provider = 'icloud' AND status = 'active' LIMIT 1;"
      )
      .get(userId) as { id: string } | null;

    if (existing) {
      db()
        .query(
          "UPDATE linked_accounts SET provider_user_id = ?, scopes = ?, refresh_token_ciphertext = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(providerUserId, "caldav", ct, existing.id);
    } else {
      db()
        .query(
          "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, 'icloud', ?, ?, ?, 'active', ?, NULL);"
        )
        .run(ulid(), userId, providerUserId, "caldav", ct, now);
    }

    markConnectStateUsed(state);

    auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_icloud",
      eventType: "linked_account_updated",
      event: { provider: "icloud", scopes: "caldav" },
    });

    const telegram = db()
      .query("SELECT telegram_user_id FROM users WHERE id = ?;")
      .get(userId) as { telegram_user_id: number } | null;
    if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
      const { createBot } = await import("../telegram/bot");
      const bot = createBot();
      bot.api
        .sendMessage(telegram.telegram_user_id, "Connected icloud.")
        .catch(() => {});
    }

    return c.html(
      renderIcloudConnectResult({ ok: true, message: "iCloud connected." })
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.html(renderIcloudConnectResult({ ok: false, message: msg }), 400);
  }
});

// Cloudflare API token connect (broker-hosted form; non-OAuth)
accountRouter.get("/connect/cloudflare", async (c) => {
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  try {
    getConnectState({ state, provider: "cloudflare" });
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
  if (!env.APP_SECRET) {
    return c.html(
      renderCloudflareConnectResult({
        ok: false,
        message: "APP_SECRET not configured",
      }),
      500
    );
  }

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
    ({ userId } = getConnectState({ state, provider: "cloudflare" }));
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
    const credentialJson = JSON.stringify({ apiToken, accounts });
    const ct = await encryptUtf8(credentialJson);
    const now = nowIso();
    const scopes = accounts.length
      ? `api_token accounts=${accounts.map((x) => x.id).join(",")}`
      : "api_token";

    const existing = db()
      .query(
        "SELECT id FROM linked_accounts WHERE user_id = ? AND provider = 'cloudflare' AND status = 'active' LIMIT 1;"
      )
      .get(userId) as { id: string } | null;

    if (existing) {
      db()
        .query(
          "UPDATE linked_accounts SET provider_user_id = ?, scopes = ?, refresh_token_ciphertext = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(providerUserId, scopes, ct, existing.id);
    } else {
      db()
        .query(
          "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, 'cloudflare', ?, ?, ?, 'active', ?, NULL);"
        )
        .run(ulid(), userId, providerUserId, scopes, ct, now);
    }

    markConnectStateUsed(state);

    auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_cloudflare",
      eventType: "linked_account_updated",
      event: { provider: "cloudflare", scopes },
    });

    const telegram = db()
      .query("SELECT telegram_user_id FROM users WHERE id = ?;")
      .get(userId) as { telegram_user_id: number } | null;
    if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
      const { createBot } = await import("../telegram/bot");
      const bot = createBot();
      bot.api
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
