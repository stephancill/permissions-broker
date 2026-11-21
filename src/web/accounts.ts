import { type Context, Hono } from "hono";

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
import {
  fetchCloudflareAccounts,
  serializeCloudflareOAuthCredential,
} from "../providers/cloudflare/proxy";
import { discoverImapSettings } from "../providers/imap/discovery";
import { registerAppleReleaseConnect } from "./appleReleaseConnect";
import { escapeHtml, sendPage } from "./pages";

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
  "Set up a passkey first (sign in to the stupid vault app), then reconnect.";

export const accountRouter = new Hono();
registerAppleReleaseConnect(accountRouter);

// Connect pages use the PWA shell (theme incl. dark mode, nonce CSP). They
// open outside the app's navigation (OAuth sheet or form), so no nav bar.
function connectResultPage(
  c: Context,
  params: { ok: boolean; message: string; status?: number }
): Response {
  const title = params.ok ? "Connected" : "Connection failed";
  return sendPage(c, {
    title,
    nav: null,
    status: params.status ?? (params.ok ? 200 : 400),
    body: `<h1>${escapeHtml(title)}</h1>
    <p${params.ok ? "" : ' class="error"'}>${escapeHtml(params.message)}</p>
    <p>You can close this page and return to the stupid vault app.</p>
    <p><a href="/app/accounts">Back to accounts</a></p>`,
  });
}

function imapConnectFormPage(c: Context, state: string): Response {
  return sendPage(c, {
    title: "Connect email",
    nav: null,
    body: `<h1>Connect email (read-only IMAP)</h1>
    <p>Your IMAP credentials are encrypted to your passkey. Agents can only read your mail and only after you approve with your passkey — never modify or delete anything.</p>
    <p class="note">Prefer an <b>app-specific password</b> where your provider offers one (e.g. Gmail, iCloud, Outlook). The IMAP server is auto-detected from your email address.</p>
    <form method="post" action="/v1/accounts/connect/imap">
      <input type="hidden" name="state" value="${escapeHtml(state)}" />
      <label>Email address <input name="email" type="email" autocomplete="username" required /></label>
      <label>Password / app password <input name="password" type="password" autocomplete="current-password" required /></label>
      <label>IMAP host (optional; auto-detected when empty) <input name="host" type="text" autocomplete="off" placeholder="imap.example.com" /></label>
      <label>IMAP port (optional; default 993) <input name="port" type="number" autocomplete="off" placeholder="993" /></label>
      <button type="submit">Connect</button>
    </form>`,
  });
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
  if (!state) {
    return connectResultPage(c, { ok: false, message: "Missing state." });
  }

  let provider: OAuthProviderConfig;
  try {
    provider = getProvider(providerId);
  } catch {
    return connectResultPage(c, {
      ok: false,
      message: "Unknown provider.",
      status: 404,
    });
  }

  if (!env.APP_BASE_URL) return c.text("APP_BASE_URL not configured", 500);
  const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/${providerId}`;

  const { userId, pkceVerifier } = await getOauthState({
    state,
    provider: providerId,
  });
  if (!pkceVerifier) {
    return connectResultPage(c, {
      ok: false,
      message: "Missing PKCE verifier.",
    });
  }

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
    return connectResultPage(c, {
      ok: false,
      message: `OAuth exchange failed: ${msg}`,
    });
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

  // Cloudflare stores { refreshToken, accounts } so account names can be
  // shown without decrypting; access tokens are short-lived, so a refresh
  // token (offline_access) is required.
  let plaintext = tokenToStore;
  if (providerId === "cloudflare") {
    if (!refreshToken) {
      return connectResultPage(c, {
        ok: false,
        message:
          "Cloudflare did not return a refresh token. Remove the app under Manage OAuth authorizations in Cloudflare and connect again.",
      });
    }
    plaintext = serializeCloudflareOAuthCredential({
      refreshToken,
      accounts: accessToken ? await fetchCloudflareAccounts(accessToken) : [],
    });
  }
  if (!tokenToStore && !existing) {
    return connectResultPage(c, {
      ok: false,
      message:
        "No token returned. Try removing app access in your provider account and reconnect.",
    });
  }

  if (plaintext) {
    try {
      await saveLinkedCredential({
        userId,
        provider: providerId,
        providerUserId: "unknown",
        scopes,
        plaintext,
      });
    } catch (err) {
      if (err instanceof CredentialError && err.code === "NOT_ENROLLED") {
        return connectResultPage(c, {
          ok: false,
          message: NOT_ENROLLED_MESSAGE,
          status: 409,
        });
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

  return connectResultPage(c, {
    ok: true,
    message: `Connected ${providerId}.`,
  });
});

// IMAP email connect (broker-hosted form; non-OAuth, read-only)
accountRouter.get("/connect/imap", async (c) => {
  const state = c.req.query("state");
  if (!state) {
    return connectResultPage(c, { ok: false, message: "Missing state." });
  }

  try {
    const { userId } = await getConnectState({ state, provider: "imap" });
    if (!(await isEnrolled(userId))) {
      return connectResultPage(c, {
        ok: false,
        message: NOT_ENROLLED_MESSAGE,
        status: 409,
      });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return connectResultPage(c, { ok: false, message: msg, status: 400 });
  }

  return imapConnectFormPage(c, state);
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
    return connectResultPage(c, {
      ok: false,
      message: "missing fields",
      status: 400,
    });
  }
  if (!email.includes("@")) {
    return connectResultPage(c, {
      ok: false,
      message: "invalid email address",
      status: 400,
    });
  }

  let userId: string;
  try {
    ({ userId } = await getConnectState({ state, provider: "imap" }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return connectResultPage(c, { ok: false, message: msg, status: 400 });
  }

  try {
    let endpoint: { host: string; port: number; secure: boolean };
    if (host) {
      const port = portInput ? Number(portInput) : 993;
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return connectResultPage(c, {
          ok: false,
          message: "invalid port",
          status: 400,
        });
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

    await markConnectStateUsed(state);

    await auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_imap",
      eventType: "linked_account_updated",
      event: { provider: "imap", scopes: "read" },
    });

    return connectResultPage(c, {
      ok: true,
      message: `Email connected (${endpoint.host}).`,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return connectResultPage(c, { ok: false, message: msg, status: 400 });
  }
});
