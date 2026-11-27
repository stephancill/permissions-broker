import { type Context, Hono } from "hono";

import { authenticateApiKey } from "../auth/apiKey";
import { ApiKeyLabelSchema } from "../auth/apiKeyAdmin";
import { requireSessionPage } from "../auth/session";
import {
  type AuthorizationRequest,
  authorizationResponseUrl,
  authorizationServerMetadata,
  createAuthorizationCode,
  exchangeAuthorizationCode,
  MCP_SCOPE,
  OAuthServerError,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  registerClient,
  suggestLabel,
  validateAuthorizationRequest,
} from "../mcp/oauthServer";
import { callTool, listTools } from "../mcp/tools";
import { expectedOrigin } from "../passkey/webauthn";
import { escapeHtml, sendMessagePage, sendPage } from "./pages";

// MCP connector for Claude, ChatGPT and other MCP clients: a stateless
// Streamable HTTP endpoint (/mcp) plus the OAuth 2.1 authorization server it
// points to. See docs/MCP_CONNECTOR.md.

export const SUPPORTED_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
] as const;
const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

// Browsers must not drive the endpoint from other sites (MCP transport spec,
// DNS rebinding). Hosted connectors call it server-side.
const ALLOWED_BROWSER_ORIGINS = ["https://claude.ai", "https://chatgpt.com"];

const SERVER_INSTRUCTIONS = `stupid vault is the user's credential broker. It holds their linked accounts (Google, GitHub, Spotify, Cloudflare, IMAP email) and lets you use them without ever seeing a credential.

Everything needs the user's approval: they get a push notification on their phone, review what you asked for and confirm with their passkey. Tools wait for that decision; if one returns PENDING_APPROVAL, tell the user what is waiting and call the matching follow-up tool (proxy_result, email_session_status, git_session_remote) with the id it returned.

- APIs: proxy_get (reads) and proxy_request (writes) make one upstream request each; a response is returned only once, so keep what you need.
- Email (read-only): email_start_session, then email_list_folders, email_search and email_read with its session_id. One approval covers the session.
- Git (needs a shell with git): git_read_session (clone/fetch/pull) or git_push_session returns a short-lived remote URL for your git CLI.

Use list_accounts to see what is linked. Propose exactly what you will do, keep requests narrow, and add a short consent_hint so the user knows why you are asking. Linking accounts happens in the stupid vault app (Accounts), not through these tools.`;

function noStore(c: Context): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
}

function getRequesterIp(c: Context): string | null {
  const xff = c.req.header("x-forwarded-for");
  const first = xff?.split(",", 1)[0]?.trim();
  if (first) return first;
  return c.req.header("x-real-ip")?.trim() || null;
}

// --- Discovery (RFC 9728 protected resource, RFC 8414 authorization server) ---

export const mcpWellKnownRouter = new Hono();

for (const path of [
  "/oauth-protected-resource",
  "/oauth-protected-resource/mcp",
]) {
  mcpWellKnownRouter.get(path, (c) => {
    c.header("Cache-Control", "public, max-age=300");
    return c.json(protectedResourceMetadata());
  });
}

mcpWellKnownRouter.get("/oauth-authorization-server", (c) => {
  c.header("Cache-Control", "public, max-age=300");
  return c.json(authorizationServerMetadata());
});

// --- MCP endpoint (Streamable HTTP, stateless, JSON responses) ---

type JsonRpcId = string | number | null;

function rpcResult(c: Context, id: JsonRpcId, result: unknown): Response {
  return c.json({ jsonrpc: "2.0", id, result });
}

function rpcError(
  c: Context,
  id: JsonRpcId,
  code: number,
  message: string,
  status: 200 | 400 | 403 = 200,
  data?: unknown
): Response {
  return c.json(
    {
      jsonrpc: "2.0",
      id,
      error: { code, message, ...(data !== undefined && { data }) },
    },
    status
  );
}

function unauthorized(c: Context, error: string): Response {
  c.header(
    "WWW-Authenticate",
    `Bearer resource_metadata="${protectedResourceMetadataUrl()}", scope="${MCP_SCOPE}"${
      error === "missing_api_key"
        ? ""
        : `, error="invalid_token", error_description="${error}"`
    }`
  );
  return c.json({ error }, 401);
}

export const mcpRouter = new Hono();

mcpRouter.post("/", async (c) => {
  noStore(c);
  const origin = c.req.header("origin");
  if (
    origin &&
    origin !== expectedOrigin() &&
    !ALLOWED_BROWSER_ORIGINS.includes(origin)
  ) {
    return rpcError(c, null, -32600, "origin not allowed", 403);
  }

  // Revoked keys answer 401 too so the client signs in again.
  const authResult = await authenticateApiKey(c.req.header("authorization"));
  if (!authResult.ok) return unauthorized(c, authResult.error);

  const version = c.req.header("mcp-protocol-version");
  if (
    version &&
    !(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version)
  ) {
    return rpcError(
      c,
      null,
      -32600,
      `unsupported MCP-Protocol-Version: ${version}`,
      400
    );
  }

  const msg = (await c.req.json().catch(() => undefined)) as
    | Record<string, unknown>
    | undefined;
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
    return rpcError(c, null, -32700, "parse error", 400);
  }
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    // Responses from the client (we never send requests) are acknowledged.
    if (msg.jsonrpc === "2.0" && ("result" in msg || "error" in msg)) {
      return c.body(null, 202);
    }
    return rpcError(c, null, -32600, "invalid request", 400);
  }
  if (!("id" in msg)) {
    // Notifications (initialized, cancelled, ...) need no answer.
    return c.body(null, 202);
  }
  const id = msg.id as JsonRpcId;
  const params = (
    msg.params && typeof msg.params === "object" ? msg.params : {}
  ) as Record<string, unknown>;

  switch (msg.method) {
    case "initialize": {
      const requested = params.protocolVersion;
      const protocolVersion =
        typeof requested === "string" &&
        (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
          ? requested
          : LATEST_PROTOCOL_VERSION;
      return rpcResult(c, id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: "stupid-vault",
          title: "stupid vault",
          version: "1.0.0",
        },
        instructions: SERVER_INSTRUCTIONS,
      });
    }
    case "ping":
      return rpcResult(c, id, {});
    case "tools/list":
      return rpcResult(c, id, { tools: listTools() });
    case "tools/call": {
      const name = params.name;
      const args = params.arguments ?? {};
      if (typeof name !== "string") {
        return rpcError(c, id, -32602, "missing tool name");
      }
      if (typeof args !== "object" || Array.isArray(args)) {
        return rpcError(c, id, -32602, "arguments must be an object");
      }
      const result = await callTool(name, args as Record<string, unknown>, {
        auth: authResult.auth,
        authorization: c.req.header("authorization") ?? "",
        requesterIp: getRequesterIp(c),
      });
      if (!result) return rpcError(c, id, -32602, `unknown tool: ${name}`);
      return rpcResult(c, id, result);
    }
    default:
      return rpcError(c, id, -32601, `method not found: ${msg.method}`);
  }
});

// No server-initiated stream and no sessions to end.
mcpRouter.on(["GET", "DELETE"], "/", (c) => {
  c.header("Allow", "POST");
  return c.body(null, 405);
});

// --- OAuth 2.1 authorization server ---

export const oauthServerRouter = new Hono();

// RFC 7591 dynamic client registration (public clients only).
oauthServerRouter.post("/register", async (c) => {
  noStore(c);
  const body = await c.req.json().catch(() => null);
  try {
    const { client, createdAt } = await registerClient(body);
    return c.json(
      {
        client_id: client.id,
        client_id_issued_at: Math.floor(Date.parse(createdAt) / 1000),
        ...(client.client_name && { client_name: client.client_name }),
        redirect_uris: client.redirect_uris,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
      201
    );
  } catch (err) {
    if (!(err instanceof OAuthServerError)) throw err;
    return c.json(
      { error: err.code, error_description: err.message },
      err.status as 400
    );
  }
});

function renderConsentPage(
  c: Context,
  params: {
    request: AuthorizationRequest;
    label: string;
    error?: string;
  }
): Response {
  const { request } = params;
  const redirect = new URL(request.redirectUri);
  const name = request.client.client_name || "An MCP client";
  const hidden = (k: string, v: string | null) =>
    v == null
      ? ""
      : `<input type="hidden" name="${k}" value="${escapeHtml(v)}" />`;
  const fields = [
    hidden("response_type", "code"),
    hidden("client_id", request.client.id),
    hidden("redirect_uri", request.redirectUri),
    hidden("state", request.state),
    hidden("code_challenge", request.codeChallenge),
    hidden("code_challenge_method", "S256"),
    hidden("resource", request.resource),
  ].join("\n      ");
  const error = params.error
    ? `<p class="error">${escapeHtml(params.error)}</p>`
    : "";
  const body = `
    <h1>Connect ${escapeHtml(name)}</h1>
    <p><b>${escapeHtml(name)}</b> wants to use your stupid vault. Approving creates an API key for it and returns to <code>${escapeHtml(redirect.host)}</code>.</p>
    <p class="note">The connector never sees your credentials. Every request it makes still needs your approval with your passkey. Revoke its key under API keys to disconnect it. Only continue if you just added this connector yourself.</p>
    ${error}
    <form method="post" action="/oauth/authorize">
      ${fields}
      <input type="hidden" name="action" value="approve" />
      <label>API key label <input type="text" name="label" value="${escapeHtml(params.label)}" maxlength="64" required /></label>
      <p class="note">The label is what you'll see on its approval requests.</p>
      <button type="submit">Approve</button>
    </form>
    <form method="post" action="/oauth/authorize">
      ${fields}
      <input type="hidden" name="action" value="deny" />
      <button type="submit">Deny</button>
    </form>`;
  return sendPage(c, {
    title: `Connect ${name}`,
    body,
    nav: null,
    status: params.error ? 400 : 200,
    // The approve/deny POSTs redirect back to the client.
    formActionOrigins: [redirect.origin],
  });
}

async function handleAuthorize(
  c: Context,
  params: Record<string, unknown>
): Promise<Response> {
  const validated = await validateAuthorizationRequest(params);
  if (!validated.ok && validated.kind === "page") {
    return sendMessagePage(c, {
      title: "Can't connect",
      message: validated.message,
      status: 400,
      nav: null,
    });
  }
  if (!validated.ok) {
    return c.redirect(
      authorizationResponseUrl({
        redirectUri: validated.redirectUri,
        state: validated.state,
        values: {
          error: validated.error,
          error_description: validated.description,
        },
      }),
      302
    );
  }
  const { request } = validated;
  const { userId, sessionId } = c.get("webSession");

  if (c.req.method === "GET") {
    return renderConsentPage(c, {
      request,
      label: await suggestLabel({
        userId,
        clientName: request.client.client_name,
      }),
    });
  }

  if (params.action === "deny") {
    return c.redirect(
      authorizationResponseUrl({
        redirectUri: request.redirectUri,
        state: request.state,
        values: {
          error: "access_denied",
          error_description: "the user denied access",
        },
      }),
      303
    );
  }
  if (params.action !== "approve") return c.text("Bad request", 400);

  const rawLabel = typeof params.label === "string" ? params.label : "";
  const label = ApiKeyLabelSchema.safeParse(rawLabel);
  if (!label.success) {
    return renderConsentPage(c, {
      request,
      label: rawLabel,
      error: "Enter a label (up to 64 characters).",
    });
  }
  let code: string;
  try {
    code = await createAuthorizationCode({
      request,
      userId,
      sessionId,
      label: label.data,
    });
  } catch (err) {
    if (!(err instanceof OAuthServerError)) throw err;
    return renderConsentPage(c, {
      request,
      label: label.data,
      error: err.message,
    });
  }
  return c.redirect(
    authorizationResponseUrl({
      redirectUri: request.redirectUri,
      state: request.state,
      values: { code },
    }),
    303
  );
}

oauthServerRouter.get("/authorize", requireSessionPage, (c) =>
  handleAuthorize(c, c.req.query())
);

oauthServerRouter.post("/authorize", requireSessionPage, async (c) => {
  const form = await c.req.parseBody();
  return handleAuthorize(c, form);
});

async function readTokenParams(c: Context): Promise<Record<string, string>> {
  const type = c.req.header("content-type") ?? "";
  let raw: Record<string, unknown> = {};
  if (type.includes("application/x-www-form-urlencoded")) {
    raw = await c.req.parseBody();
  } else if (type.includes("application/json")) {
    const body = await c.req.json().catch(() => null);
    if (body && typeof body === "object") raw = body;
  }
  return Object.fromEntries(
    Object.entries(raw).filter((e): e is [string, string] => {
      return typeof e[1] === "string";
    })
  );
}

oauthServerRouter.post("/token", async (c) => {
  noStore(c);
  const params = await readTokenParams(c);
  if (params.grant_type !== "authorization_code") {
    return c.json(
      {
        error: "unsupported_grant_type",
        error_description: "only authorization_code is supported",
      },
      400
    );
  }
  try {
    const { accessToken } = await exchangeAuthorizationCode({
      code: params.code ?? null,
      clientId: params.client_id ?? null,
      redirectUri: params.redirect_uri ?? null,
      codeVerifier: params.code_verifier ?? null,
      resource: params.resource ?? null,
    });
    // No expiry and no refresh token: the token is an API key that lives
    // until the user revokes it in the app, after which the client gets a
    // 401 challenge and signs in again.
    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      scope: MCP_SCOPE,
    });
  } catch (err) {
    if (!(err instanceof OAuthServerError)) throw err;
    if (err.status === 401) {
      c.header("WWW-Authenticate", 'Basic realm="stupid vault"');
    }
    return c.json(
      { error: err.code, error_description: err.message },
      err.status as 400
    );
  }
});
