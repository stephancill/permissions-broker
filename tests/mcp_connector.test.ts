import { afterAll, expect, test } from "bun:test";
import { ulid } from "ulid";

import { createApp } from "../src/app";
import { randomBase64Url } from "../src/crypto/random";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, env } from "../src/env";

const ORIGIN = "https://broker.test";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

await migrate();
configureEnv({ ...env, APP_BASE_URL: ORIGIN, APP_SECRET: "test-app-secret" });

const app = createApp();

const upstream = Bun.serve({
  port: 0,
  fetch: () =>
    new Response(JSON.stringify({ login: "octocat" }), {
      headers: { "content-type": "application/json" },
    }),
});
afterAll(() => upstream.stop(true));

type Json = Record<string, unknown>;

async function signedInUser(): Promise<{ userId: string; cookie: string }> {
  const userId = ulid();
  const token = randomBase64Url(32);
  const now = new Date();
  const later = new Date(now.getTime() + 60 * 60_000).toISOString();
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, -Math.floor(Math.random() * 1e12), now.toISOString());
  await database
    .query(
      "INSERT INTO web_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?);"
    )
    .run(
      ulid(),
      userId,
      await sha256Hex(token),
      now.toISOString(),
      now.toISOString(),
      later
    );
  return { userId, cookie: `pb_session=${token}` };
}

async function register(redirectUris = [REDIRECT]): Promise<string> {
  const res = await app.request(`${ORIGIN}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "Claude",
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  expect(res.status).toBe(201);
  const json = (await res.json()) as Json;
  expect(json.token_endpoint_auth_method).toBe("none");
  return json.client_id as string;
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomBase64Url(48);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  const challenge = Buffer.from(digest)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return { verifier, challenge };
}

function authorizeParams(params: {
  clientId: string;
  challenge: string;
  redirectUri?: string;
}): Record<string, string> {
  return {
    response_type: "code",
    client_id: params.clientId,
    redirect_uri: params.redirectUri ?? REDIRECT,
    code_challenge: params.challenge,
    code_challenge_method: "S256",
    state: "xyz",
    scope: "vault",
    resource: `${ORIGIN}/mcp`,
  };
}

async function submitConsent(params: {
  cookie: string;
  form: Record<string, string>;
}): Promise<Response> {
  return app.request(`${ORIGIN}/oauth/authorize`, {
    method: "POST",
    headers: {
      cookie: params.cookie,
      origin: ORIGIN,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params.form).toString(),
  });
}

async function token(form: Record<string, string>) {
  const res = await app.request(`${ORIGIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status, json: (await res.json()) as Json };
}

// Runs the whole connector sign-in and returns the issued access token.
async function connect(label = "Claude"): Promise<{
  accessToken: string;
  userId: string;
}> {
  const { userId, cookie } = await signedInUser();
  const clientId = await register();
  const { verifier, challenge } = await pkce();
  const params = authorizeParams({ clientId, challenge });
  const res = await submitConsent({
    cookie,
    form: { ...params, action: "approve", label },
  });
  expect(res.status).toBe(303);
  const code = new URL(res.headers.get("location") ?? "").searchParams.get(
    "code"
  );
  const { status, json } = await token({
    grant_type: "authorization_code",
    code: code ?? "",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
    resource: `${ORIGIN}/mcp`,
  });
  expect(status).toBe(200);
  return { accessToken: json.access_token as string, userId };
}

async function rpc(
  accessToken: string,
  method: string,
  params: Json = {},
  headers: Record<string, string> = {}
) {
  const res = await app.request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { res, json: (await res.json()) as Json };
}

function toolText(json: Json): { text: string; isError: boolean } {
  const result = json.result as {
    content: { text: string }[];
    isError?: boolean;
  };
  return {
    text: result.content[0]?.text ?? "",
    isError: result.isError === true,
  };
}

test("serves protected resource and authorization server metadata", async () => {
  for (const path of [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ]) {
    const res = await app.request(`${ORIGIN}${path}`);
    expect(res.status).toBe(200);
    const json = (await res.json()) as Json;
    expect(json.resource).toBe(`${ORIGIN}/mcp`);
    expect(json.authorization_servers).toEqual([ORIGIN]);
  }
  const res = await app.request(
    `${ORIGIN}/.well-known/oauth-authorization-server`
  );
  const json = (await res.json()) as Json;
  expect(json.issuer).toBe(ORIGIN);
  expect(json.code_challenge_methods_supported).toEqual(["S256"]);
  expect(json.registration_endpoint).toBe(`${ORIGIN}/oauth/register`);
  expect(json.token_endpoint_auth_methods_supported).toEqual(["none"]);
  expect(json.authorization_response_iss_parameter_supported).toBe(true);
});

test("unauthenticated MCP requests get a 401 challenge", async () => {
  const res = await app.request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });
  expect(res.status).toBe(401);
  expect(res.headers.get("www-authenticate")).toContain(
    `resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"`
  );
  const get = await app.request(`${ORIGIN}/mcp`);
  expect(get.status).toBe(405);
});

test("registration rejects non-https redirect URIs", async () => {
  const res = await app.request(`${ORIGIN}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }),
  });
  expect(res.status).toBe(400);
  expect(((await res.json()) as Json).error).toBe("invalid_redirect_uri");
});

test("consent page needs a session and shows the client and redirect host", async () => {
  const clientId = await register();
  const { challenge } = await pkce();
  const qs = new URLSearchParams(authorizeParams({ clientId, challenge }));

  const anon = await app.request(`${ORIGIN}/oauth/authorize?${qs}`);
  expect(anon.status).toBe(302);
  expect(anon.headers.get("location")).toStartWith("/app/signin?next=");

  const { cookie } = await signedInUser();
  const res = await app.request(`${ORIGIN}/oauth/authorize?${qs}`, {
    headers: { cookie },
  });
  expect(res.status).toBe(200);
  const html = await res.text();
  expect(html).toContain("Connect Claude");
  expect(html).toContain("claude.ai");
  expect(res.headers.get("content-security-policy")).toContain(
    "form-action 'self' https://claude.ai;"
  );
});

test("unregistered redirect URIs are never redirected to", async () => {
  const clientId = await register();
  const { challenge } = await pkce();
  const { cookie } = await signedInUser();
  const qs = new URLSearchParams(
    authorizeParams({
      clientId,
      challenge,
      redirectUri: "https://evil.example/cb",
    })
  );
  const res = await app.request(`${ORIGIN}/oauth/authorize?${qs}`, {
    headers: { cookie },
  });
  expect(res.status).toBe(400);
  expect(res.headers.get("location")).toBeNull();
});

test("missing PKCE is returned to the client as an error", async () => {
  const clientId = await register();
  const { cookie } = await signedInUser();
  const params = authorizeParams({ clientId, challenge: "x" });
  const res = await app.request(
    `${ORIGIN}/oauth/authorize?${new URLSearchParams(params)}`,
    { headers: { cookie } }
  );
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location") ?? "");
  expect(loc.searchParams.get("error")).toBe("invalid_request");
  expect(loc.searchParams.get("state")).toBe("xyz");
  expect(loc.searchParams.get("iss")).toBe(ORIGIN);
});

test("loopback redirect URIs match on any port", async () => {
  const clientId = await register(["http://localhost:3333/callback"]);
  const { cookie } = await signedInUser();
  const { challenge } = await pkce();
  const qs = new URLSearchParams(
    authorizeParams({
      clientId,
      challenge,
      redirectUri: "http://localhost:51234/callback",
    })
  );
  const res = await app.request(`${ORIGIN}/oauth/authorize?${qs}`, {
    headers: { cookie },
  });
  expect(res.status).toBe(200);
});

test("deny redirects with access_denied", async () => {
  const clientId = await register();
  const { cookie } = await signedInUser();
  const { challenge } = await pkce();
  const res = await submitConsent({
    cookie,
    form: { ...authorizeParams({ clientId, challenge }), action: "deny" },
  });
  expect(res.status).toBe(303);
  const loc = new URL(res.headers.get("location") ?? "");
  expect(loc.origin + loc.pathname).toBe(REDIRECT);
  expect(loc.searchParams.get("error")).toBe("access_denied");
});

test("authorization code flow issues a single API key", async () => {
  const { userId, cookie } = await signedInUser();
  const clientId = await register();
  const { verifier, challenge } = await pkce();
  const params = authorizeParams({ clientId, challenge });

  const res = await submitConsent({
    cookie,
    form: { ...params, action: "approve", label: "My Claude" },
  });
  expect(res.status).toBe(303);
  const loc = new URL(res.headers.get("location") ?? "");
  expect(loc.searchParams.get("state")).toBe("xyz");
  expect(loc.searchParams.get("iss")).toBe(ORIGIN);
  const code = loc.searchParams.get("code") ?? "";

  const exchange = {
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  };
  const wrong = await token({
    ...exchange,
    code_verifier: randomBase64Url(48),
  });
  expect(wrong.json.error).toBe("invalid_grant");

  const ok = await token(exchange);
  expect(ok.status).toBe(200);
  expect(ok.json.token_type).toBe("Bearer");
  expect(ok.json.access_token as string).toStartWith("pb_");
  expect(ok.json.refresh_token).toBeUndefined();

  const reused = await token(exchange);
  expect(reused.json.error).toBe("invalid_grant");

  const database = await db();
  const keys = await database
    .query("SELECT label FROM api_keys WHERE user_id = ?;")
    .all<{ label: string }>(userId);
  expect(keys.map((k) => k.label)).toEqual(["My Claude"]);

  // The label is now taken: a second approval with it is refused.
  const again = await submitConsent({
    cookie,
    form: { ...params, action: "approve", label: "My Claude" },
  });
  expect(again.status).toBe(400);
  expect(await again.text()).toContain("already exists");
});

test("MCP initialize, tools/list and whoami", async () => {
  const { accessToken } = await connect();

  const init = await rpc(accessToken, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "test", version: "0" },
  });
  expect(init.res.status).toBe(200);
  const result = init.json.result as Json;
  expect(result.protocolVersion).toBe("2025-06-18");
  expect(result.capabilities).toEqual({ tools: { listChanged: false } });

  const fallback = await rpc(accessToken, "initialize", {
    protocolVersion: "1999-01-01",
  });
  expect((fallback.json.result as Json).protocolVersion).toBe("2025-11-25");

  const notif = await app.request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }),
  });
  expect(notif.status).toBe(202);

  const list = await rpc(accessToken, "tools/list");
  const tools = (list.json.result as { tools: Json[] }).tools;
  expect(tools.map((t) => t.name)).toEqual([
    "whoami",
    "list_accounts",
    "proxy_get",
    "proxy_request",
    "proxy_result",
  ]);
  for (const t of tools) {
    expect((t.inputSchema as Json).type).toBe("object");
    expect(t.call).toBeUndefined();
  }

  const who = await rpc(accessToken, "tools/call", {
    name: "whoami",
    arguments: {},
  });
  expect(JSON.parse(toolText(who.json).text).api_key_label).toBe("Claude");

  const unknown = await rpc(accessToken, "tools/call", { name: "nope" });
  expect((unknown.json.error as Json).code).toBe(-32602);

  const badVersion = await rpc(
    accessToken,
    "ping",
    {},
    { "mcp-protocol-version": "1999-01-01" }
  );
  expect(badVersion.res.status).toBe(400);

  const badOrigin = await rpc(
    accessToken,
    "ping",
    {},
    { origin: "https://evil.example" }
  );
  expect(badOrigin.res.status).toBe(403);
});

test("proxy tools wait for approval, then return the upstream response once", async () => {
  const { accessToken, userId } = await connect();

  const pending = await rpc(accessToken, "tools/call", {
    name: "proxy_get",
    arguments: {
      url: "https://api.github.com/user",
      consent_hint: "check who you are",
      wait_seconds: 0,
    },
  });
  const out = toolText(pending.json);
  expect(out.isError).toBe(false);
  const parsed = JSON.parse(out.text) as Json;
  expect(parsed.status).toBe("PENDING_APPROVAL");
  const requestId = parsed.request_id as string;

  const database = await db();
  const row = await database
    .query(
      "SELECT api_key_label_snapshot, consent_hint FROM proxy_requests WHERE id = ? AND user_id = ?;"
    )
    .get<{ api_key_label_snapshot: string; consent_hint: string }>(
      requestId,
      userId
    );
  expect(row?.api_key_label_snapshot).toBe("Claude");
  expect(row?.consent_hint).toBe("check who you are");

  // Simulate the passkey approval (test mode executes against a stub).
  await database
    .query(
      "UPDATE proxy_requests SET status = 'APPROVED', upstream_url = ? WHERE id = ?;"
    )
    .run(`http://localhost:${upstream.port}/user`, requestId);

  const done = await rpc(accessToken, "tools/call", {
    name: "proxy_result",
    arguments: { request_id: requestId, wait_seconds: 0 },
  });
  const result = toolText(done.json);
  expect(result.isError).toBe(false);
  expect(result.text).toStartWith("HTTP 200 (application/json)");
  expect(result.text).toContain('"login":"octocat"');

  const again = await rpc(accessToken, "tools/call", {
    name: "proxy_result",
    arguments: { request_id: requestId, wait_seconds: 0 },
  });
  expect(toolText(again.json).text).toContain("already executed");
});

test("proxy errors and bad input come back as tool errors", async () => {
  const { accessToken } = await connect();
  const bad = await rpc(accessToken, "tools/call", {
    name: "proxy_get",
    arguments: { url: "https://evil.example/x", wait_seconds: 0 },
  });
  expect(toolText(bad.json).isError).toBe(true);
  expect(toolText(bad.json).text).toContain("invalid_upstream_url");

  const missing = await rpc(accessToken, "tools/call", {
    name: "proxy_request",
    arguments: { url: "https://api.github.com/user" },
  });
  expect(toolText(missing.json)).toEqual({
    text: "method is required",
    isError: true,
  });

  const other = await rpc(accessToken, "tools/call", {
    name: "proxy_result",
    arguments: { request_id: ulid(), wait_seconds: 0 },
  });
  expect(toolText(other.json).isError).toBe(true);
});

test("revoked connector keys get a 401 challenge", async () => {
  const { accessToken } = await connect();
  const database = await db();
  await database
    .query("UPDATE api_keys SET revoked_at = ? WHERE key_hash = ?;")
    .run(new Date().toISOString(), await sha256Hex(accessToken));
  const { res } = await rpc(accessToken, "ping");
  expect(res.status).toBe(401);
  expect(res.headers.get("www-authenticate")).toContain(
    'error="invalid_token"'
  );
});
