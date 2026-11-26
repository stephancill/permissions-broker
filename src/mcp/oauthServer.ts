import { ulid } from "ulid";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { insertApiKey, isUniqueLabelError } from "../auth/apiKeyAdmin";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { expectedOrigin } from "../passkey/webauthn";

// OAuth 2.1 authorization server for MCP connectors (MCP authorization spec
// 2025-11-25). Public clients only: dynamic registration (RFC 7591),
// authorization code + PKCE S256, resource indicators (RFC 8707) and issuer
// identification (RFC 9207). The access token is an ordinary API key labelled
// on the consent page. See docs/MCP_CONNECTOR.md.

export const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
// Registrations that never complete an authorization are dropped.
const UNUSED_CLIENT_TTL_MS = 24 * 60 * 60_000;
export const MCP_SCOPE = "vault";

export class OAuthServerError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

export function issuer(): string {
  return expectedOrigin();
}

export function mcpResourceUrl(): string {
  return `${expectedOrigin()}/mcp`;
}

export function protectedResourceMetadataUrl(): string {
  return `${expectedOrigin()}/.well-known/oauth-protected-resource`;
}

export function protectedResourceMetadata() {
  return {
    resource: mcpResourceUrl(),
    authorization_servers: [issuer()],
    scopes_supported: [MCP_SCOPE],
    bearer_methods_supported: ["header"],
    resource_name: "stupid vault",
  };
}

export function authorizationServerMetadata() {
  const origin = issuer();
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [MCP_SCOPE],
    authorization_response_iss_parameter_supported: true,
  };
}

// The resource a client may ask for: the MCP endpoint (as Claude and ChatGPT
// send it) or the bare origin.
export function isAcceptedResource(raw: string): boolean {
  const trimmed = raw.replace(/\/+$/, "");
  return trimmed === mcpResourceUrl() || trimmed === expectedOrigin();
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"
  );
}

function parseRedirectUri(raw: string): URL | null {
  if (raw.length > 512) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.hash || url.username || url.password) return null;
  if (url.protocol === "https:") return url;
  // Native clients (e.g. Claude Code) listen on a loopback port (RFC 8252).
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) return url;
  return null;
}

// Exact match, except that loopback redirects may use any port (RFC 8252
// §7.3): native clients pick a free port per sign-in.
export function redirectUriMatches(
  registered: string[],
  candidate: string
): boolean {
  const url = parseRedirectUri(candidate);
  if (!url) return false;
  for (const r of registered) {
    if (r === candidate) return true;
    const reg = parseRedirectUri(r);
    if (
      reg &&
      reg.protocol === "http:" &&
      isLoopbackHost(reg.hostname) &&
      reg.hostname === url.hostname &&
      reg.pathname === url.pathname &&
      reg.search === url.search
    ) {
      return true;
    }
  }
  return false;
}

const RegisterSchema = z.object({
  redirect_uris: z.array(z.string()).min(1).max(10),
  client_name: z
    .string()
    .transform((s) => s.trim().replace(/\s+/g, " "))
    .pipe(z.string().max(100))
    .optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
});

export type OAuthClient = {
  id: string;
  client_name: string | null;
  redirect_uris: string[];
};

export async function registerClient(raw: unknown): Promise<{
  client: OAuthClient;
  createdAt: string;
}> {
  const parsed = RegisterSchema.safeParse(raw);
  if (!parsed.success) {
    throw new OAuthServerError(
      "invalid_client_metadata",
      parsed.error.issues[0]?.message ?? "invalid client metadata"
    );
  }
  const data = parsed.data;
  for (const uri of data.redirect_uris) {
    if (!parseRedirectUri(uri)) {
      throw new OAuthServerError(
        "invalid_redirect_uri",
        "redirect_uris must be https (or http on a loopback host) without a fragment"
      );
    }
  }
  if (data.grant_types && !data.grant_types.includes("authorization_code")) {
    throw new OAuthServerError(
      "invalid_client_metadata",
      "only the authorization_code grant is supported"
    );
  }
  if (data.response_types && !data.response_types.includes("code")) {
    throw new OAuthServerError(
      "invalid_client_metadata",
      "only the code response type is supported"
    );
  }

  const client: OAuthClient = {
    id: `mcp_${randomBase64Url(24)}`,
    client_name: data.client_name || null,
    redirect_uris: data.redirect_uris,
  };
  const createdAt = nowIso();
  const database = await db();
  await database
    .query(
      "INSERT INTO oauth_clients (id, client_name, redirect_uris_json, created_at) VALUES (?, ?, ?, ?);"
    )
    .run(
      client.id,
      client.client_name,
      JSON.stringify(client.redirect_uris),
      createdAt
    );
  return { client, createdAt };
}

export async function getClient(clientId: string): Promise<OAuthClient | null> {
  if (clientId.length > 128) return null;
  const database = await db();
  const row = await database
    .query(
      "SELECT id, client_name, redirect_uris_json FROM oauth_clients WHERE id = ?;"
    )
    .get<{
      id: string;
      client_name: string | null;
      redirect_uris_json: string;
    }>(clientId);
  if (!row) return null;
  return {
    id: row.id,
    client_name: row.client_name,
    redirect_uris: JSON.parse(row.redirect_uris_json) as string[],
  };
}

// Parameters of an authorization request, validated in two steps: problems
// with the client or redirect URI are shown to the user (never redirected),
// everything else goes back to the client as an OAuth error.
export type AuthorizationRequest = {
  client: OAuthClient;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string | null;
};

export type AuthorizationRequestResult =
  | { ok: true; request: AuthorizationRequest }
  | { ok: false; kind: "page"; message: string }
  | {
      ok: false;
      kind: "redirect";
      redirectUri: string;
      state: string | null;
      error: string;
      description: string;
    };

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

export async function validateAuthorizationRequest(
  params: Record<string, unknown>
): Promise<AuthorizationRequestResult> {
  const clientId = str(params.client_id);
  const client = clientId ? await getClient(clientId) : null;
  if (!client) {
    return {
      ok: false,
      kind: "page",
      message:
        "Unknown client. Remove the connector in your app and add it again.",
    };
  }
  const redirectUri = str(params.redirect_uri);
  if (!redirectUri || !redirectUriMatches(client.redirect_uris, redirectUri)) {
    return {
      ok: false,
      kind: "page",
      message: "The redirect URI is not registered for this client.",
    };
  }

  const state = str(params.state);
  const fail = (error: string, description: string) =>
    ({
      ok: false,
      kind: "redirect",
      redirectUri,
      state,
      error,
      description,
    }) as const;

  if (params.response_type !== "code") {
    return fail("unsupported_response_type", "response_type must be code");
  }
  const codeChallenge = str(params.code_challenge);
  if (
    !codeChallenge ||
    params.code_challenge_method !== "S256" ||
    !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)
  ) {
    return fail("invalid_request", "PKCE with S256 is required");
  }
  const resource = str(params.resource);
  if (resource && !isAcceptedResource(resource)) {
    return fail("invalid_target", "unknown resource");
  }
  return {
    ok: true,
    request: { client, redirectUri, state, codeChallenge, resource },
  };
}

// RFC 6749 §4.1.2 plus RFC 9207 `iss` on every response.
export function authorizationResponseUrl(params: {
  redirectUri: string;
  state: string | null;
  values: Record<string, string>;
}): string {
  const url = new URL(params.redirectUri);
  for (const [k, v] of Object.entries(params.values)) {
    url.searchParams.set(k, v);
  }
  if (params.state != null) url.searchParams.set("state", params.state);
  url.searchParams.set("iss", issuer());
  return url.toString();
}

// Suggests a free API key label based on the client's name.
export async function suggestLabel(params: {
  userId: string;
  clientName: string | null;
}): Promise<string> {
  const base = (params.clientName || "MCP connector").slice(0, 56);
  const database = await db();
  for (let n = 1; n < 50; n++) {
    const label = n === 1 ? base : `${base} ${n}`;
    const taken = await database
      .query("SELECT 1 AS x FROM api_keys WHERE user_id = ? AND label = ?;")
      .get(params.userId, label);
    if (!taken) return label;
  }
  return `${base} ${ulid().slice(-6)}`;
}

export async function createAuthorizationCode(params: {
  request: AuthorizationRequest;
  userId: string;
  sessionId: string;
  label: string;
}): Promise<string> {
  const database = await db();
  const taken = await database
    .query("SELECT 1 AS x FROM api_keys WHERE user_id = ? AND label = ?;")
    .get(params.userId, params.label);
  if (taken) {
    throw new OAuthServerError(
      "label_taken",
      `A key labelled "${params.label}" already exists.`
    );
  }

  const code = randomBase64Url(32);
  const now = Date.now();
  await database
    .query(
      "INSERT INTO oauth_authorization_codes (id, code_hash, client_id, user_id, approved_session_id, redirect_uri, code_challenge, resource, label, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?);"
    )
    .run(
      ulid(),
      await sha256Hex(code),
      params.request.client.id,
      params.userId,
      params.sessionId,
      params.request.redirectUri,
      params.request.codeChallenge,
      params.request.resource,
      params.label,
      new Date(now).toISOString(),
      new Date(now + AUTHORIZATION_CODE_TTL_SECONDS * 1000).toISOString()
    );
  await database
    .query("UPDATE oauth_clients SET last_used_at = ? WHERE id = ?;")
    .run(new Date(now).toISOString(), params.request.client.id);
  await auditEvent({
    userId: params.userId,
    actorType: "session",
    actorId: params.sessionId,
    eventType: "mcp_oauth_authorized",
    event: {
      clientId: params.request.client.id,
      clientName: params.request.client.client_name,
      redirectHost: new URL(params.request.redirectUri).host,
      label: params.label,
    },
  });
  return code;
}

async function pkceS256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return Buffer.from(digest)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export async function exchangeAuthorizationCode(params: {
  code: string | null;
  clientId: string | null;
  redirectUri: string | null;
  codeVerifier: string | null;
  resource: string | null;
}): Promise<{ accessToken: string; label: string }> {
  const invalidGrant = (msg: string) =>
    new OAuthServerError("invalid_grant", msg);
  if (!params.clientId || !(await getClient(params.clientId))) {
    throw new OAuthServerError("invalid_client", "unknown client", 401);
  }
  if (!params.code || !params.codeVerifier || !params.redirectUri) {
    throw new OAuthServerError(
      "invalid_request",
      "code, code_verifier and redirect_uri are required"
    );
  }
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(params.codeVerifier)) {
    throw new OAuthServerError("invalid_request", "malformed code_verifier");
  }

  const database = await db();
  const row = await database
    .query(
      "SELECT id, client_id, user_id, approved_session_id, redirect_uri, code_challenge, resource, label, status, expires_at FROM oauth_authorization_codes WHERE code_hash = ?;"
    )
    .get<{
      id: string;
      client_id: string;
      user_id: string;
      approved_session_id: string;
      redirect_uri: string;
      code_challenge: string;
      resource: string | null;
      label: string;
      status: string;
      expires_at: string;
    }>(await sha256Hex(params.code));
  if (!row || row.client_id !== params.clientId) {
    throw invalidGrant("unknown authorization code");
  }
  if (row.status !== "PENDING") throw invalidGrant("code already used");
  if (Date.now() >= Date.parse(row.expires_at)) {
    throw invalidGrant("code expired");
  }
  if (row.redirect_uri !== params.redirectUri) {
    throw invalidGrant("redirect_uri mismatch");
  }
  if ((await pkceS256(params.codeVerifier)) !== row.code_challenge) {
    throw invalidGrant("PKCE verification failed");
  }
  if (params.resource && !isAcceptedResource(params.resource)) {
    throw new OAuthServerError("invalid_target", "unknown resource");
  }

  // Claim first so concurrent exchanges mint at most one key.
  const claimed = await database
    .query(
      "UPDATE oauth_authorization_codes SET status = 'USED' WHERE id = ? AND status = 'PENDING';"
    )
    .run(row.id);
  if (!claimed.changes) throw invalidGrant("code already used");

  let created: { id: string; keyPlain: string };
  try {
    created = await insertApiKey({ userId: row.user_id, label: row.label });
  } catch (err) {
    if (!isUniqueLabelError(err)) throw err;
    throw invalidGrant(
      `a key labelled "${row.label}" was created in the meantime`
    );
  }
  await database
    .query("UPDATE oauth_authorization_codes SET api_key_id = ? WHERE id = ?;")
    .run(created.id, row.id);
  await auditEvent({
    userId: row.user_id,
    actorType: "session",
    actorId: row.approved_session_id,
    eventType: "api_key_created",
    event: {
      apiKeyId: created.id,
      label: row.label,
      via: "mcp_oauth",
      clientId: row.client_id,
    },
  });
  return { accessToken: created.keyPlain, label: row.label };
}

export async function sweepOAuthServerState(): Promise<void> {
  const database = await db();
  await database
    .query("DELETE FROM oauth_authorization_codes WHERE expires_at < ?;")
    .run(new Date(Date.now() - 60 * 60_000).toISOString());
  await database
    .query(
      "DELETE FROM oauth_clients WHERE last_used_at IS NULL AND created_at < ?;"
    )
    .run(new Date(Date.now() - UNUSED_CLIENT_TTL_MS).toISOString());
}
