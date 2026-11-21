import { afterAll, beforeAll, expect, test } from "bun:test";
import { ulid } from "ulid";

import { createApp } from "../src/app";
import { saveLinkedCredential } from "../src/credentials/store";
import { encryptUtf8 } from "../src/crypto/aesgcm";
import { fromBase64Url, toBase64Url, toBytes } from "../src/crypto/bytes";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, type Env, env } from "../src/env";
import { CLIENT_CRYPTO_JS } from "../src/passkey/clientCrypto";
import { createVirtualAuthenticator } from "./helpers/virtualAuthenticator";

type JsonRecord = Record<string, unknown>;

type ClientCrypto = {
  deriveKek(prfOutput: ArrayBuffer, userId: string): Promise<CryptoKey>;
  generateUserKeypair(): Promise<{
    publicKeyRaw: Uint8Array;
    privateKey: CryptoKey;
  }>;
  wrapPrivateKey(
    kek: CryptoKey,
    privateKey: CryptoKey,
    userId: string
  ): Promise<Uint8Array>;
  unwrapPrivateKey(
    kek: CryptoKey,
    wrapped: Uint8Array,
    userId: string,
    extractable?: boolean
  ): Promise<CryptoKey>;
  deriveDek(
    privateKey: CryptoKey,
    epkRaw: Uint8Array,
    linkedAccountId: string
  ): Promise<Uint8Array>;
};

new Function(CLIENT_CRYPTO_JS)();
const PB = (globalThis as unknown as { PB: ClientCrypto }).PB;

const ORIGIN = "https://broker.test";
const GITHUB_TOKEN = "gho_test_token";

let prevEnv: Env;
const realFetch = globalThis.fetch;
const upstreamAuthHeaders: string[] = [];
const pushes: Array<{ url: string; headers: Headers; body: Uint8Array }> = [];
// Cloudflare OAuth stub: token endpoint form bodies and upstream auth headers.
const cloudflareTokenRequests: URLSearchParams[] = [];
const cloudflareUpstreamAuth: string[] = [];
let cloudflareTokenCounter = 0;

await migrate();

beforeAll(() => {
  prevEnv = env;
  configureEnv({
    ...env,
    APP_BASE_URL: ORIGIN,
    APP_SECRET: "test-app-secret",
    PB_TEST_BYPASS_OAUTH: false,
    // Tests create several accounts; the closed default is tested explicitly.
    ALLOW_SIGNUP: true,
  });
  // Stub the upstream provider; record the injected credential.
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit
  ) => {
    const url = new URL(
      input instanceof Request ? input.url : input.toString()
    );
    if (
      url.hostname === "dash.cloudflare.com" &&
      url.pathname === "/oauth2/token"
    ) {
      const form = new URLSearchParams(
        init?.body instanceof URLSearchParams
          ? init.body.toString()
          : String(init?.body ?? "")
      );
      cloudflareTokenRequests.push(form);
      cloudflareTokenCounter++;
      return new Response(
        JSON.stringify({
          access_token: `cf_at_${cloudflareTokenCounter}`,
          refresh_token: `cf_rt_${cloudflareTokenCounter}`,
          token_type: "bearer",
          expires_in: 3600,
          scope: "account-settings.read user-details.read offline_access",
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (url.hostname === "api.cloudflare.com") {
      cloudflareUpstreamAuth.push(
        new Headers(init?.headers).get("authorization") ?? ""
      );
      const result =
        url.pathname === "/client/v4/accounts"
          ? [{ id: "acc_1", name: "Main account" }]
          : [];
      return new Response(JSON.stringify({ success: true, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.hostname === "web.push.apple.com") {
      pushes.push({
        url: url.toString(),
        headers: new Headers(init?.headers),
        body: new Uint8Array(init?.body as ArrayBuffer),
      });
      return new Response(null, { status: 201 });
    }
    if (url.hostname === "api.github.com") {
      upstreamAuthHeaders.push(
        new Headers(init?.headers).get("authorization") ?? ""
      );
      return new Response(JSON.stringify({ login: "octocat" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return realFetch(input, init);
  }) as typeof fetch;
});

afterAll(() => {
  configureEnv(prevEnv);
  globalThis.fetch = realFetch;
});

const app = createApp();
const authenticator = createVirtualAuthenticator({
  rpId: "broker.test",
  origin: ORIGIN,
});

// Session cookie of the most recently signed-up/signed-in account.
let sessionCookie = "";

function cookieFrom(res: Response): string {
  const raw = res.headers.get("set-cookie") ?? "";
  const m = raw.match(/pb_session=([^;]+)/);
  if (!m) throw new Error("no session cookie");
  return `pb_session=${m[1]}`;
}

async function postJson(
  path: string,
  body: unknown,
  headers: Record<string, string> = {}
) {
  const res = await app.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
      cookie: sessionCookie,
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return {
    status: res.status,
    json: (await res.json()) as JsonRecord,
    res,
  };
}

function getPage(path: string, cookie = sessionCookie) {
  return app.request(path, { headers: { cookie } });
}

async function resetDb() {
  const database = await db();
  for (const table of [
    "credential_grants",
    "approval_windows",
    "webauthn_challenges",
    "auth_challenges",
    "web_sessions",
    "push_subscriptions",
    "proxy_requests",
    "linked_accounts",
    "user_passkeys",
    "user_keys",
    "connect_states",
    "api_keys",
    "users",
  ]) {
    await database.exec(`DELETE FROM ${table};`);
  }
}

async function insertApiKey(userId: string, keyPlain: string) {
  const database = await db();
  const now = new Date().toISOString();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, 'agent', ?, ?, ?, NULL, NULL);"
    )
    .run(ulid(), userId, await sha256Hex(keyPlain), now, now);
}

type Account = {
  userId: string;
  credentialId: string;
  cookie: string;
};

// What the sign-in page does on "Create account".
async function signUp(): Promise<Account> {
  const o = await postJson("/passkey/signup/options", {});
  expect(o.status).toBe(200);
  const userId = o.json.user_id as string;
  const opts = o.json.registration_options as { challenge: string };
  const prfSalt = fromBase64Url(o.json.prf_salt as string);

  const created = await authenticator.create({ challenge: opts.challenge });
  const prf = await authenticator.prf(created.credential.idB64, prfSalt);
  const kek = await PB.deriveKek(prf, userId);
  const pair = await PB.generateUserKeypair();
  const wrapped = await PB.wrapPrivateKey(kek, pair.privateKey, userId);

  const v = await postJson("/passkey/signup/verify", {
    nonce: o.json.nonce,
    registration: created.response,
    public_key: toBase64Url(pair.publicKeyRaw),
    wrapped_private_key: toBase64Url(wrapped),
  });
  expect(v.status).toBe(200);
  sessionCookie = cookieFrom(v.res);
  return {
    userId,
    credentialId: created.credential.idB64,
    cookie: sessionCookie,
  };
}

async function signUpWithKey(keyPlain: string): Promise<string> {
  const account = await signUp();
  await insertApiKey(account.userId, keyPlain);
  return account.userId;
}

type PageData = {
  user_id: string;
  passkey: {
    credential_id: string;
    prf_salt: string;
    wrapped_private_key: string;
  };
  credential: { linked_account_id: string; epk: string } | null;
};

async function loadApprovalPage(kind: string, id: string): Promise<PageData> {
  const res = await getPage(`/approve/${kind}/${id}`);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-security-policy")).toContain(
    "script-src 'nonce-"
  );
  const html = await res.text();
  const m = html.match(/var DATA = (.*?);\n/);
  if (!m) throw new Error("approval page data not found");
  return JSON.parse(m[1]) as PageData;
}

// What the approval page script does in the browser.
async function approveViaPage(params: {
  kind: string;
  id: string;
  options: unknown;
  tamperDek?: boolean;
}) {
  const data = await loadApprovalPage(params.kind, params.id);
  const base = `/approve/${params.kind}/${params.id}`;
  const ch = await postJson(`${base}/challenge`, {
    options: params.options,
  });
  expect(ch.status).toBe(200);

  const assertion = await authenticator.get({
    credentialId: data.passkey.credential_id,
    challenge: ch.json.challenge as string,
  });
  const body: JsonRecord = { nonce: ch.json.nonce, assertion };

  if (data.credential) {
    const prf = await authenticator.prf(
      data.passkey.credential_id,
      fromBase64Url(data.passkey.prf_salt)
    );
    const kek = await PB.deriveKek(prf, data.user_id);
    const priv = await PB.unwrapPrivateKey(
      kek,
      fromBase64Url(data.passkey.wrapped_private_key),
      data.user_id
    );
    const dek = await PB.deriveDek(
      priv,
      fromBase64Url(data.credential.epk),
      data.credential.linked_account_id
    );
    if (params.tamperDek) dek[0] ^= 0xff;
    body.dek = toBase64Url(dek);
  }

  return { ...(await postJson(base, body)), body };
}

async function createProxyRequest(
  keyPlain: string,
  ip = "203.0.113.7",
  upstreamUrl = "https://api.github.com/user"
) {
  const res = await postJson(
    "/v1/proxy/request",
    { upstream_url: upstreamUrl, method: "GET" },
    { authorization: `Bearer ${keyPlain}`, "x-forwarded-for": ip }
  );
  expect(res.status).toBe(200);
  return res.json;
}

async function execute(keyPlain: string, requestId: string) {
  return app.request(`/v1/proxy/requests/${requestId}/execute`, {
    method: "POST",
    headers: { authorization: `Bearer ${keyPlain}` },
  });
}

async function githubAccountRow(userId: string) {
  const database = await db();
  return (await database
    .query(
      "SELECT id, enc_version, credential_epk, metadata_json FROM linked_accounts WHERE user_id = ? AND provider = 'github';"
    )
    .get(userId)) as {
    id: string;
    enc_version: number;
    credential_epk: Uint8Array | null;
    metadata_json: string | null;
  };
}

async function githubEpk(userId: string): Promise<Uint8Array> {
  const epk = (await githubAccountRow(userId)).credential_epk;
  if (!epk) throw new Error("credential_epk missing");
  return toBytes(epk);
}

test("replacing the passkey keeps the key and migrates legacy credentials", async () => {
  await resetDb();
  const account = await signUp();
  const userId = account.userId;

  const database = await db();
  await database
    .query(
      "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, 'github', 'unknown', 'repo', ?, 'active', ?, NULL);"
    )
    .run(
      ulid(),
      userId,
      await encryptUtf8(GITHUB_TOKEN),
      new Date().toISOString()
    );

  // What /passkey/enroll does for "Replace passkey (I still have my current one)".
  const o = await postJson("/passkey/enroll/options", {});
  expect(o.status).toBe(200);
  const existing = o.json.existing as {
    credential_id: string;
    prf_salt: string;
    public_key: string;
    wrapped_private_key: string;
  };
  const oldPrf = await authenticator.prf(
    existing.credential_id,
    fromBase64Url(existing.prf_salt)
  );
  const privateKey = await PB.unwrapPrivateKey(
    await PB.deriveKek(oldPrf, userId),
    fromBase64Url(existing.wrapped_private_key),
    userId,
    true
  );
  const opts = o.json.registration_options as { challenge: string };
  const created = await authenticator.create({ challenge: opts.challenge });
  const newPrf = await authenticator.prf(
    created.credential.idB64,
    fromBase64Url(o.json.prf_salt as string)
  );
  const wrapped = await PB.wrapPrivateKey(
    await PB.deriveKek(newPrf, userId),
    privateKey,
    userId
  );
  const v = await postJson("/passkey/enroll/verify", {
    nonce: o.json.nonce,
    mode: "rewrap",
    registration: created.response,
    public_key: existing.public_key,
    wrapped_private_key: toBase64Url(wrapped),
  });
  expect(v.status).toBe(200);
  expect(v.json.message).toContain("Re-encrypted 1");

  const row = await githubAccountRow(userId);
  expect(row.enc_version).toBe(1);
  expect(row.credential_epk).not.toBeNull();
});

test("proxy request: passkey approval unlocks, executes once, rotates", async () => {
  await resetDb();
  const userId = await signUpWithKey("pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "github",
    providerUserId: "unknown",
    scopes: "repo",
    plaintext: GITHUB_TOKEN,
  });

  const created = await createProxyRequest("pb_flow_a");
  expect(created.status).toBe("PENDING_APPROVAL");
  const requestId = created.request_id as string;

  // Not executable before approval.
  expect((await execute("pb_flow_a", requestId)).status).toBe(202);

  const epkBefore = await githubEpk(userId);
  const approved = await approveViaPage({
    kind: "proxy",
    id: requestId,
    options: { mode: "once" },
  });
  expect(approved.status).toBe(200);

  upstreamAuthHeaders.length = 0;
  const res = await execute("pb_flow_a", requestId);
  expect(res.status).toBe(200);
  expect(upstreamAuthHeaders).toEqual([`Bearer ${GITHUB_TOKEN}`]);

  // Grant wiped and credential re-encrypted under a fresh ephemeral key.
  const database = await db();
  const grants = (await database
    .query("SELECT COUNT(*) AS n FROM credential_grants;")
    .get()) as { n: number };
  expect(grants.n).toBe(0);
  const epkAfter = await githubEpk(userId);
  expect(Buffer.from(epkAfter).equals(Buffer.from(epkBefore))).toBe(false);

  // Second execute is rejected as before.
  expect((await execute("pb_flow_a", requestId)).status).toBe(410);
});

test("approval challenge is single use and the DEK must match", async () => {
  await resetDb();
  const userId = await signUpWithKey("pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "github",
    providerUserId: "unknown",
    scopes: "repo",
    plaintext: GITHUB_TOKEN,
  });

  const created = await createProxyRequest("pb_flow_a");
  const requestId = created.request_id as string;

  const bad = await approveViaPage({
    kind: "proxy",
    id: requestId,
    options: { mode: "once" },
    tamperDek: true,
  });
  expect(bad.status).toBe(400);
  expect(bad.json.error).toBe("decrypt_failed");

  const good = await approveViaPage({
    kind: "proxy",
    id: requestId,
    options: { mode: "once" },
  });
  expect(good.status).toBe(200);

  // Replaying the same signed approval fails.
  const replay = await postJson(`/approve/proxy/${requestId}`, good.body);
  expect(replay.status).toBe(400);
  expect(replay.json.error).toBe("invalid_challenge");
});

test("approval pages are scoped to the signed-in owner", async () => {
  await resetDb();
  const owner = await signUp();
  await insertApiKey(owner.userId, "pb_flow_a");
  const created = await createProxyRequest("pb_flow_a");
  const requestId = created.request_id as string;
  const path = `/approve/proxy/${requestId}`;

  // Signed out: redirected to sign-in, and the JSON endpoints refuse.
  const signedOut = await getPage(path, "");
  expect(signedOut.status).toBe(302);
  expect(signedOut.headers.get("location")).toBe(
    `/app/signin?next=${encodeURIComponent(path)}`
  );
  const ch = await postJson(
    `${path}/challenge`,
    { options: {} },
    { cookie: "" }
  );
  expect(ch.status).toBe(401);

  // Cross-origin writes are refused even with a valid session.
  const cross = await postJson(
    `${path}/deny`,
    {},
    { origin: "https://evil.example" }
  );
  expect(cross.status).toBe(403);
  const noOrigin = await postJson(
    `${path}/deny`,
    {},
    { origin: "null", "sec-fetch-site": "cross-site" }
  );
  expect(noOrigin.status).toBe(403);

  // Another account can't see it.
  const other = await signUp();
  expect((await getPage(path, other.cookie)).status).toBe(404);
  expect((await postJson(`${path}/deny`, {})).status).toBe(404);

  // The owner can.
  expect((await getPage(path, owner.cookie)).status).toBe(200);
});

test("deny from the app needs no passkey and is final", async () => {
  await resetDb();
  await signUpWithKey("pb_flow_a");
  const created = await createProxyRequest("pb_flow_a");
  const requestId = created.request_id as string;

  const denied = await postJson(`/approve/proxy/${requestId}/deny`, {});
  expect(denied.status).toBe(200);
  const again = await postJson(`/approve/proxy/${requestId}/deny`, {});
  expect(again.status).toBe(409);

  const status = await app.request(`/v1/proxy/requests/${requestId}`, {
    headers: { authorization: "Bearer pb_flow_a" },
  });
  expect(status.status).toBe(403);
  expect(((await status.json()) as JsonRecord).error).toBe("denied");
});

test("sign in with the passkey creates a session; unknown passkeys are refused", async () => {
  await resetDb();
  const account = await signUp();
  sessionCookie = "";

  const o = await postJson("/passkey/signin/options", {});
  expect(o.status).toBe(200);
  const assertion = await authenticator.get({
    credentialId: account.credentialId,
    challenge: o.json.challenge as string,
  });
  const v = await postJson("/passkey/signin/verify", {
    nonce: o.json.nonce,
    assertion,
  });
  expect(v.status).toBe(200);
  const cookie = cookieFrom(v.res);
  expect(v.res.headers.get("set-cookie")).toContain("HttpOnly");
  expect((await getPage("/app", cookie)).status).toBe(200);

  // Challenge is single use.
  const replay = await postJson("/passkey/signin/verify", {
    nonce: o.json.nonce,
    assertion,
  });
  expect(replay.status).toBe(400);

  // A passkey the broker doesn't know.
  const stranger = await authenticator.create({ challenge: "AAAA" });
  const o2 = await postJson("/passkey/signin/options", {});
  const a2 = await authenticator.get({
    credentialId: stranger.credential.idB64,
    challenge: o2.json.challenge as string,
  });
  const v2 = await postJson("/passkey/signin/verify", {
    nonce: o2.json.nonce,
    assertion: a2,
  });
  expect(v2.status).toBe(403);

  // Signing out ends the session server-side.
  const out = await app.request("/passkey/signout", {
    method: "POST",
    headers: { origin: ORIGIN, cookie },
  });
  expect(out.status).toBe(303);
  expect((await getPage("/app", cookie)).status).toBe(302);
});

test("sign-up is only open on an empty broker unless ALLOW_SIGNUP", async () => {
  await resetDb();
  const current = env;
  configureEnv({ ...current, ALLOW_SIGNUP: false });
  try {
    // First account bootstraps the broker.
    await signUp();
    const closed = await postJson("/passkey/signup/options", {});
    expect(closed.status).toBe(403);
    const page = await (await getPage("/app/signin", "")).text();
    expect(page).not.toContain("Create account");
  } finally {
    configureEnv(current);
  }
  expect((await postJson("/passkey/signup/options", {})).status).toBe(200);
});

test("API keys are created in the app and shown once", async () => {
  await resetDb();
  const account = await signUp();
  const res = await app.request("/app/keys", {
    method: "POST",
    headers: {
      origin: ORIGIN,
      cookie: account.cookie,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "label=laptop+agent",
  });
  expect(res.status).toBe(200);
  const html = await res.text();
  const key = html.match(/<pre id="new-key">(pb_[A-Za-z0-9_-]+)<\/pre>/)?.[1];
  expect(key).toBeDefined();

  const who = await app.request("/v1/whoami", {
    headers: { authorization: `Bearer ${key}` },
  });
  expect(who.status).toBe(200);

  // Listed afterwards without the secret.
  const list = await (await getPage("/app/keys", account.cookie)).text();
  expect(list).toContain("laptop agent");
  // App title sits above the nav row.
  expect(list).toContain(
    '<header class="app"><a href="/app">stupid vault</a></header><nav>'
  );
  expect(list).not.toContain(key as string);
});

test("approval window auto-approves the endpoint and survives rotation", async () => {
  await resetDb();
  const userId = await signUpWithKey("pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "github",
    providerUserId: "unknown",
    scopes: "repo",
    plaintext: GITHUB_TOKEN,
  });

  const first = await createProxyRequest("pb_flow_a");
  const approved = await approveViaPage({
    kind: "proxy",
    id: first.request_id as string,
    options: { mode: "window", scope: "endpoint", minutes: 15 },
  });
  expect(approved.status).toBe(200);
  expect((await execute("pb_flow_a", first.request_id as string)).status).toBe(
    200
  );

  // Same key + IP + endpoint: auto-approved, and the window's key still works
  // after the credential was rotated by the previous execution.
  for (let i = 0; i < 2; i++) {
    const next = await createProxyRequest("pb_flow_a");
    expect(next.status).toBe("APPROVED");
    const res = await execute("pb_flow_a", next.request_id as string);
    expect(res.status).toBe(200);
  }

  // A different requester IP is not covered by the window.
  const other = await createProxyRequest("pb_flow_a", "198.51.100.1");
  expect(other.status).toBe("PENDING_APPROVAL");
});

test("provider approval window auto-approves any endpoint for the provider", async () => {
  await resetDb();
  const userId = await signUpWithKey("pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "github",
    providerUserId: "unknown",
    scopes: "repo",
    plaintext: GITHUB_TOKEN,
  });

  const first = await createProxyRequest("pb_flow_a");
  const page = await getPage(`/approve/proxy/${first.request_id as string}`);
  const html = await page.text();
  expect(html).toContain("<summary>Advanced</summary>");
  expect(html).toContain("window:provider:15");

  const approved = await approveViaPage({
    kind: "proxy",
    id: first.request_id as string,
    options: { mode: "window", scope: "provider", minutes: 15 },
  });
  expect(approved.status).toBe(200);

  // A different endpoint on the same provider is covered.
  const next = await createProxyRequest(
    "pb_flow_a",
    "203.0.113.7",
    "https://api.github.com/user/repos"
  );
  expect(next.status).toBe("APPROVED");
  expect((await execute("pb_flow_a", next.request_id as string)).status).toBe(
    200
  );

  // Still scoped to the requester IP.
  const other = await createProxyRequest("pb_flow_a", "198.51.100.1");
  expect(other.status).toBe("PENDING_APPROVAL");
});

test("connecting an account requires an enrolled passkey", async () => {
  await resetDb();
  const userId = ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, -1, new Date().toISOString());
  await expect(
    saveLinkedCredential({
      userId,
      provider: "github",
      providerUserId: "unknown",
      scopes: "repo",
      plaintext: GITHUB_TOKEN,
    })
  ).rejects.toThrow(/passkey/i);
});

test("account listing uses stored metadata without decrypting", async () => {
  await resetDb();
  const userId = await signUpWithKey("pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "imap",
    providerUserId: "x",
    scopes: "read",
    plaintext: JSON.stringify({
      email: "user@example.com",
      password: "secret",
      host: "imap.example.com",
      port: 993,
      secure: true,
    }),
  });

  const res = await app.request("/v1/accounts", {
    headers: { authorization: "Bearer pb_flow_a" },
  });
  const j = (await res.json()) as {
    accounts: Array<{ metadata?: { imap?: { host: string } } }>;
  };
  expect(j.accounts[0]?.metadata?.imap?.host).toBe("imap.example.com");
  expect(JSON.stringify(j)).not.toContain("secret");
});

// Device side of RFC 8291: decrypt a single-record aes128gcm push.
async function decryptPush(params: {
  body: Uint8Array;
  uaKeys: CryptoKeyPair;
  uaPublic: Uint8Array;
  auth: Uint8Array;
}): Promise<unknown> {
  const salt = params.body.subarray(0, 16);
  const idLen = params.body[20];
  const asPublic = params.body.subarray(21, 21 + idLen);
  const ciphertext = params.body.subarray(21 + idLen);
  const hmac = async (key: Uint8Array, data: Uint8Array) =>
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        await crypto.subtle.importKey(
          "raw",
          new Uint8Array(key),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        ),
        new Uint8Array(data)
      )
    );
  const hkdf = async (
    salt: Uint8Array,
    ikm: Uint8Array,
    info: Uint8Array,
    len: number
  ) =>
    (await hmac(await hmac(salt, ikm), new Uint8Array([...info, 1]))).subarray(
      0,
      len
    );
  const enc = new TextEncoder();
  const ecdh = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: await crypto.subtle.importKey(
          "raw",
          new Uint8Array(asPublic),
          { name: "ECDH", namedCurve: "P-256" },
          false,
          []
        ),
      },
      params.uaKeys.privateKey,
      256
    )
  );
  const ikm = await hkdf(
    params.auth,
    ecdh,
    new Uint8Array([
      ...enc.encode("WebPush: info\0"),
      ...params.uaPublic,
      ...asPublic,
    ]),
    32
  );
  const cek = await hkdf(
    salt,
    ikm,
    enc.encode("Content-Encoding: aes128gcm\0"),
    16
  );
  const nonce = await hkdf(
    salt,
    ikm,
    enc.encode("Content-Encoding: nonce\0"),
    12
  );
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(nonce) },
      await crypto.subtle.importKey(
        "raw",
        new Uint8Array(cek),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      ),
      new Uint8Array(ciphertext)
    )
  );
  expect(plain[plain.length - 1]).toBe(2);
  return JSON.parse(new TextDecoder().decode(plain.subarray(0, -1)));
}

test("a new request is pushed, encrypted, to the user's devices", async () => {
  await resetDb();
  await signUpWithKey("pb_flow_a");

  const vapid = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const current = env;
  configureEnv({
    ...current,
    VAPID_PUBLIC_KEY: toBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("raw", vapid.publicKey))
    ),
    VAPID_PRIVATE_KEY: (await crypto.subtle.exportKey("jwk", vapid.privateKey))
      .d as string,
    VAPID_SUBJECT: "mailto:ops@example.com",
  });

  try {
    // The device's push subscription.
    const uaKeys = (await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    )) as CryptoKeyPair;
    const uaPublic = new Uint8Array(
      await crypto.subtle.exportKey("raw", uaKeys.publicKey)
    );
    const auth = crypto.getRandomValues(new Uint8Array(16));

    const rejected = await postJson("/app/push/subscribe", {
      endpoint: "https://attacker.example/push",
      keys: { p256dh: toBase64Url(uaPublic), auth: toBase64Url(auth) },
    });
    expect(rejected.status).toBe(400);

    const sub = await postJson("/app/push/subscribe", {
      endpoint: "https://web.push.apple.com/QGuQyavXutnMH",
      keys: { p256dh: toBase64Url(uaPublic), auth: toBase64Url(auth) },
    });
    expect(sub.status).toBe(200);

    pushes.length = 0;
    const created = await createProxyRequest("pb_flow_a");
    expect(pushes.length).toBe(1);
    const push = pushes[0];
    expect(push.headers.get("content-encoding")).toBe("aes128gcm");
    expect(push.headers.get("urgency")).toBe("high");
    expect(push.headers.get("authorization")).toMatch(/^vapid t=/);

    const payload = (await decryptPush({
      body: push.body,
      uaKeys,
      uaPublic,
      auth,
    })) as { title: string; body: string; url: string; tag: string };
    expect(payload.title).toBe("agent requests access");
    expect(payload.body).toContain("GET api.github.com/user");
    expect(payload.url).toBe(`/approve/proxy/${created.request_id}`);
    expect(payload.tag).toBe(`proxy:${created.request_id}`);
  } finally {
    configureEnv(current);
  }
});

test("moving domains: old passkeys work via related origins until moved", async () => {
  await resetDb();
  const current = env;
  const OLD = "https://old.test";

  // An account created while the broker lived on the old domain.
  configureEnv({ ...current, APP_BASE_URL: OLD });
  let userId: string;
  let oldCredentialId: string;
  try {
    const o = await postJson("/passkey/signup/options", {}, { origin: OLD });
    expect(o.status).toBe(200);
    userId = o.json.user_id as string;
    const created = await authenticator.create({
      challenge: (o.json.registration_options as { challenge: string })
        .challenge,
      rpId: "old.test",
      origin: OLD,
    });
    oldCredentialId = created.credential.idB64;
    const prf = await authenticator.prf(
      oldCredentialId,
      fromBase64Url(o.json.prf_salt as string)
    );
    const pair = await PB.generateUserKeypair();
    const wrapped = await PB.wrapPrivateKey(
      await PB.deriveKek(prf, userId),
      pair.privateKey,
      userId
    );
    const v = await postJson(
      "/passkey/signup/verify",
      {
        nonce: o.json.nonce,
        registration: created.response,
        public_key: toBase64Url(pair.publicKeyRaw),
        wrapped_private_key: toBase64Url(wrapped),
      },
      { origin: OLD }
    );
    expect(v.status).toBe(200);
  } finally {
    configureEnv(current);
  }
  await insertApiKey(userId, "pb_flow_a");
  await saveLinkedCredential({
    userId,
    provider: "github",
    providerUserId: "unknown",
    scopes: "repo",
    plaintext: GITHUB_TOKEN,
  });

  // The broker moves to broker.test; old.test becomes the legacy RP ID.
  configureEnv({ ...current, WEBAUTHN_LEGACY_RP_ID: "old.test" });
  try {
    const wellKnown = await app.request(`${OLD}/.well-known/webauthn`);
    expect(await wellKnown.json()).toEqual({ origins: [ORIGIN] });
    const page = await app.request(`${OLD}/app/keys?x=1`);
    expect(page.status).toBe(308);
    expect(page.headers.get("location")).toBe(`${ORIGIN}/app/keys?x=1`);
    const api = await app.request(`${OLD}/v1/whoami`, {
      headers: { authorization: "Bearer pb_flow_a" },
    });
    expect(api.status).toBe(200);
    // The new domain doesn't serve the well-known file itself.
    expect((await app.request(`${ORIGIN}/.well-known/webauthn`)).status).toBe(
      404
    );

    const signinPage = await (await getPage("/app/signin", "")).text();
    expect(signinPage).toContain('data-rp-id="old.test"');

    // Sign in on the new origin with the old-domain passkey.
    sessionCookie = "";
    const so = await postJson("/passkey/signin/options", {});
    const sv = await postJson("/passkey/signin/verify", {
      nonce: so.json.nonce,
      assertion: await authenticator.get({
        credentialId: oldCredentialId,
        challenge: so.json.challenge as string,
      }),
    });
    expect(sv.status).toBe(200);
    sessionCookie = cookieFrom(sv.res);
    expect(await (await getPage("/app")).text()).toContain("Move it to");

    // Approvals keep working with the old passkey (and unlock credentials).
    const first = await createProxyRequest("pb_flow_a");
    const approvalHtml = await (
      await getPage(`/approve/proxy/${first.request_id}`)
    ).text();
    expect(approvalHtml).toContain('"rp_id":"old.test"');
    const approved = await approveViaPage({
      kind: "proxy",
      id: first.request_id as string,
      options: { mode: "once" },
    });
    expect(approved.status).toBe(200);
    expect(
      (await execute("pb_flow_a", first.request_id as string)).status
    ).toBe(200);

    // Move the passkey: unlock with the old one, wrap under a new one.
    const eo = await postJson("/passkey/enroll/options", {});
    const existing = eo.json.existing as {
      credential_id: string;
      rp_id: string;
      prf_salt: string;
      public_key: string;
      wrapped_private_key: string;
    };
    expect(existing.rp_id).toBe("old.test");
    const privateKey = await PB.unwrapPrivateKey(
      await PB.deriveKek(
        await authenticator.prf(
          existing.credential_id,
          fromBase64Url(existing.prf_salt)
        ),
        userId
      ),
      fromBase64Url(existing.wrapped_private_key),
      userId,
      true
    );
    const created = await authenticator.create({
      challenge: (eo.json.registration_options as { challenge: string })
        .challenge,
    });
    const newPrf = await authenticator.prf(
      created.credential.idB64,
      fromBase64Url(eo.json.prf_salt as string)
    );
    const moved = await postJson("/passkey/enroll/verify", {
      nonce: eo.json.nonce,
      mode: "rewrap",
      registration: created.response,
      public_key: existing.public_key,
      wrapped_private_key: toBase64Url(
        await PB.wrapPrivateKey(
          await PB.deriveKek(newPrf, userId),
          privateKey,
          userId
        )
      ),
    });
    expect(moved.status).toBe(200);

    // Now on the new RP ID: no nudge, no legacy sign-in, and approvals
    // (including credential unlock) work with the new passkey.
    expect(await (await getPage("/app")).text()).not.toContain("Move it to");
    expect(await (await getPage("/app/signin", "")).text()).not.toContain(
      "data-rp-id="
    );
    const second = await createProxyRequest("pb_flow_a");
    expect(
      await (await getPage(`/approve/proxy/${second.request_id}`)).text()
    ).toContain('"rp_id":"broker.test"');
    const approvedAgain = await approveViaPage({
      kind: "proxy",
      id: second.request_id as string,
      options: { mode: "once" },
    });
    expect(approvedAgain.status).toBe(200);
    expect(
      (await execute("pb_flow_a", second.request_id as string)).status
    ).toBe(200);

    // The old passkey no longer signs in.
    const lo = await postJson("/passkey/signin/options", {});
    const lv = await postJson("/passkey/signin/verify", {
      nonce: lo.json.nonce,
      assertion: await authenticator.get({
        credentialId: oldCredentialId,
        challenge: lo.json.challenge as string,
      }),
    });
    expect(lv.status).toBe(403);
  } finally {
    configureEnv(current);
  }
});

test("cloudflare connects over OAuth and refreshes with rotation", async () => {
  await resetDb();
  const current = env;
  configureEnv({
    ...current,
    CLOUDFLARE_OAUTH_CLIENT_ID: "cf_client",
    CLOUDFLARE_OAUTH_CLIENT_SECRET: "cf_secret",
  });
  try {
    const userId = await signUpWithKey("pb_flow_a");
    cloudflareTokenRequests.length = 0;
    cloudflareUpstreamAuth.length = 0;

    // The app's Connect link goes to Cloudflare's consent screen.
    const start = await getPage("/app/accounts/connect/cloudflare");
    expect(start.status).toBe(302);
    const authorize = new URL(start.headers.get("location") ?? "");
    expect(authorize.origin + authorize.pathname).toBe(
      "https://dash.cloudflare.com/oauth2/auth"
    );
    expect(authorize.searchParams.get("client_id")).toBe("cf_client");
    expect(authorize.searchParams.get("redirect_uri")).toBe(
      `${ORIGIN}/v1/accounts/callback/cloudflare`
    );
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    const scope = authorize.searchParams.get("scope") ?? "";
    expect(scope).toContain("offline_access");
    expect(scope).toContain("workers-scripts.edit");

    // Cloudflare redirects back (with its RFC 9207 issuer).
    const state = authorize.searchParams.get("state") ?? "";
    const callback = await app.request(
      `/v1/accounts/callback/cloudflare?code=abc&state=${encodeURIComponent(state)}&iss=${encodeURIComponent("https://dash.cloudflare.com")}`
    );
    expect(callback.status).toBe(200);
    expect(await callback.text()).toContain("Connected cloudflare");
    expect(cloudflareTokenRequests[0]?.get("grant_type")).toBe(
      "authorization_code"
    );
    expect(cloudflareTokenRequests[0]?.get("code_verifier")).toBeTruthy();

    // Account names are stored as display metadata.
    const accounts = await app.request("/v1/accounts", {
      headers: { authorization: "Bearer pb_flow_a" },
    });
    expect(JSON.stringify(await accounts.json())).toContain("Main account");
    expect(await (await getPage("/app/accounts")).text()).toContain(
      "Main account"
    );

    // A passkey-approved request refreshes and uses the new access token.
    const upstream =
      "https://api.cloudflare.com/client/v4/accounts/acc_1/workers/scripts";
    for (const expectedRefresh of ["cf_rt_1", "cf_rt_2"]) {
      const created = await createProxyRequest(
        "pb_flow_a",
        "203.0.113.7",
        upstream
      );
      const approved = await approveViaPage({
        kind: "proxy",
        id: created.request_id as string,
        options: { mode: "once" },
      });
      expect(approved.status).toBe(200);
      cloudflareUpstreamAuth.length = 0;
      const res = await execute("pb_flow_a", created.request_id as string);
      expect(res.status).toBe(200);
      const refresh = cloudflareTokenRequests.at(-1);
      expect(refresh?.get("grant_type")).toBe("refresh_token");
      // The rotated refresh token from the previous refresh is used next.
      expect(refresh?.get("refresh_token")).toBe(expectedRefresh);
      expect(cloudflareUpstreamAuth).toEqual([
        `Bearer cf_at_${cloudflareTokenCounter}`,
      ]);
    }
    expect(userId).toBeTruthy();
  } finally {
    configureEnv(current);
  }
});
