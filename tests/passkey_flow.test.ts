import { afterAll, beforeAll, expect, test } from "bun:test";
import { ulid } from "ulid";

import { createApp } from "../src/app";
import { createConnectState } from "../src/connect/state";
import { saveLinkedCredential } from "../src/credentials/store";
import { encryptUtf8 } from "../src/crypto/aesgcm";
import { fromBase64Url, toBase64Url, toBytes } from "../src/crypto/bytes";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, type Env, env } from "../src/env";
import { CLIENT_CRYPTO_JS } from "../src/passkey/clientCrypto";
import { approvalLinkToken } from "../src/passkey/webauthn";
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

await migrate();

beforeAll(() => {
  prevEnv = env;
  configureEnv({
    ...env,
    APP_BASE_URL: ORIGIN,
    APP_SECRET: "test-app-secret",
    PB_TEST_BYPASS_OAUTH: false,
  });
  // Stub the upstream provider; record the injected credential.
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit
  ) => {
    const url = new URL(
      input instanceof Request ? input.url : input.toString()
    );
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

async function postJson(path: string, body: unknown, headers = {}) {
  const res = await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as JsonRecord };
}

async function resetDb() {
  const database = await db();
  for (const table of [
    "credential_grants",
    "approval_windows",
    "webauthn_challenges",
    "approvals",
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

async function insertUserWithKey(keyPlain: string): Promise<string> {
  const database = await db();
  const userId = ulid();
  const now = new Date().toISOString();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, Math.floor(Math.random() * 1e9), now);
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, 'agent', ?, ?, ?, NULL, NULL);"
    )
    .run(ulid(), userId, await sha256Hex(keyPlain), now, now);
  return userId;
}

type Enrolled = {
  userId: string;
  credentialId: string;
  prfSalt: Uint8Array;
};

async function enroll(userId: string): Promise<Enrolled> {
  const { state } = await createConnectState({
    userId,
    provider: "passkey",
    ttlMs: 60_000,
  });
  const page = await app.request(`/passkey/enroll?state=${state}`);
  expect(page.status).toBe(200);
  expect(page.headers.get("content-security-policy")).toContain(
    "script-src 'nonce-"
  );

  const o = await postJson("/passkey/enroll/options", { state });
  expect(o.status).toBe(200);
  const opts = o.json.registration_options as { challenge: string };
  const prfSalt = fromBase64Url(o.json.prf_salt as string);

  const created = await authenticator.create({ challenge: opts.challenge });
  const prf = await authenticator.prf(created.credential.idB64, prfSalt);
  const kek = await PB.deriveKek(prf, userId);
  const pair = await PB.generateUserKeypair();
  const wrapped = await PB.wrapPrivateKey(kek, pair.privateKey, userId);

  const v = await postJson("/passkey/enroll/verify", {
    state,
    nonce: o.json.nonce,
    mode: "new",
    registration: created.response,
    public_key: toBase64Url(pair.publicKeyRaw),
    wrapped_private_key: toBase64Url(wrapped),
  });
  expect(v.status).toBe(200);
  expect(v.json.ok).toBe(true);

  return { userId, credentialId: created.credential.idB64, prfSalt };
}

type PageData = {
  t: string;
  user_id: string;
  passkey: {
    credential_id: string;
    prf_salt: string;
    wrapped_private_key: string;
  };
  credential: { linked_account_id: string; epk: string } | null;
};

async function loadApprovalPage(kind: string, id: string): Promise<PageData> {
  const t = await approvalLinkToken({ kind, id });
  const res = await app.request(`/approve/${kind}/${id}?t=${t}`);
  expect(res.status).toBe(200);
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
    t: data.t,
    options: params.options,
  });
  expect(ch.status).toBe(200);

  const assertion = await authenticator.get({
    credentialId: data.passkey.credential_id,
    challenge: ch.json.challenge as string,
  });
  const body: JsonRecord = { t: data.t, nonce: ch.json.nonce, assertion };

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

async function createProxyRequest(keyPlain: string, ip = "203.0.113.7") {
  const res = await postJson(
    "/v1/proxy/request",
    { upstream_url: "https://api.github.com/user", method: "GET" },
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

test("enrollment migrates legacy APP_SECRET credentials", async () => {
  await resetDb();
  const userId = await insertUserWithKey("pb_flow_a");

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

  await enroll(userId);

  const row = await githubAccountRow(userId);
  expect(row.enc_version).toBe(1);
  expect(row.credential_epk).not.toBeNull();
});

test("proxy request: passkey approval unlocks, executes once, rotates", async () => {
  await resetDb();
  const userId = await insertUserWithKey("pb_flow_a");
  await enroll(userId);
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
  const userId = await insertUserWithKey("pb_flow_a");
  await enroll(userId);
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

test("approval page rejects a missing or wrong link token", async () => {
  await resetDb();
  const userId = await insertUserWithKey("pb_flow_a");
  await enroll(userId);
  const created = await createProxyRequest("pb_flow_a");
  const requestId = created.request_id as string;

  expect((await app.request(`/approve/proxy/${requestId}`)).status).toBe(404);
  expect((await app.request(`/approve/proxy/${requestId}?t=AAAA`)).status).toBe(
    404
  );
});

test("approval window auto-approves the endpoint and survives rotation", async () => {
  await resetDb();
  const userId = await insertUserWithKey("pb_flow_a");
  await enroll(userId);
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
    options: { mode: "window", minutes: 15 },
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

test("connecting an account requires an enrolled passkey", async () => {
  await resetDb();
  const userId = await insertUserWithKey("pb_flow_a");
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
  const userId = await insertUserWithKey("pb_flow_a");
  await enroll(userId);
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
