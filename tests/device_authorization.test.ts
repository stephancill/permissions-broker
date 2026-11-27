import { expect, test } from "bun:test";
import { ulid } from "ulid";

import { createApp } from "../src/app";
import { sweepExpiredApiKeys } from "../src/auth/apiKeyAdmin";
import { normalizeUserCode } from "../src/auth/device";
import { randomBase64Url } from "../src/crypto/random";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, env } from "../src/env";

const ORIGIN = "https://broker.test";
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";

await migrate();
configureEnv({ ...env, APP_BASE_URL: ORIGIN, APP_SECRET: "test-app-secret" });

const app = createApp();

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

async function authorize(body: Record<string, string> = {}) {
  const res = await app.request(`${ORIGIN}/v1/device/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
  expect(res.status).toBe(200);
  expect(res.headers.get("cache-control")).toBe("no-store");
  return (await res.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
  };
}

async function poll(deviceCode: string, headers: Record<string, string> = {}) {
  const res = await app.request(`${ORIGIN}/v1/device/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams({
      grant_type: GRANT,
      device_code: deviceCode,
    }).toString(),
  });
  return { status: res.status, json: (await res.json()) as JsonBody };
}

type JsonBody = Record<string, string>;

async function resetPoll(deviceCode: string): Promise<void> {
  const database = await db();
  await database
    .query(
      "UPDATE device_authorizations SET last_polled_at = NULL WHERE device_code_hash = ?;"
    )
    .run(await sha256Hex(deviceCode));
}

function pagePost(params: {
  path: string;
  cookie: string;
  form: Record<string, string>;
}) {
  return app.request(`${ORIGIN}${params.path}`, {
    method: "POST",
    headers: {
      cookie: params.cookie,
      origin: ORIGIN,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params.form).toString(),
  });
}

test("normalizeUserCode accepts sloppy input and rejects ambiguous letters", () => {
  expect(normalizeUserCode("bcdf ghjk")).toBe("BCDF-GHJK");
  expect(normalizeUserCode("BCDF-GHJK")).toBe("BCDF-GHJK");
  expect(normalizeUserCode("ABCD-EFGH")).toBeNull();
  expect(normalizeUserCode("BCDF")).toBeNull();
});

test("device flow issues an API key after approval", async () => {
  const { cookie } = await signedInUser();
  const auth = await authorize({ client_id: "pb-cli", label: "laptop" });
  expect(auth.user_code).toMatch(/^[B-Z]{4}-[B-Z]{4}$/);
  expect(auth.verification_uri).toBe(`${ORIGIN}/device`);
  expect(auth.verification_uri_complete).toContain(auth.user_code);
  expect(auth.interval).toBe(5);

  expect((await poll(auth.device_code)).json.error).toBe(
    "authorization_pending"
  );
  // Polling again inside the interval slows the client down.
  expect((await poll(auth.device_code)).json.error).toBe("slow_down");

  // /device lands on the app page, which needs a session.
  const redirect = await app.request(
    `${ORIGIN}/device?user_code=${auth.user_code}`
  );
  expect(redirect.headers.get("location")).toBe(
    `/app/device?user_code=${auth.user_code}`
  );
  const anon = await app.request(
    `${ORIGIN}/app/device?user_code=${auth.user_code}`
  );
  expect(anon.status).toBe(302);
  expect(anon.headers.get("location")).toContain("/app/signin");

  const page = await app.request(
    `${ORIGIN}/app/device?user_code=${auth.user_code.toLowerCase()}`,
    { headers: { cookie } }
  );
  expect(page.status).toBe(200);
  const html = await page.text();
  expect(html).toContain(auth.user_code);
  expect(html).toContain('value="laptop"');

  const approved = await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: auth.user_code, label: "my laptop" },
  });
  expect(approved.status).toBe(200);
  expect(await approved.text()).toContain("Device signed in");

  await resetPoll(auth.device_code);
  const done = await poll(auth.device_code);
  expect(done.status).toBe(200);
  expect(done.json.token_type).toBe("Bearer");
  expect(done.json.api_key_label).toBe("my laptop");
  expect(done.json.access_token).toMatch(/^pb_/);

  const whoami = await app.request(`${ORIGIN}/v1/whoami`, {
    headers: { authorization: `Bearer ${done.json.access_token}` },
  });
  expect(whoami.status).toBe(200);
  expect(((await whoami.json()) as JsonBody).api_key_label).toBe("my laptop");

  // The device code is single-use.
  await resetPoll(auth.device_code);
  expect((await poll(auth.device_code)).json.error).toBe("invalid_grant");
});

test("denied codes return access_denied", async () => {
  const { cookie } = await signedInUser();
  const auth = await authorize();
  const denied = await pagePost({
    path: "/app/device/deny",
    cookie,
    form: { user_code: auth.user_code },
  });
  expect(denied.status).toBe(200);
  expect((await poll(auth.device_code)).json.error).toBe("access_denied");
});

test("approval rejects a label that is already in use", async () => {
  const { cookie } = await signedInUser();
  const first = await authorize();
  await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: first.user_code, label: "dup" },
  });
  expect((await poll(first.device_code)).status).toBe(200);

  const second = await authorize();
  const res = await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: second.user_code, label: "dup" },
  });
  expect(res.status).toBe(400);
  expect(await res.text()).toContain("already exists");
  expect((await poll(second.device_code)).json.error).toBe(
    "authorization_pending"
  );
});

test("expired codes return expired_token and can't be approved", async () => {
  const { cookie } = await signedInUser();
  const auth = await authorize();
  const database = await db();
  await database
    .query(
      "UPDATE device_authorizations SET expires_at = ? WHERE device_code_hash = ?;"
    )
    .run(
      new Date(Date.now() - 1000).toISOString(),
      await sha256Hex(auth.device_code)
    );
  expect((await poll(auth.device_code)).json.error).toBe("expired_token");
  const res = await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: auth.user_code, label: "late" },
  });
  expect(res.status).toBe(400);
});

test("token endpoint rejects other grant types", async () => {
  const res = await app.request(`${ORIGIN}/v1/device/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  expect(res.status).toBe(400);
  expect(((await res.json()) as JsonBody).error).toBe("unsupported_grant_type");
});

test("session keys expire after 6 hours and are swept", async () => {
  const { userId, cookie } = await signedInUser();
  const auth = await authorize({ label: "claude", key_type: "session" });

  const page = await app.request(
    `${ORIGIN}/app/device?user_code=${auth.user_code}`,
    { headers: { cookie } }
  );
  expect(await page.text()).toContain(
    "<b>session key</b> that expires 6 hours"
  );

  await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: auth.user_code, label: "claude" },
  });
  const before = Date.now();
  const done = await poll(auth.device_code, {
    "cf-connecting-ip": "203.0.113.9",
    "cf-ipcountry": "ZA",
    "user-agent": "stupid-vault-cli/1.0",
  });
  expect(done.status).toBe(200);
  expect(done.json.key_type).toBe("session");
  const expiresAt = Date.parse(done.json.expires_at);
  expect(expiresAt - before).toBeGreaterThan(6 * 3600_000 - 5_000);
  expect(expiresAt - before).toBeLessThanOrEqual(6 * 3600_000 + 5_000);
  expect(Number(done.json.expires_in)).toBeGreaterThan(6 * 3600 - 5);

  const token = done.json.access_token;
  const who = await app.request(`${ORIGIN}/v1/whoami`, {
    headers: {
      authorization: `Bearer ${token}`,
      "cf-connecting-ip": "198.51.100.4",
      "user-agent": "curl/8.4",
    },
  });
  const whoJson = (await who.json()) as JsonBody;
  expect(whoJson.key_type).toBe("session");
  expect(whoJson.expires_at).toBe(done.json.expires_at);

  // The keys page shows the session key and its audit trail.
  const keys = await (
    await app.request(`${ORIGIN}/app/keys`, { headers: { cookie } })
  ).text();
  expect(keys).toMatch(/Session key · expires in (5 h 59|6 h 0) min/);
  expect(keys).toContain("from ZA (203.0.113.9)");
  expect(keys).toContain("stupid-vault-cli/1.0");
  expect(keys).toContain("from 198.51.100.4");
  expect(keys).toContain("curl/8.4");
  expect(keys).not.toContain("/rotate");

  // The next sign-in with the same suggested label gets a free one.
  const next = await authorize({ label: "claude", key_type: "session" });
  const nextPage = await app.request(
    `${ORIGIN}/app/device?user_code=${next.user_code}`,
    { headers: { cookie } }
  );
  expect(await nextPage.text()).toContain('value="claude 2"');

  // Past expiry the key stops working, and the sweeper deletes it.
  const database = await db();
  await database
    .query("UPDATE api_keys SET expires_at = ? WHERE key_hash = ?;")
    .run(new Date(Date.now() - 1000).toISOString(), await sha256Hex(token));
  const expired = await app.request(`${ORIGIN}/v1/whoami`, {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(expired.status).toBe(401);
  expect(((await expired.json()) as JsonBody).error).toBe("api_key_expired");

  await sweepExpiredApiKeys();
  const left = await database
    .query("SELECT label FROM api_keys WHERE user_id = ?;")
    .all<{ label: string }>(userId);
  expect(left).toEqual([]);
});

test("device keys default to persistent", async () => {
  const { cookie } = await signedInUser();
  const auth = await authorize({ label: "server" });
  await pagePost({
    path: "/app/device/approve",
    cookie,
    form: { user_code: auth.user_code, label: "server" },
  });
  const done = await poll(auth.device_code);
  expect(done.json.key_type).toBe("persistent");
  expect(done.json.expires_at).toBeUndefined();
});
