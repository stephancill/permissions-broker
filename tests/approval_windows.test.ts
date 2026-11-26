import { expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { createApprovalWindow } from "../src/proxy/approvalWindows";
import { proxyRouter } from "../src/web/proxy";

type JsonRecord = Record<string, unknown>;

function nowIso(): string {
  return new Date().toISOString();
}

// Create schema once for this test file.
await migrate();

async function setupDb() {
  const database = await db();
  await database.exec("DELETE FROM proxy_requests;");
  await database.exec("DELETE FROM approval_windows;");
  await database.exec("DELETE FROM linked_accounts;");
  await database.exec("DELETE FROM api_keys;");
  await database.exec("DELETE FROM users;");
}

async function insertUser(telegramUserId = 123): Promise<string> {
  const id = ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, ?);"
    )
    .run(id, telegramUserId, nowIso(), "active");
  return id;
}

async function insertApiKey(params: {
  userId: string;
  label: string;
  keyPlain: string;
}): Promise<{ apiKeyId: string; keyHash: string }> {
  const apiKeyId = ulid();
  const keyHash = await sha256Hex(params.keyPlain);
  const now = nowIso();
  const database = await db();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(apiKeyId, params.userId, params.label, keyHash, now, now);
  return { apiKeyId, keyHash };
}

function app() {
  const a = new Hono();
  a.route("/v1/proxy", proxyRouter);
  return a;
}

async function requestGithubUser(ip: string) {
  return requestUpstream({ ip, upstreamUrl: "https://api.github.com/user" });
}

async function requestUpstream(params: {
  ip: string | null;
  upstreamUrl: string;
  method?: string;
  key?: string;
}) {
  const headers: Record<string, string> = {
    authorization: `Bearer ${params.key ?? "pb_test_key_a"}`,
    "content-type": "application/json",
  };
  // Simulate a proxied deployment that passes through the client IP.
  if (params.ip) headers["x-forwarded-for"] = params.ip;
  return app().request("/v1/proxy/request", {
    method: "POST",
    headers,
    body: JSON.stringify({
      upstream_url: params.upstreamUrl,
      method: params.method ?? "GET",
    }),
  });
}

test("approval window: /request auto-approves matching endpoints", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  // Window for GET api.github.com/user, scoped to key/IP.
  const { windowId } = await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
    scope: "endpoint",
    providerId: "github",
    grantId: "grant_test",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  });

  const res = await requestGithubUser("203.0.113.10");
  expect(res.status).toBe(200);
  const j = (await res.json()) as JsonRecord;
  expect(j.status).toBe("APPROVED");

  const database = await db();
  const row = (await database
    .query("SELECT status, grant_id FROM proxy_requests WHERE id = ? LIMIT 1;")
    .get(j.request_id as string)) as { status: string; grant_id: string };
  expect(row.status).toBe("APPROVED");
  expect(row.grant_id).toBe("grant_test");

  // Other requester IPs still need approval.
  const other = await requestGithubUser("198.51.100.1");
  expect(((await other.json()) as JsonRecord).status).toBe("PENDING_APPROVAL");
  expect(windowId).toBeTruthy();
});

test("approval window: expired windows do not auto-approve", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
    scope: "endpoint",
    providerId: "github",
    grantId: null,
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });

  const res = await requestGithubUser("203.0.113.10");
  expect(((await res.json()) as JsonRecord).status).toBe("PENDING_APPROVAL");
});

test("approval window: provider scope auto-approves any endpoint for that provider", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
    scope: "provider",
    providerId: "github",
    grantId: "grant_provider",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  });

  const database = await db();
  const windowRow = (await database
    .query(
      "SELECT method, upstream_host, upstream_path FROM approval_windows LIMIT 1;"
    )
    .get()) as { method: string; upstream_host: string; upstream_path: string };
  expect(windowRow).toEqual({
    method: "*",
    upstream_host: "*",
    upstream_path: "*",
  });

  // Different method + path on the same provider.
  const res = await requestUpstream({
    ip: "203.0.113.10",
    upstreamUrl: "https://api.github.com/repos/octo/hello/issues",
    method: "POST",
  });
  expect(res.status).toBe(200);
  const j = (await res.json()) as JsonRecord;
  expect(j.status).toBe("APPROVED");
  const row = (await database
    .query("SELECT grant_id FROM proxy_requests WHERE id = ? LIMIT 1;")
    .get(j.request_id as string)) as { grant_id: string };
  expect(row.grant_id).toBe("grant_provider");
});

test("approval window: provider scope is not tied to the requester IP", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });
  await insertApiKey({ userId, label: "keyB", keyPlain: "pb_test_key_b" });

  await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.cloudflare.com/client/v4/zones"),
    scope: "provider",
    providerId: "cloudflare",
    grantId: "grant_provider",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  });

  const database = await db();
  const stored = (await database
    .query("SELECT requester_ip FROM approval_windows LIMIT 1;")
    .get()) as { requester_ip: string };
  expect(stored.requester_ip).toBe("*");

  // Agents egress from rotating IPs; a different IP is still covered.
  const otherIp = await requestUpstream({
    ip: "198.51.100.1",
    upstreamUrl: "https://api.cloudflare.com/client/v4/accounts",
  });
  expect(((await otherIp.json()) as JsonRecord).status).toBe("APPROVED");

  // As is a deployment that passes no client IP.
  const noIp = await requestUpstream({
    ip: null,
    upstreamUrl: "https://api.cloudflare.com/client/v4/zones",
  });
  expect(((await noIp.json()) as JsonRecord).status).toBe("APPROVED");

  // Still scoped to the API key.
  const otherKey = await requestUpstream({
    ip: "203.0.113.10",
    upstreamUrl: "https://api.cloudflare.com/client/v4/zones",
    key: "pb_test_key_b",
  });
  expect(((await otherKey.json()) as JsonRecord).status).toBe(
    "PENDING_APPROVAL"
  );
});

test("approval window: endpoint scope stays tied to the requester IP", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
    scope: "endpoint",
    providerId: "github",
    grantId: "grant_test",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  });

  const other = await requestGithubUser("198.51.100.1");
  expect(((await other.json()) as JsonRecord).status).toBe("PENDING_APPROVAL");
});

test("approval window: provider scope does not cover other providers", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  await createApprovalWindow({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
    scope: "provider",
    providerId: "some-other-provider",
    grantId: null,
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  });

  const res = await requestGithubUser("203.0.113.10");
  expect(((await res.json()) as JsonRecord).status).toBe("PENDING_APPROVAL");
});

test("approval window: endpoint scope requires a requester ip", async () => {
  await expect(
    createApprovalWindow({
      userId: "u",
      apiKeyId: "k",
      requesterIp: null,
      method: "GET",
      url: new URL("https://api.github.com/user"),
      scope: "endpoint",
      providerId: "github",
      grantId: null,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    })
  ).rejects.toThrow();
});

test("approval window: provider scope requires a provider id", async () => {
  await expect(
    createApprovalWindow({
      userId: "u",
      apiKeyId: "k",
      requesterIp: "203.0.113.10",
      method: "GET",
      url: new URL("https://api.github.com/user"),
      scope: "provider",
      providerId: null,
      grantId: null,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    })
  ).rejects.toThrow();
});
