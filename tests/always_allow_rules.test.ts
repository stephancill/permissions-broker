import { expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { upsertAlwaysAllowRule } from "../src/proxy/alwaysAllow";
import { proxyRouter } from "../src/web/proxy";

type JsonRecord = Record<string, unknown>;

function nowIso(): string {
  return new Date().toISOString();
}

// Create schema once for this test file.
migrate();

async function setupDb() {
  db().exec("DELETE FROM approvals;");
  db().exec("DELETE FROM proxy_requests;");
  db().exec("DELETE FROM proxy_always_allow_rules;");
  db().exec("DELETE FROM linked_accounts;");
  db().exec("DELETE FROM api_keys;");
  db().exec("DELETE FROM users;");
}

async function insertUser(telegramUserId = 123): Promise<string> {
  const id = ulid();
  db()
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
  db()
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

test("always allow: /request auto-approves matching endpoints", async () => {
  await setupDb();

  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_test_key_a",
  });

  // Create permanent allow rule for GET api.github.com/user, scoped to key/IP.
  upsertAlwaysAllowRule({
    userId,
    apiKeyId: keyA.apiKeyId,
    requesterIp: "203.0.113.10",
    method: "GET",
    url: new URL("https://api.github.com/user"),
  });

  const res = await app().request("/v1/proxy/request", {
    method: "POST",
    // Simulate a proxied deployment that passes through the client IP.
    headers: {
      authorization: "Bearer pb_test_key_a",
      "content-type": "application/json",
      "x-forwarded-for": "203.0.113.10",
    },
    body: JSON.stringify({
      upstream_url: "https://api.github.com/user",
      method: "GET",
    }),
  });

  expect(res.status).toBe(200);
  const j = (await res.json()) as JsonRecord;
  expect(j.status).toBe("APPROVED");

  const row = db()
    .query("SELECT status FROM proxy_requests WHERE id = ? LIMIT 1;")
    .get(j.request_id as string) as { status: string };
  expect(row.status).toBe("APPROVED");
});
