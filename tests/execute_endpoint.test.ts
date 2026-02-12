import { expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { proxyRouter } from "../src/web/proxy";

type JsonRecord = Record<string, unknown>;

function nowIso(): string {
  return new Date().toISOString();
}

async function setupDb() {
  // Ensure clean slate for this test file.
  db().exec("DELETE FROM approvals;");
  db().exec("DELETE FROM proxy_requests;");
  db().exec("DELETE FROM linked_accounts;");
  db().exec("DELETE FROM api_keys;");
  db().exec("DELETE FROM users;");
}

// Create schema once for this test file.
migrate();

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

async function insertApprovedRequest(params: {
  userId: string;
  apiKeyId: string;
  apiKeyLabel: string;
  upstreamUrl: string;
}): Promise<string> {
  const id = ulid();
  const now = nowIso();
  const approvalExpiresAt = new Date(Date.now() + 120_000).toISOString();
  db()
    .query(
      "INSERT INTO proxy_requests (id, user_id, api_key_id, api_key_label_snapshot, upstream_url, request_hash, consent_hint, status, created_at, updated_at, approval_expires_at, idempotency_key, upstream_http_status, upstream_content_type, upstream_bytes, result_state, error_code, error_message) " +
        "VALUES (?, ?, ?, ?, ?, ?, NULL, 'APPROVED', ?, ?, ?, NULL, NULL, NULL, NULL, 'NONE', NULL, NULL);"
    )
    .run(
      id,
      params.userId,
      params.apiKeyId,
      params.apiKeyLabel,
      params.upstreamUrl,
      "hash",
      now,
      now,
      approvalExpiresAt
    );
  return id;
}

function app() {
  const a = new Hono();
  a.route("/v1/proxy", proxyRouter);
  return a;
}

test("execute endpoint architecture", async () => {
  await setupDb();

  // Case 1: exact key enforcement
  {
    const upstream = Bun.serve({
      port: 0,
      fetch() {
        return new Response("ok", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      },
    });

    const userId = await insertUser();
    const keyA = await insertApiKey({
      userId,
      label: "keyA",
      keyPlain: "pb_test_key_a",
    });
    await insertApiKey({
      userId,
      label: "keyB",
      keyPlain: "pb_test_key_b",
    });

    const reqId = await insertApprovedRequest({
      userId,
      apiKeyId: keyA.apiKeyId,
      apiKeyLabel: "keyA",
      upstreamUrl: `http://127.0.0.1:${upstream.port}/`,
    });

    const res1 = await app().request(`/v1/proxy/requests/${reqId}`, {
      headers: { authorization: "Bearer pb_test_key_b" },
    });
    expect(res1.status).toBe(403);
    expect(((await res1.json()) as JsonRecord).error).toBe("forbidden");

    const res2 = await app().request(`/v1/proxy/requests/${reqId}/execute`, {
      method: "POST",
      headers: { authorization: "Bearer pb_test_key_b" },
    });
    expect(res2.status).toBe(403);
    expect(((await res2.json()) as JsonRecord).error).toBe("forbidden");

    upstream.stop();
  }

  await setupDb();

  // Case 2: execute 2xx => SUCCEEDED, second execute => 410, status-only endpoint is JSON
  {
    const upstream = Bun.serve({
      port: 0,
      fetch() {
        return new Response("hello", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      },
    });

    const userId = await insertUser();
    const keyA = await insertApiKey({
      userId,
      label: "keyA",
      keyPlain: "pb_test_key_a",
    });

    const reqId = await insertApprovedRequest({
      userId,
      apiKeyId: keyA.apiKeyId,
      apiKeyLabel: "keyA",
      upstreamUrl: `http://127.0.0.1:${upstream.port}/`,
    });

    const pre = db()
      .query("SELECT status, api_key_id FROM proxy_requests WHERE id = ?;")
      .get(reqId) as { status: string; api_key_id: string };
    expect(pre.status).toBe("APPROVED");
    expect(pre.api_key_id).toBe(keyA.apiKeyId);

    const exec1 = await app().request(`/v1/proxy/requests/${reqId}/execute`, {
      method: "POST",
      headers: { authorization: "Bearer pb_test_key_a" },
    });
    expect(exec1.status).toBe(200);
    expect(await exec1.text()).toBe("hello");

    const statusRes = await app().request(`/v1/proxy/requests/${reqId}`, {
      headers: { authorization: "Bearer pb_test_key_a" },
    });
    expect(statusRes.status).toBe(200);
    expect(statusRes.headers.get("content-type") ?? "").toContain(
      "application/json"
    );
    const statusJson = (await statusRes.json()) as JsonRecord;
    expect(statusJson.status).toBe("SUCCEEDED");
    expect(statusJson.upstream_http_status).toBe(200);

    const exec2 = await app().request(`/v1/proxy/requests/${reqId}/execute`, {
      method: "POST",
      headers: { authorization: "Bearer pb_test_key_a" },
    });
    expect(exec2.status).toBe(410);
    expect(((await exec2.json()) as JsonRecord).error).toBe("already_executed");

    upstream.stop();
  }

  await setupDb();

  // Case 3: non-2xx upstream => FAILED, but execute returns upstream bytes
  {
    const upstream = Bun.serve({
      port: 0,
      fetch() {
        return new Response("nope", {
          status: 404,
          headers: { "content-type": "text/plain" },
        });
      },
    });

    const userId = await insertUser();
    const keyA = await insertApiKey({
      userId,
      label: "keyA",
      keyPlain: "pb_test_key_a",
    });

    const reqId = await insertApprovedRequest({
      userId,
      apiKeyId: keyA.apiKeyId,
      apiKeyLabel: "keyA",
      upstreamUrl: `http://127.0.0.1:${upstream.port}/`,
    });

    const exec = await app().request(`/v1/proxy/requests/${reqId}/execute`, {
      method: "POST",
      headers: { authorization: "Bearer pb_test_key_a" },
    });
    expect(exec.status).toBe(404);
    expect(await exec.text()).toBe("nope");

    const statusRes = await app().request(`/v1/proxy/requests/${reqId}`, {
      headers: { authorization: "Bearer pb_test_key_a" },
    });
    const j = (await statusRes.json()) as JsonRecord;
    expect(j.status).toBe("FAILED");
    expect(j.error_code).toBe("UPSTREAM_HTTP_404");
    expect(j.upstream_http_status).toBe(404);

    upstream.stop();
  }
});
