import { expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import { encryptUtf8 } from "../src/crypto/aesgcm";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { serializeCredential } from "../src/email/credential";
import { buildSearchObject, type EmailSearchQuery } from "../src/email/ops";
import {
  createEmailSession,
  setEmailSessionStatus,
} from "../src/email/sessions";
import { configureEnv, env } from "../src/env";
import { emailRouter } from "../src/web/email";

type JsonRecord = Record<string, unknown>;

function nowIso(): string {
  return new Date().toISOString();
}

// Create schema once for this test file.
await migrate();
// Email credentials are encrypted at rest; tests need APP_SECRET configured.
configureEnv({ ...env, APP_SECRET: "test-app-secret" });

async function setupDb() {
  const database = await db();
  await database.exec("DELETE FROM email_sessions;");
  await database.exec("DELETE FROM linked_accounts;");
  await database.exec("DELETE FROM api_keys;");
  await database.exec("DELETE FROM users;");
  await database.exec("DELETE FROM connect_states;");
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
}): Promise<string> {
  const apiKeyId = ulid();
  const keyHash = await sha256Hex(params.keyPlain);
  const now = nowIso();
  const database = await db();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(apiKeyId, params.userId, params.label, keyHash, now, now);
  return apiKeyId;
}

async function insertLinkedImapAccount(params: {
  userId: string;
}): Promise<void> {
  const id = ulid();
  const credential = serializeCredential({
    email: "user@example.com",
    password: "secret",
    host: "imap.example.com",
    port: 993,
    secure: true,
  });
  const ct = await encryptUtf8(credential);
  const database = await db();
  await database
    .query(
      "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, 'imap', ?, 'read', ?, 'active', ?, NULL);"
    )
    .run(id, params.userId, await sha256Hex("user@example.com"), ct, nowIso());
}

function app() {
  const a = new Hono();
  a.route("/v1/email", emailRouter);
  return a;
}

test("create session requires a linked imap account", async () => {
  await setupDb();
  const userId = await insertUser();
  await insertApiKey({ userId, label: "keyA", keyPlain: "pb_email_a" });

  const res = await app().request("/v1/email/sessions", {
    method: "POST",
    headers: { authorization: "Bearer pb_email_a" },
    body: JSON.stringify({}),
  });
  expect(res.status).toBe(409);
  expect(((await res.json()) as JsonRecord).error).toBe("no_linked_imap");
});

test("create session returns PENDING_APPROVAL and polls as pending", async () => {
  await setupDb();
  const userId = await insertUser();
  await insertApiKey({ userId, label: "keyA", keyPlain: "pb_email_a" });
  await insertLinkedImapAccount({ userId });

  const res = await app().request("/v1/email/sessions", {
    method: "POST",
    headers: {
      authorization: "Bearer pb_email_a",
      "content-type": "application/json",
    },
    body: JSON.stringify({ consent_hint: "check my inbox" }),
  });
  expect(res.status).toBe(200);
  const created = (await res.json()) as JsonRecord;
  expect(created.session_id).toBeTypeOf("string");
  expect(created.status).toBe("PENDING_APPROVAL");
  expect(created.read_only).toBe(true);

  const poll = await app().request(
    `/v1/email/sessions/${created.session_id as string}`,
    { headers: { authorization: "Bearer pb_email_a" } }
  );
  expect(poll.status).toBe(200);
  const polled = (await poll.json()) as JsonRecord;
  expect(polled.status).toBe("PENDING_APPROVAL");
});

test("read endpoints reject while session awaits approval", async () => {
  await setupDb();
  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_email_a",
  });
  await insertLinkedImapAccount({ userId });

  const created = await createEmailSession({
    userId,
    apiKeyId: keyA,
    approvalTtlMs: 600_000,
  });

  const folders = await app().request(
    `/v1/email/sessions/${created.sessionId}/folders`,
    { headers: { authorization: "Bearer pb_email_a" } }
  );
  expect(folders.status).toBe(202);
  expect(((await folders.json()) as JsonRecord).error).toBe("pending_approval");
});

test("session is scoped to the exact API key that created it", async () => {
  await setupDb();
  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_email_a",
  });
  await insertApiKey({ userId, label: "keyB", keyPlain: "pb_email_b" });
  await insertLinkedImapAccount({ userId });

  const created = await createEmailSession({
    userId,
    apiKeyId: keyA,
    approvalTtlMs: 600_000,
  });

  const res = await app().request(`/v1/email/sessions/${created.sessionId}`, {
    headers: { authorization: "Bearer pb_email_b" },
  });
  expect(res.status).toBe(403);
  expect(((await res.json()) as JsonRecord).error).toBe("forbidden");
});

test("approved session proceeds past the gate before connecting", async () => {
  await setupDb();
  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_email_a",
  });
  await insertLinkedImapAccount({ userId });

  const created = await createEmailSession({
    userId,
    apiKeyId: keyA,
    approvalTtlMs: 600_000,
  });
  await setEmailSessionStatus({
    sessionId: created.sessionId,
    userId,
    status: "APPROVED",
  });

  // Delete the linked account: the denyless gate passes (APPROVED -> ACTIVE),
  // then the operation fails loudly with no_linked_imap instead of attempting
  // an IMAP connection.
  const database = await db();
  await database
    .query("DELETE FROM linked_accounts WHERE user_id = ?;")
    .run(userId);

  const folders = await app().request(
    `/v1/email/sessions/${created.sessionId}/folders`,
    { headers: { authorization: "Bearer pb_email_a" } }
  );
  expect(folders.status).toBe(409);
  expect(((await folders.json()) as JsonRecord).error).toBe("no_linked_imap");
});

test("expired pending session reports EXPIRED", async () => {
  await setupDb();
  const userId = await insertUser();
  const keyA = await insertApiKey({
    userId,
    label: "keyA",
    keyPlain: "pb_email_a",
  });

  const created = await createEmailSession({
    userId,
    apiKeyId: keyA,
    approvalTtlMs: 600_000,
  });

  const database = await db();
  await database
    .query("UPDATE email_sessions SET approval_expires_at = ? WHERE id = ?;")
    .run(new Date(Date.now() - 1000).toISOString(), created.sessionId);

  const res = await app().request(`/v1/email/sessions/${created.sessionId}`, {
    headers: { authorization: "Bearer pb_email_a" },
  });
  expect(res.status).toBe(200);

  const read = await app().request(
    `/v1/email/sessions/${created.sessionId}/folders`,
    { headers: { authorization: "Bearer pb_email_a" } }
  );
  expect(read.status).toBe(408);
});

test("buildSearchObject maps curated query to imap search criteria", () => {
  const query: EmailSearchQuery = {
    subject: "invoice",
    from: "billing@example.com",
    to: "me@example.com",
    since: "2026-01-01",
    before: "2026-02-01",
    unseen: true,
    keyword: "important",
    bodyText: "receipt",
  };
  const obj = buildSearchObject(query);
  expect(obj.subject).toBe("invoice");
  expect(obj.from).toBe("billing@example.com");
  expect(obj.to).toBe("me@example.com");
  expect(obj.since).toBeInstanceOf(Date);
  expect((obj.since as Date).toISOString()).toBe("2026-01-01T00:00:00.000Z");
  expect(obj.before).toBeInstanceOf(Date);
  expect(obj.unseen).toBe(true);
  expect(obj.keyword).toBe("important");
  expect(obj.body).toBe("receipt");
});

test("read-only surface: email modules never reference IMAP write commands", async () => {
  const files = [
    "src/email/client.ts",
    "src/email/ops.ts",
    "src/email/protocol.ts",
  ];
  const forbidden = [
    "messageDelete(",
    "messageFlagsAdd(",
    "messageFlagsSet(",
    "messageFlagsRemove(",
    "mailboxCreate(",
    "mailboxDelete(",
    "mailboxRename(",
    "mailboxSubscribe(",
    "messageAppend(",
    "setFlagColor(",
  ];
  const source = (await Promise.all(files.map((f) => Bun.file(f).text()))).join(
    "\n"
  );
  for (const f of forbidden) {
    expect(source.includes(f)).toBe(false);
  }
});
