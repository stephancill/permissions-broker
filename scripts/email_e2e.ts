// End-to-end exercise of the read-only email feature without Telegram or a
// real mailbox. Boots the broker against a temp SQLite DB, starts the local
// plaintext IMAP test server, links the account (simulating a successful
// connect-form verification), creates a session, simulates Telegram approval,
// and runs folders/search/read through the real HTTP handlers — imapflow talks
// to the local IMAP server over real sockets.
//
//   bun scripts/email_e2e.ts
//
// Note: the connect form itself is thin, TLS-verification is covered by the
// Gmail smoke test and the unit tests, so this harness skips it and seeds the
// linked account directly (secure=false => plaintext against the local server).

import { Hono } from "hono";
import { ulid } from "ulid";

import { encryptUtf8 } from "../src/crypto/aesgcm";
import { sha256Hex } from "../src/crypto/sha256";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { serializeCredential } from "../src/email/credential";
import { setEmailSessionStatus } from "../src/email/sessions";
import { configureEnv, env } from "../src/env";
import { accountRouter } from "../src/web/accounts";
import { emailRouter } from "../src/web/email";
import { startImapTestServer } from "./imap_test_server";

function nowIso(): string {
  return new Date().toISOString();
}

const tmpDb = `/tmp/pb-email-e2e-${process.pid}.sqlite3`;
configureEnv({
  ...env,
  NODE_ENV: "test",
  DB_PATH: tmpDb,
  APP_SECRET: "e2e-app-secret",
  TELEGRAM_BOT_TOKEN: undefined,
});
await migrate();

async function insertUser(telegramUserId = 424242): Promise<string> {
  const id = ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(id, telegramUserId, nowIso());
  return id;
}

async function insertApiKey(params: { userId: string }): Promise<string> {
  const apiKeyId = ulid();
  const keyPlain = "pb_e2e_test_key";
  const keyHash = await sha256Hex(keyPlain);
  const database = await db();
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(apiKeyId, params.userId, "e2e", keyHash, nowIso(), nowIso());
  return apiKeyId;
}

async function insertLinkedImapAccount(params: {
  userId: string;
  host: string;
  port: number;
}): Promise<void> {
  const id = ulid();
  const credential = serializeCredential({
    email: "test@example.com",
    password: "testpass",
    host: params.host,
    port: params.port,
    secure: false, // plaintext local test server
  });
  const ct = await encryptUtf8(credential);
  const database = await db();
  await database
    .query(
      "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, 'imap', ?, 'read', ?, 'active', ?, NULL);"
    )
    .run(id, params.userId, await sha256Hex("test@example.com"), ct, nowIso());
}

function app() {
  const a = new Hono();
  a.route("/v1/accounts", accountRouter);
  a.route("/v1/email", emailRouter);
  return a;
}

const imap = await startImapTestServer();
console.log(
  `IMAP test server -> imap://${imap.host}:${imap.port} (test@example.com / testpass)`
);

const userId = await insertUser();
const keyPlain = "pb_e2e_test_key";
await insertApiKey({ userId });
await insertLinkedImapAccount({
  userId,
  host: imap.host,
  port: imap.port,
});
console.log("linked account -> seeded (secure=false, plaintext local IMAP)");

// 1) Create a session (would prompt Telegram; here we auto-approve below).
const sessionRes = await app().request("/v1/email/sessions", {
  method: "POST",
  headers: {
    authorization: `Bearer ${keyPlain}`,
    "content-type": "application/json",
  },
  body: JSON.stringify({ consent_hint: "e2e: check my inbox" }),
});
const sessionJson = (await sessionRes.json()) as Record<string, unknown>;
console.log(
  `create session -> HTTP ${sessionRes.status} ${JSON.stringify(sessionJson)}`
);
const sessionId = sessionJson.session_id as string;

// 2) Simulate the Telegram Approve button.
await setEmailSessionStatus({ sessionId, userId, status: "APPROVED" });
console.log("approve       -> simulated Telegram approval (APPROVED)");

const auth = { authorization: `Bearer ${keyPlain}` } as const;

// 3) List folders.
const foldersRes = await app().request(
  `/v1/email/sessions/${sessionId}/folders`,
  { headers: auth }
);
console.log(
  `folders       -> HTTP ${foldersRes.status} ${JSON.stringify((await foldersRes.json()) as Record<string, unknown>)}`
);

// 4) Search (subject filter).
const searchRes = await app().request(
  `/v1/email/sessions/${sessionId}/search`,
  {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({
      mailbox: "INBOX",
      query: { subject: "Invoice" },
      results_limit: 10,
    }),
  }
);
console.log(
  `search        -> HTTP ${searchRes.status} ${JSON.stringify((await searchRes.json()) as Record<string, unknown>)}`
);

// 5) Read a message.
const readRes = await app().request(`/v1/email/sessions/${sessionId}/read`, {
  method: "POST",
  headers: { ...auth, "content-type": "application/json" },
  body: JSON.stringify({
    mailbox: "INBOX",
    uid: 1,
    parts: { envelope: true, text: true },
  }),
});
const readJson = (await readRes.json()) as Record<string, unknown>;
console.log(`read uid=1     -> HTTP ${readRes.status}`);
console.log(`  subject: ${readJson.subject as string}`);
console.log(`  from: ${readJson.from as string}`);
console.log(`  text: ${JSON.stringify(readJson.text)}`);

imap.stop();
console.log("\nDone. The read-only email path works end to end.");
