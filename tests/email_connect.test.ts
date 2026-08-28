import { expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import { createConnectState } from "../src/connect/state";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, env } from "../src/env";
import { accountRouter } from "../src/web/accounts";

function nowIso(): string {
  return new Date().toISOString();
}

// Create schema once for this test file.
await migrate();
configureEnv({ ...env, APP_SECRET: "test-app-secret" });

function app() {
  const a = new Hono();
  a.route("/v1/accounts", accountRouter);
  return a;
}

test("imap connect form requires a state", async () => {
  const res = await app().request("/v1/accounts/connect/imap", {});
  expect(res.status).toBe(400);
  expect(await res.text()).toBe("missing state");
});

test("imap connect form renders for a valid state", async () => {
  const userId = ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, 999, nowIso());
  const { state } = await createConnectState({
    userId,
    provider: "imap",
    ttlMs: 60_000,
  });

  const res = await app().request(
    `/v1/accounts/connect/imap?state=${encodeURIComponent(state)}`,
    {}
  );
  expect(res.status).toBe(200);
  const html = await res.text();
  expect(html).toContain("Connect Email");
  expect(html).toContain('action="/v1/accounts/connect/imap"');
});

test("imap connect post rejects an unknown state", async () => {
  const res = await app().request("/v1/accounts/connect/imap", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      state: "cs_nope",
      email: "a@b.com",
      password: "whatever",
    }),
  });
  expect(res.status).toBe(400);
  expect(await res.text()).toContain("invalid state");
});

test("imap connect post requires fields", async () => {
  const res = await app().request("/v1/accounts/connect/imap", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ state: "cs_the_state_abc", email: "a@b.com" }),
  });
  expect(res.status).toBe(400);
  expect(await res.text()).toContain("missing fields");
});
