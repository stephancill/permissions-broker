import { expect, test } from "bun:test";

import { createApp } from "../src/app";
import { createConnectState } from "../src/connect/state";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, env } from "../src/env";

await migrate();
configureEnv({
  ...env,
  APP_BASE_URL: "https://broker.test",
  APP_SECRET: "test-app-secret",
});

const app = createApp();

test("default security headers are applied", async () => {
  const res = await app.request("/healthz");
  expect(res.headers.get("x-frame-options")).toBe("DENY");
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("content-security-policy")).toContain(
    "default-src 'none'"
  );
});

test("passkey pages keep their own nonce-based CSP", async () => {
  const database = await db();
  const userId = `u_${crypto.randomUUID()}`;
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, Math.floor(Math.random() * 1e9), new Date().toISOString());
  const { state } = await createConnectState({
    userId,
    provider: "passkey",
    ttlMs: 60_000,
  });

  const res = await app.request(`/passkey/enroll?state=${state}`);
  expect(res.status).toBe(200);
  const csp = res.headers.get("content-security-policy") ?? "";
  expect(csp).toMatch(/script-src 'nonce-[^']+'/);
  // Other defaults are still added.
  expect(res.headers.get("x-frame-options")).toBe("DENY");
});
