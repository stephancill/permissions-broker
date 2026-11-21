import { expect, test } from "bun:test";

import { createApp } from "../src/app";
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

test("app pages keep their own nonce-based CSP and are installable", async () => {
  const res = await app.request("/app/signin");
  expect(res.status).toBe(200);
  const csp = res.headers.get("content-security-policy") ?? "";
  expect(csp).toMatch(/script-src 'nonce-[^']+'/);
  expect(csp).toContain("manifest-src 'self'");
  expect(csp).toContain("worker-src 'self'");
  expect(csp).toContain("form-action 'self'");
  // Other defaults are still added.
  expect(res.headers.get("x-frame-options")).toBe("DENY");
  const html = await res.text();
  expect(html).toContain(
    '<link rel="manifest" href="/manifest.webmanifest" />'
  );
  expect(html).toContain('rel="apple-touch-icon"');
});

test("manifest and service worker are served for the PWA", async () => {
  const manifest = await app.request("/manifest.webmanifest");
  expect(manifest.headers.get("content-type")).toBe(
    "application/manifest+json"
  );
  const m = (await manifest.json()) as { display: string; start_url: string };
  expect(m.display).toBe("standalone");
  expect(m.start_url).toBe("/app");

  const sw = await app.request("/sw.js");
  expect(sw.headers.get("content-type")).toContain("text/javascript");
  const js = await sw.text();
  expect(js).toContain('addEventListener("push"');
  expect(js).toContain('addEventListener("notificationclick"');
  // Open windows are told where to go (Safari lacks WindowClient.navigate).
  expect(js).toContain('type: "pb-open"');
  expect(js).not.toContain(".navigate(");
  const page = await (await app.request("/app/signin")).text();
  expect(page).toContain('d.type !== "pb-open"');
});

test("signed-out app pages redirect to passkey sign-in", async () => {
  for (const path of ["/app", "/app/keys", "/passkey/enroll"]) {
    const res = await app.request(path);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toStartWith("/app/signin?next=");
  }
});
