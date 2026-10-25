import { expect, test } from "bun:test";

import { githubProxyProvider } from "../src/providers/github/proxy";

test("github provider sets a default User-Agent", () => {
  const headers: Record<string, string> = {};
  githubProxyProvider.applyUpstreamRequestHeaderDefaults({ headers });
  expect(headers["user-agent"]).toBe("permissions-broker");
  expect(headers.accept).toBe("application/vnd.github+json");
});

test("github provider keeps an explicit User-Agent", () => {
  const headers: Record<string, string> = { "user-agent": "custom" };
  githubProxyProvider.applyUpstreamRequestHeaderDefaults({ headers });
  expect(headers["user-agent"]).toBe("custom");
});
