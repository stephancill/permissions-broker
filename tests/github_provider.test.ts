import { expect, test } from "bun:test";
import * as oauth from "oauth4webapi";

import { configureEnv, env } from "../src/env";
import { githubProvider } from "../src/providers/github/oauth";
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

test("github OAuth callbacks carrying GitHub's iss are accepted", () => {
  const prev = env;
  configureEnv({
    ...env,
    GITHUB_OAUTH_CLIENT_ID: "client",
    GITHUB_OAUTH_CLIENT_SECRET: "secret",
  });
  try {
    const provider = githubProvider();
    const as: oauth.AuthorizationServer = {
      issuer: provider.issuer,
      authorization_endpoint: provider.authorizationEndpoint,
      token_endpoint: provider.tokenEndpoint,
    };
    const callback = new URL(
      "https://vault.example/v1/accounts/callback/github?code=abc&state=st&iss=https%3A%2F%2Fgithub.com%2Flogin%2Foauth"
    );
    expect(() =>
      oauth.validateAuthResponse(as, { client_id: "client" }, callback, "st")
    ).not.toThrow();
    // A different issuer is still rejected (mix-up protection).
    const mixedUp = new URL(callback);
    mixedUp.searchParams.set("iss", "https://evil.example");
    expect(() =>
      oauth.validateAuthResponse(as, { client_id: "client" }, mixedUp, "st")
    ).toThrow();
  } finally {
    configureEnv(prev);
  }
});
