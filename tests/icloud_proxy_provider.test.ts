import { describe, expect, test } from "bun:test";

import { icloudProxyProvider } from "../src/providers/icloud/proxy";

describe("icloudProxyProvider", () => {
  test("enforces host + path prefix scope", async () => {
    const storedCredential = JSON.stringify({
      username: "u@example.com",
      appSpecificPassword: "abcd-efgh-ijkl-mnop",
      allowedHosts: ["caldav.icloud.com", "p99-caldav.icloud.com"],
      allowedPathPrefixes: ["/123456789/calendars/"],
    });

    const ok = await icloudProxyProvider.isAllowedUpstreamUrl({
      userId: "user",
      url: new URL(
        "https://p99-caldav.icloud.com/123456789/calendars/ABC/events/"
      ),
      storedCredential,
    });
    expect(ok.allowed).toBe(true);

    const badHost = await icloudProxyProvider.isAllowedUpstreamUrl({
      userId: "user",
      url: new URL("https://evil.com/123456789/calendars/"),
      storedCredential,
    });
    expect(badHost.allowed).toBe(false);

    const badPath = await icloudProxyProvider.isAllowedUpstreamUrl({
      userId: "user",
      url: new URL("https://p99-caldav.icloud.com/other/path"),
      storedCredential,
    });
    expect(badPath.allowed).toBe(false);
  });
});
