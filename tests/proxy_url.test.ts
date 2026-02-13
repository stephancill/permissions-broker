import { describe, expect, test } from "bun:test";

import { canonicalizeUrl, validateUpstreamUrl } from "../src/proxy/url";

describe("validateUpstreamUrl", () => {
  test("accepts allowed https hosts", () => {
    const url = validateUpstreamUrl(
      "https://docs.googleapis.com/v1/documents/abc?fields=body"
    );
    expect(url.hostname).toBe("docs.googleapis.com");
  });

  test("accepts api.github.com", () => {
    const url = validateUpstreamUrl("https://api.github.com/user");
    expect(url.hostname).toBe("api.github.com");
  });

  test("accepts sheets.googleapis.com", () => {
    const url = validateUpstreamUrl(
      "https://sheets.googleapis.com/v4/spreadsheets/sheet123?fields=properties.title"
    );
    expect(url.hostname).toBe("sheets.googleapis.com");
  });

  test("accepts caldav.icloud.com", () => {
    const url = validateUpstreamUrl("https://caldav.icloud.com/");
    expect(url.hostname).toBe("caldav.icloud.com");
  });

  test("rejects non-https", () => {
    expect(() =>
      validateUpstreamUrl("http://docs.googleapis.com/v1/documents/abc")
    ).toThrow();
  });

  test("accepts arbitrary https hosts (provider validation happens elsewhere)", () => {
    const url = validateUpstreamUrl("https://example.com/");
    expect(url.hostname).toBe("example.com");
  });

  test("rejects embedded credentials", () => {
    expect(() =>
      validateUpstreamUrl(
        "https://user:pass@docs.googleapis.com/v1/documents/abc"
      )
    ).toThrow();
  });
});

describe("canonicalizeUrl", () => {
  test("sorts query params by key then value", () => {
    const u = new URL(
      "https://www.googleapis.com/drive/v3/files?q=z&pageSize=10&q=a&fields=files(id)"
    );
    const canon = canonicalizeUrl(u);
    expect(canon).toBe(
      "https://www.googleapis.com/drive/v3/files?fields=files%28id%29&pageSize=10&q=a&q=z"
    );
  });
});
