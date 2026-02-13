import { describe, expect, test } from "bun:test";

import {
  interpretProxyRequest,
  interpretUpstreamUrl,
} from "../src/proxy/interpret";

describe("interpretUpstreamUrl", () => {
  test("interprets Docs documents.get", () => {
    const url = new URL(
      "https://docs.googleapis.com/v1/documents/doc123?fields=body"
    );
    const out = interpretUpstreamUrl(url);
    expect(out.summary).toBe("Read Google Doc");
    expect(out.details.join("\n")).toContain("documentId: doc123");
  });

  test("interprets Drive files.list", () => {
    const url = new URL(
      "https://www.googleapis.com/drive/v3/files?pageSize=20&q=mimeType%3D%27application%2Fvnd.google-apps.document%27"
    );
    const out = interpretUpstreamUrl(url);
    expect(out.summary).toBe("List Drive files");
  });
});

describe("interpretProxyRequest", () => {
  test("interprets GitHub pull request creation", () => {
    const url = new URL("https://api.github.com/repos/o/r/pulls");
    const out = interpretProxyRequest({
      url,
      method: "POST",
      bodyJson: { title: "t", head: "feat", base: "main" },
    });
    expect(out.summary).toBe("Create GitHub pull request");
    expect(out.details.join("\n")).toContain("repo: o/r");
  });

  test("interprets Sheets spreadsheets.get", () => {
    const url = new URL(
      "https://sheets.googleapis.com/v4/spreadsheets/s123?fields=properties.title"
    );
    const out = interpretProxyRequest({ url, method: "GET" });
    expect(out.summary).toBe("Read Google Sheet metadata");
    expect(out.details.join("\n")).toContain("spreadsheetId: s123");
  });
});
