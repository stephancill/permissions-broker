import { describe, expect, test } from "bun:test";

import { interpretUpstreamUrl } from "../src/proxy/interpret";

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
