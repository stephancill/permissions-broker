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

  test("interprets iCloud REPORT time-range", () => {
    const url = new URL("https://caldav.icloud.com/123/calendars/abc/");
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag />
    <C:calendar-data />
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:time-range start="20260213T000000Z" end="20260220T000000Z" />
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>`;

    const out = interpretProxyRequest({
      url,
      method: "REPORT",
      headers: { "content-type": "application/xml", depth: "1" },
      bodyText: body,
    });
    expect(out.summary).toBe("Query iCloud CalDAV data");
    expect(out.details.join("\n")).toContain("components:");
    expect(out.details.join("\n")).toContain("time-range:");
  });

  test("interprets iCloud PUT VEVENT", () => {
    const url = new URL(
      "https://caldav.icloud.com/123/calendars/abc/uid123.ics"
    );
    const ics = `BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:uid123\nSUMMARY:Hello\nDTSTART:20260213T100000Z\nDTEND:20260213T103000Z\nEND:VEVENT\nEND:VCALENDAR\n`;
    const out = interpretProxyRequest({
      url,
      method: "PUT",
      headers: { "content-type": "text/calendar; charset=utf-8" },
      bodyText: ics,
    });
    expect(out.summary).toBe("Write iCloud CalDAV object");
    const d = out.details.join("\n");
    expect(d).toContain("kind: Event");
    expect(d).toContain("title: Hello");
    expect(d).toContain("when:");
  });
});
