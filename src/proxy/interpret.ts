function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function firstParam(url: URL, key: string): string | undefined {
  const v = url.searchParams.get(key);
  return v == null ? undefined : v;
}

export type InterpretedRequest = {
  summary: string;
  details: string[];
};

export function interpretUpstreamUrl(url: URL): InterpretedRequest {
  const host = url.hostname;
  const path = url.pathname;

  if (host === "docs.googleapis.com") {
    const m = path.match(/^\/v1\/documents\/([^/]+)$/);
    if (m) {
      const documentId = m[1];
      const fields = firstParam(url, "fields");
      return {
        summary: "Read Google Doc",
        details: [
          `documentId: ${documentId}`,
          fields ? `fields: ${truncate(fields, 200)}` : "",
        ].filter(Boolean),
      };
    }
  }

  if (host === "www.googleapis.com") {
    if (path === "/drive/v3/files") {
      const q = firstParam(url, "q");
      const pageSize = firstParam(url, "pageSize");
      const fields = firstParam(url, "fields");
      return {
        summary: "List Drive files",
        details: [
          pageSize ? `pageSize: ${truncate(pageSize, 50)}` : "",
          q ? `q: ${truncate(q, 200)}` : "",
          fields ? `fields: ${truncate(fields, 200)}` : "",
        ].filter(Boolean),
      };
    }

    const m = path.match(/^\/drive\/v3\/files\/([^/]+)$/);
    if (m) {
      const fileId = m[1];
      const fields = firstParam(url, "fields");
      return {
        summary: "Read Drive file metadata",
        details: [
          `fileId: ${fileId}`,
          fields ? `fields: ${truncate(fields, 200)}` : "",
        ].filter(Boolean),
      };
    }
  }

  return { summary: "Google API request", details: [] };
}
