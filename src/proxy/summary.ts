import { interpretProxyRequest } from "./interpret";

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

export function decodeBodyForInterpret(params: {
  contentType: string | undefined;
  bodyBase64: string | undefined;
}): {
  bodyText?: string;
  bodyJson?: unknown;
  bodySummary?: string;
} {
  if (!params.bodyBase64) return {};

  const bytes = Buffer.from(params.bodyBase64, "base64");
  const ctRaw = params.contentType;
  const ct = ctRaw ? ctRaw.split(";", 1)[0]?.trim().toLowerCase() : "";

  const isJson = ct === "application/json" || ct.endsWith("+json");
  const isTextual =
    ct.startsWith("text/") ||
    ct === "application/x-www-form-urlencoded" ||
    ct.endsWith("+xml") ||
    ct === "application/xml";

  if (isJson || isTextual) {
    const text = new TextDecoder().decode(bytes);
    if (isJson) {
      try {
        return {
          bodyText: text,
          bodyJson: JSON.parse(text),
          bodySummary: text,
        };
      } catch {
        return { bodyText: text, bodySummary: text };
      }
    }

    return { bodyText: text, bodySummary: text };
  }

  const prefix = bytes.subarray(0, 24);
  const b64Prefix = Buffer.from(prefix).toString("base64");
  return {
    bodySummary: `<binary ${bytes.byteLength} bytes; base64_prefix=${b64Prefix}…>`,
  };
}

// Plain-text summary of a stored proxy request for the approval page.
export function summarizeStoredProxyRequest(row: {
  upstream_url: string;
  method: string;
  request_headers_json: string | null;
  request_body_base64: string | null;
}): { action: string; details: string[]; request: string; body?: string } {
  const url = new URL(row.upstream_url);
  let headers: Record<string, string> = {};
  if (row.request_headers_json) {
    try {
      headers = JSON.parse(row.request_headers_json) as Record<string, string>;
    } catch {
      headers = {};
    }
  }
  const decoded = decodeBodyForInterpret({
    contentType: headers["content-type"],
    bodyBase64: row.request_body_base64 ?? undefined,
  });
  const interpreted = interpretProxyRequest({
    url,
    method: row.method,
    headers,
    bodyJson: decoded.bodyJson,
    bodyText: decoded.bodyText,
  });

  return {
    action: interpreted.summary,
    details: interpreted.details,
    request: `${row.method} ${url.hostname}${url.pathname}${url.search}`,
    body:
      decoded.bodySummary != null
        ? truncate(decoded.bodySummary, 2000)
        : undefined,
  };
}
