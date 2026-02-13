import { refreshAccessToken } from "../../oauth/flow";
import type {
  InterpretedRequest,
  ProxyInterpretInput,
} from "../../proxy/interpret";
import type { ProxyProvider } from "../../proxy/provider";
import { googleProvider } from "./oauth";

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function firstParam(url: URL, key: string): string | undefined {
  const v = url.searchParams.get(key);
  return v == null ? undefined : v;
}

function interpretGoogle(
  input: ProxyInterpretInput
): InterpretedRequest | null {
  const url = input.url;
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

  if (host === "sheets.googleapis.com") {
    // Spreadsheet metadata
    // GET /v4/spreadsheets/{spreadsheetId}
    const m = path.match(/^\/v4\/spreadsheets\/([^/]+)$/);
    if (m) {
      const spreadsheetId = m[1];
      const fields = firstParam(url, "fields");
      const includeGridData = firstParam(url, "includeGridData");
      return {
        summary: "Read Google Sheet metadata",
        details: [
          `spreadsheetId: ${spreadsheetId}`,
          fields ? `fields: ${truncate(fields, 200)}` : "",
          includeGridData
            ? `includeGridData: ${truncate(includeGridData, 20)}`
            : "",
        ].filter(Boolean),
      };
    }

    // Values read
    // GET /v4/spreadsheets/{spreadsheetId}/values/{range}
    const mv = path.match(/^\/v4\/spreadsheets\/([^/]+)\/values\/(.+)$/);
    if (mv) {
      const spreadsheetId = mv[1];
      const rangeEnc = mv[2];
      const range = decodeURIComponent(rangeEnc);
      const majorDimension = firstParam(url, "majorDimension");
      const valueRenderOption = firstParam(url, "valueRenderOption");
      const dateTimeRenderOption = firstParam(url, "dateTimeRenderOption");
      return {
        summary: "Read Google Sheet values",
        details: [
          `spreadsheetId: ${spreadsheetId}`,
          `range: ${truncate(range, 200)}`,
          majorDimension
            ? `majorDimension: ${truncate(majorDimension, 30)}`
            : "",
          valueRenderOption
            ? `valueRenderOption: ${truncate(valueRenderOption, 40)}`
            : "",
          dateTimeRenderOption
            ? `dateTimeRenderOption: ${truncate(dateTimeRenderOption, 40)}`
            : "",
        ].filter(Boolean),
      };
    }
  }

  return null;
}

export const googleProxyProvider: ProxyProvider = {
  id: "google",
  allowedHosts: new Set([
    "docs.googleapis.com",
    "www.googleapis.com",
    "sheets.googleapis.com",
  ]),
  extraAllowedRequestHeaders: new Set([]),

  async getAccessToken(params: { storedToken: string }): Promise<string> {
    const token = await refreshAccessToken({
      provider: googleProvider(),
      refreshToken: params.storedToken,
    });
    return token.access_token;
  },

  applyUpstreamRequestHeaderDefaults(): void {
    // No-op for Google in the MVP.
  },

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null {
    return interpretGoogle(input);
  },
};
