import type {
  InterpretedRequest,
  ProxyInterpretInput,
} from "../../proxy/interpret";
import type { ProxyProvider } from "../../proxy/provider";

type CloudflareCredential = {
  apiToken: string;
  accounts?: Array<{ id: string; name?: string }>;
};

function safeJsonParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function parseCredential(stored: string): CloudflareCredential | null {
  const j = safeJsonParse(stored);
  if (!j || typeof j !== "object" || Array.isArray(j)) return null;
  const o = j as Record<string, unknown>;
  const apiToken = typeof o.apiToken === "string" ? o.apiToken : null;
  if (!apiToken) return null;

  const accounts = Array.isArray(o.accounts)
    ? o.accounts
        .map((x) => {
          if (!x || typeof x !== "object" || Array.isArray(x)) return null;
          const account = x as Record<string, unknown>;
          const id = typeof account.id === "string" ? account.id : null;
          const name =
            typeof account.name === "string" ? account.name : undefined;
          return id ? { id, name } : null;
        })
        .filter((x) => x != null)
    : undefined;

  return { apiToken, accounts };
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 3)}...`;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (v == null || typeof v !== "object") return null;
  if (Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function interpretCloudflare(
  input: ProxyInterpretInput
): InterpretedRequest | null {
  const url = input.url;
  const method = (input.method || "GET").toUpperCase();
  const path = url.pathname;
  const body = asRecord(input.bodyJson);

  const accountMatch = path.match(/^\/client\/v4\/accounts\/([^/]+)/);
  const zoneMatch = path.match(/^\/client\/v4\/zones\/([^/]+)/);
  const accountId = accountMatch?.[1];
  const zoneId = zoneMatch?.[1];

  if (path === "/client/v4/accounts" && method === "GET") {
    return { summary: "List Cloudflare accounts", details: [] };
  }

  if (path === "/client/v4/zones" && method === "GET") {
    const name = url.searchParams.get("name");
    return {
      summary: "List Cloudflare zones",
      details: [name ? `name: ${truncate(name, 120)}` : ""].filter(Boolean),
    };
  }

  const workerScriptMatch = path.match(
    /^\/client\/v4\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)$/
  );
  if (workerScriptMatch && ["PUT", "PATCH", "DELETE"].includes(method)) {
    return {
      summary:
        method === "DELETE"
          ? "Delete Cloudflare Worker script"
          : "Deploy Cloudflare Worker script",
      details: [
        `account: ${workerScriptMatch[1]}`,
        `script: ${decodeURIComponent(workerScriptMatch[2] ?? "")}`,
      ],
    };
  }

  const kvMatch = path.match(
    /^\/client\/v4\/accounts\/([^/]+)\/storage\/kv\/namespaces\/([^/]+)\/values\/(.+)$/
  );
  if (kvMatch) {
    return {
      summary: `${method} Cloudflare KV value`,
      details: [
        `account: ${kvMatch[1]}`,
        `namespace: ${kvMatch[2]}`,
        `key: ${truncate(decodeURIComponent(kvMatch[3] ?? ""), 160)}`,
      ],
    };
  }

  const d1Match = path.match(
    /^\/client\/v4\/accounts\/([^/]+)\/d1\/database\/([^/]+)\/query$/
  );
  if (d1Match && method === "POST") {
    const sql = asString(body?.sql);
    return {
      summary: "Execute Cloudflare D1 query",
      details: [
        `account: ${d1Match[1]}`,
        `database: ${d1Match[2]}`,
        sql ? `sql: ${truncate(sql.replace(/\s+/g, " ").trim(), 220)}` : "",
      ].filter(Boolean),
    };
  }

  if (accountId) {
    return {
      summary: "Cloudflare account API request",
      details: [`method: ${method}`, `account: ${accountId}`, `path: ${path}`],
    };
  }

  if (zoneId) {
    return {
      summary: "Cloudflare zone API request",
      details: [`method: ${method}`, `zone: ${zoneId}`, `path: ${path}`],
    };
  }

  return null;
}

export const cloudflareProxyProvider: ProxyProvider = {
  id: "cloudflare",

  matchesUrl(url: URL): boolean {
    return url.hostname === "api.cloudflare.com";
  },

  async isAllowedUpstreamUrl(params: {
    userId: string;
    url: URL;
    storedCredential?: string;
  }): Promise<{ allowed: boolean; message?: string }> {
    if (params.url.hostname !== "api.cloudflare.com") return { allowed: false };
    if (!params.url.pathname.startsWith("/client/v4/")) {
      return {
        allowed: false,
        message: "Cloudflare proxy only allows /client/v4 API paths",
      };
    }
    return { allowed: true };
  },

  allowedMethods: new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]),

  extraAllowedRequestHeaders: new Set([
    "x-stainless-arch",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
  ]),

  async getAuthorizationHeaderValue(params: {
    storedCredential: string;
  }): Promise<string> {
    const cred = parseCredential(params.storedCredential);
    if (!cred) throw new Error("invalid Cloudflare credential");
    return `Bearer ${cred.apiToken}`;
  },

  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void {
    if (!params.headers.accept) {
      params.headers.accept = "application/json";
    }
  },

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null {
    return interpretCloudflare(input);
  },
};
