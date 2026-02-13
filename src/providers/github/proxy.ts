import type {
  InterpretedRequest,
  ProxyInterpretInput,
} from "../../proxy/interpret";
import type { ProxyProvider } from "../../proxy/provider";

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (v == null || typeof v !== "object") return null;
  if (Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function interpretGitHub(
  input: ProxyInterpretInput
): InterpretedRequest | null {
  const url = input.url;
  const method = (input.method || "GET").toUpperCase();
  const path = url.pathname;
  const body = asRecord(input.bodyJson);

  // Create PR
  // POST /repos/{owner}/{repo}/pulls
  const mCreatePr = path.match(/^\/repos\/([^/]+)\/([^/]+)\/pulls$/);
  if (mCreatePr && method === "POST") {
    const owner = mCreatePr[1];
    const repo = mCreatePr[2];
    const title = asString(body?.title);
    const head = asString(body?.head);
    const base = asString(body?.base);
    return {
      summary: "Create GitHub pull request",
      details: [
        `repo: ${owner}/${repo}`,
        title ? `title: ${truncate(title, 120)}` : "",
        head ? `head: ${truncate(head, 120)}` : "",
        base ? `base: ${truncate(base, 120)}` : "",
      ].filter(Boolean),
    };
  }

  // Create issue
  // POST /repos/{owner}/{repo}/issues
  const mCreateIssue = path.match(/^\/repos\/([^/]+)\/([^/]+)\/issues$/);
  if (mCreateIssue && method === "POST") {
    const owner = mCreateIssue[1];
    const repo = mCreateIssue[2];
    const title = asString(body?.title);
    return {
      summary: "Create GitHub issue",
      details: [
        `repo: ${owner}/${repo}`,
        title ? `title: ${truncate(title, 120)}` : "",
      ].filter(Boolean),
    };
  }

  return null;
}

export const githubProxyProvider: ProxyProvider = {
  id: "github",
  allowedHosts: new Set(["api.github.com"]),
  extraAllowedRequestHeaders: new Set(["x-github-api-version"]),

  async getAccessToken(params: { storedToken: string }): Promise<string> {
    // GitHub OAuth (classic app): treat stored token as an access token.
    return params.storedToken;
  },

  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void {
    if (!params.headers.accept) {
      params.headers.accept = "application/vnd.github+json";
    }

    if (!params.headers["x-github-api-version"]) {
      params.headers["x-github-api-version"] = "2022-11-28";
    }
  },

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null {
    return interpretGitHub(input);
  },
};
