import { getProxyProviderForUrl } from "./providerRegistry";

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

export type InterpretedRequest = {
  summary: string;
  details: string[];
};

export type ProxyInterpretInput = {
  url: URL;
  method: string;
  headers?: Record<string, string>;
  bodyJson?: unknown;
  bodyText?: string;
};

export function interpretProxyRequest(
  input: ProxyInterpretInput
): InterpretedRequest {
  const url = input.url;
  const method = (input.method || "GET").toUpperCase();
  const provider = getProxyProviderForUrl(url);

  const interpreted = provider.interpretRequest({ ...input, method });
  if (interpreted) return interpreted;

  return {
    summary: `${provider.id} API request`,
    details: [
      `method: ${method}`,
      `path: ${url.pathname}`,
      url.search ? `query: ${truncate(url.search, 250)}` : "",
    ].filter(Boolean),
  };
}

// Backwards-compatible entrypoint for GET-only requests.
export function interpretUpstreamUrl(url: URL): InterpretedRequest {
  return interpretProxyRequest({ url, method: "GET" });
}
