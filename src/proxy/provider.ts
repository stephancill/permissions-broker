import type { InterpretedRequest, ProxyInterpretInput } from "./interpret";

export type ProxyProviderId = "google" | "github";

export type ProxyProvider = {
  id: ProxyProviderId;
  allowedHosts: Set<string>;

  // Provider-specific header keys allowed to be forwarded to upstream.
  // (Common headers are handled in the proxy layer.)
  extraAllowedRequestHeaders: Set<string>;

  // Transform the stored token from `linked_accounts` into an access token.
  // For Google this typically means refreshing; for GitHub it is already an access token.
  getAccessToken(params: { storedToken: string }): Promise<string>;

  // Allow a provider to set defaults or required headers.
  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void;

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null;
};
