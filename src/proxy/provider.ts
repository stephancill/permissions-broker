import type { InterpretedRequest, ProxyInterpretInput } from "./interpret";

export type ProxyProviderId = "google" | "github" | "icloud" | "spotify";

export type ProxyProvider = {
  id: ProxyProviderId;

  // Fast provider selection based on the upstream URL.
  // This should be a superset match (selection), not the final allow decision.
  matchesUrl(url: URL): boolean;

  // Validate that the upstream URL is allowed for this user.
  // For some providers (e.g. iCloud), this is dynamic and depends on discovery
  // results stored in the linked account.
  isAllowedUpstreamUrl(params: {
    userId: string;
    url: URL;
    storedCredential?: string;
  }): Promise<{ allowed: boolean; message?: string }>;

  allowedMethods: Set<string>;

  // Provider-specific header keys allowed to be forwarded to upstream.
  // (Common headers are handled in the proxy layer.)
  extraAllowedRequestHeaders: Set<string>;

  // Transform the stored credential from `linked_accounts` into an upstream
  // Authorization header value.
  // Examples:
  // - Google: "Bearer <access_token>"
  // - GitHub: "Bearer <token>"
  // - iCloud CalDAV: "Basic <base64(username:app_password)>"
  getAuthorizationHeaderValue(params: {
    storedCredential: string;
  }): Promise<string>;

  // Allow a provider to set defaults or required headers.
  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void;

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null;
};
