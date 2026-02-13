import { env } from "../../env";
import type { OAuthProviderConfig } from "../../oauth/provider";

export function githubProvider(): OAuthProviderConfig {
  if (!env.GITHUB_OAUTH_CLIENT_ID || !env.GITHUB_OAUTH_CLIENT_SECRET) {
    throw new Error("GitHub OAuth env vars are required");
  }

  return {
    id: "github",
    issuer: "https://github.com",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    clientId: env.GITHUB_OAUTH_CLIENT_ID,
    clientSecret: env.GITHUB_OAUTH_CLIENT_SECRET,
    scopes: ["repo"],
    pkceRequired: true,
    extraAuthorizeParams: {},
  };
}
