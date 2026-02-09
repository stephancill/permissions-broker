import * as oauth from "oauth4webapi";

import type { OAuthProviderConfig } from "./provider";

export async function buildAuthorizationUrl(params: {
  provider: OAuthProviderConfig;
  redirectUri: string;
  state: string;
  codeVerifier: string;
}): Promise<string> {
  const url = new URL(params.provider.authorizationEndpoint);
  url.searchParams.set("client_id", params.provider.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", params.provider.scopes.join(" "));
  url.searchParams.set("state", params.state);

  if (params.provider.pkceRequired) {
    const challenge = await oauth.calculatePKCECodeChallenge(
      params.codeVerifier
    );
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  if (params.provider.extraAuthorizeParams) {
    for (const [k, v] of Object.entries(params.provider.extraAuthorizeParams)) {
      url.searchParams.set(k, v);
    }
  }

  return url.toString();
}

export async function exchangeAuthorizationCode(params: {
  provider: OAuthProviderConfig;
  redirectUri: string;
  currentUrl: URL;
  expectedState: string;
  codeVerifier: string;
}): Promise<oauth.TokenEndpointResponse> {
  const as: oauth.AuthorizationServer = {
    issuer: params.provider.issuer,
    authorization_endpoint: params.provider.authorizationEndpoint,
    token_endpoint: params.provider.tokenEndpoint,
  };

  const client: oauth.Client = { client_id: params.provider.clientId };
  const clientAuth = oauth.ClientSecretPost(params.provider.clientSecret);

  const authParams = oauth.validateAuthResponse(
    as,
    client,
    params.currentUrl,
    params.expectedState
  );

  const response = await oauth.authorizationCodeGrantRequest(
    as,
    client,
    clientAuth,
    authParams,
    params.redirectUri,
    params.codeVerifier
  );

  return oauth.processAuthorizationCodeResponse(as, client, response);
}

export async function refreshAccessToken(params: {
  provider: OAuthProviderConfig;
  refreshToken: string;
}): Promise<oauth.TokenEndpointResponse> {
  const as: oauth.AuthorizationServer = {
    issuer: params.provider.issuer,
    token_endpoint: params.provider.tokenEndpoint,
  };

  const client: oauth.Client = { client_id: params.provider.clientId };
  const clientAuth = oauth.ClientSecretPost(params.provider.clientSecret);

  const response = await oauth.refreshTokenGrantRequest(
    as,
    client,
    clientAuth,
    params.refreshToken
  );

  return oauth.processRefreshTokenResponse(as, client, response);
}
