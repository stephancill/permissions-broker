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

export class OAuthTokenRefreshError extends Error {
  providerId: string;
  tokenEndpoint: string;
  status?: number;
  oauthError?: string;
  oauthErrorDescription?: string;

  constructor(params: {
    providerId: string;
    tokenEndpoint: string;
    status?: number;
    oauthError?: string;
    oauthErrorDescription?: string;
    message: string;
    cause?: unknown;
  }) {
    super(params.message, { cause: params.cause });
    this.name = "OAuthTokenRefreshError";
    this.providerId = params.providerId;
    this.tokenEndpoint = params.tokenEndpoint;
    this.status = params.status;
    this.oauthError = params.oauthError;
    this.oauthErrorDescription = params.oauthErrorDescription;
  }
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

  let response: Response;
  try {
    response = await oauth.refreshTokenGrantRequest(
      as,
      client,
      clientAuth,
      params.refreshToken
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthTokenRefreshError({
      providerId: params.provider.id,
      tokenEndpoint: params.provider.tokenEndpoint,
      message: `refresh_token_grant_request failed: ${msg}`,
      cause: err,
    });
  }

  try {
    return oauth.processRefreshTokenResponse(as, client, response);
  } catch (err) {
    if (err instanceof oauth.ResponseBodyError) {
      throw new OAuthTokenRefreshError({
        providerId: params.provider.id,
        tokenEndpoint: params.provider.tokenEndpoint,
        status: err.status,
        oauthError: err.error,
        oauthErrorDescription: err.error_description,
        message: `oauth token refresh failed: status=${err.status} error=${err.error}${err.error_description ? ` description=${err.error_description}` : ""}`,
        cause: err,
      });
    }

    if (err instanceof oauth.WWWAuthenticateChallengeError) {
      throw new OAuthTokenRefreshError({
        providerId: params.provider.id,
        tokenEndpoint: params.provider.tokenEndpoint,
        status: err.status,
        message: `oauth token refresh failed: www-authenticate challenge status=${err.status}`,
        cause: err,
      });
    }

    const msg = err instanceof Error ? err.message : String(err);
    throw new OAuthTokenRefreshError({
      providerId: params.provider.id,
      tokenEndpoint: params.provider.tokenEndpoint,
      message: `oauth token refresh failed: ${msg}`,
      cause: err,
    });
  }
}
