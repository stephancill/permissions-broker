export type OAuthProviderConfig = {
  id: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  pkceRequired: boolean;
  extraAuthorizeParams?: Record<string, string>;
};
