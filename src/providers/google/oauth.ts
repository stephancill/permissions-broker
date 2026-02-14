import { env } from "../../env";
import type { OAuthProviderConfig } from "../../oauth/provider";

export function googleProvider(): OAuthProviderConfig {
  if (!env.GOOGLE_OAUTH_CLIENT_ID || !env.GOOGLE_OAUTH_CLIENT_SECRET) {
    throw new Error("Google OAuth env vars are required");
  }

  return {
    id: "google",
    issuer: "https://accounts.google.com",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    clientId: env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: env.GOOGLE_OAUTH_CLIENT_SECRET,
    scopes: [
      // Drive read-only for listing/searching files.
      "https://www.googleapis.com/auth/drive.readonly",
      // Limited Drive write access for files created/opened by this app (e.g. new Sheets).
      "https://www.googleapis.com/auth/drive.file",
      "https://www.googleapis.com/auth/documents.readonly",
      // Sheets write access (needed to create spreadsheets + append/update values).
      "https://www.googleapis.com/auth/spreadsheets",
    ],
    pkceRequired: true,
    extraAuthorizeParams: {
      access_type: "offline",
      prompt: "consent",
    },
  };
}
