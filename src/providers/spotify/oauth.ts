import { env } from "../../env";
import type { OAuthProviderConfig } from "../../oauth/provider";

export function spotifyProvider(): OAuthProviderConfig {
  if (!env.SPOTIFY_OAUTH_CLIENT_ID || !env.SPOTIFY_OAUTH_CLIENT_SECRET) {
    throw new Error("Spotify OAuth env vars are required");
  }

  return {
    id: "spotify",
    issuer: "https://accounts.spotify.com",
    authorizationEndpoint: "https://accounts.spotify.com/authorize",
    tokenEndpoint: "https://accounts.spotify.com/api/token",
    clientId: env.SPOTIFY_OAUTH_CLIENT_ID,
    clientSecret: env.SPOTIFY_OAUTH_CLIENT_SECRET,
    scopes: [
      // Read-only basics
      "user-read-email",
      "user-read-private",
      // Playback / library / playlists (common agent use-cases)
      "user-read-playback-state",
      "user-modify-playback-state",
      "user-read-currently-playing",
      "user-library-read",
      "playlist-read-private",
      "playlist-modify-private",
      "playlist-modify-public",
    ],
    pkceRequired: true,
    // Spotify does not support access_type=offline; refresh tokens are returned
    // for Authorization Code flow.
    extraAuthorizeParams: {
      // Ensure we can always obtain a refresh token on reconnect.
      show_dialog: "true",
    },
  };
}
