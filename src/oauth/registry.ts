import { githubProvider } from "../providers/github/oauth";
import { googleProvider } from "../providers/google/oauth";
import { spotifyProvider } from "../providers/spotify/oauth";
import type { OAuthProviderConfig } from "./provider";

export function getProvider(providerId: string): OAuthProviderConfig {
  if (providerId === "google") return googleProvider();
  if (providerId === "github") return githubProvider();
  if (providerId === "spotify") return spotifyProvider();
  throw new Error(`unknown provider: ${providerId}`);
}
