import { githubProvider } from "../providers/github/oauth";
import { googleProvider } from "../providers/google/oauth";
import type { OAuthProviderConfig } from "./provider";

export function getProvider(providerId: string): OAuthProviderConfig {
  if (providerId === "google") return googleProvider();
  if (providerId === "github") return githubProvider();
  throw new Error(`unknown provider: ${providerId}`);
}
