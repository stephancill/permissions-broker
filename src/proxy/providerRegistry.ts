import { githubProxyProvider } from "../providers/github/proxy";
import { googleProxyProvider } from "../providers/google/proxy";
import { icloudProxyProvider } from "../providers/icloud/proxy";
import type { ProxyProvider, ProxyProviderId } from "./provider";

const PROVIDERS: ProxyProvider[] = [
  googleProxyProvider,
  githubProxyProvider,
  icloudProxyProvider,
];

export function listProxyProviders(): ProxyProvider[] {
  return [...PROVIDERS];
}

export function listProxyProviderIds(): ProxyProviderId[] {
  return PROVIDERS.map((p) => p.id);
}

export function getProxyProviderById(id: ProxyProviderId): ProxyProvider {
  const p = PROVIDERS.find((x) => x.id === id);
  if (!p) throw new Error(`unknown proxy provider: ${id}`);
  return p;
}

export function getProxyProviderForUrl(url: URL): ProxyProvider {
  for (const p of PROVIDERS) {
    if (p.matchesUrl(url)) return p;
  }
  throw new Error("disallowed upstream host");
}
