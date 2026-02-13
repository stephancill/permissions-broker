import { githubProxyProvider } from "../providers/github/proxy";
import { googleProxyProvider } from "../providers/google/proxy";
import { icloudProxyProvider } from "../providers/icloud/proxy";
import type { ProxyProvider, ProxyProviderId } from "./provider";

const PROVIDERS: ProxyProvider[] = [
  googleProxyProvider,
  githubProxyProvider,
  icloudProxyProvider,
];

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
