import { githubProxyProvider } from "../providers/github/proxy";
import { googleProxyProvider } from "../providers/google/proxy";
import type { ProxyProvider, ProxyProviderId } from "./provider";

const PROVIDERS: ProxyProvider[] = [googleProxyProvider, githubProxyProvider];

export function getProxyProviderById(id: ProxyProviderId): ProxyProvider {
  const p = PROVIDERS.find((x) => x.id === id);
  if (!p) throw new Error(`unknown proxy provider: ${id}`);
  return p;
}

export function getProxyProviderForUrl(url: URL): ProxyProvider {
  const host = url.hostname;
  for (const p of PROVIDERS) {
    if (p.allowedHosts.has(host)) return p;
  }
  throw new Error("disallowed upstream host");
}
