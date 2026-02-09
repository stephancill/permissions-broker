const ALLOWED_HOSTS = new Set(["docs.googleapis.com", "www.googleapis.com"]);

export function validateUpstreamUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error("invalid upstream_url");
  }

  if (url.protocol !== "https:") throw new Error("upstream_url must be https");
  if (!ALLOWED_HOSTS.has(url.hostname))
    throw new Error("disallowed upstream host");
  if (url.username || url.password)
    throw new Error("upstream_url must not include credentials");
  return url;
}

export function canonicalizeUrl(url: URL): string {
  const out = new URL(url.toString());

  const pairs: [string, string][] = [];
  for (const [k, v] of out.searchParams.entries()) {
    pairs.push([k, v]);
  }
  pairs.sort((a, b) =>
    a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])
  );

  out.search = "";
  for (const [k, v] of pairs) {
    out.searchParams.append(k, v);
  }

  return out.toString();
}
