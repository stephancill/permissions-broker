import { randomBase64Url } from "../../crypto/random";

type DiscoveryResult = {
  allowedHosts: string[];
  allowedPathPrefixes: string[];
};

function normalizePrefix(pathname: string): string {
  if (!pathname.startsWith("/")) pathname = `/${pathname}`;
  return pathname.endsWith("/") ? pathname : `${pathname}/`;
}

function extractHrefInProperty(
  xml: string,
  propLocalName: string
): string | null {
  const re = new RegExp(
    `<[^>]*${propLocalName}[^>]*>[\\s\\S]*?<[^>]*href[^>]*>([^<]+)<\\/[^>]*href>`,
    "i"
  );
  const m = xml.match(re);
  if (!m) return null;
  return m[1]?.trim() || null;
}

function basicAuthHeader(username: string, password: string): string {
  const raw = `${username}:${password}`;
  const b64 = Buffer.from(raw, "utf8").toString("base64");
  return `Basic ${b64}`;
}

async function fetchWithRedirects(params: {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
  maxRedirects: number;
}): Promise<Response> {
  let current = new URL(params.url);
  for (let i = 0; i <= params.maxRedirects; i++) {
    const res = await fetch(current.toString(), {
      method: params.method,
      headers: params.headers,
      body: params.body,
      redirect: "manual",
    });

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return res;
      const next = new URL(loc, current);
      if (next.protocol !== "https:") throw new Error("redirect to non-https");
      if (!next.hostname.endsWith("icloud.com"))
        throw new Error("redirect to non-icloud host");
      current = next;
      continue;
    }

    return res;
  }

  throw new Error("too many redirects");
}

async function readTextWithLimit(
  res: Response,
  maxBytes: number
): Promise<string> {
  const ab = await res.arrayBuffer();
  if (ab.byteLength > maxBytes) throw new Error("response_too_large");
  return Buffer.from(ab).toString("utf8");
}

const PROPFIND_PRINCIPAL_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal />
  </D:prop>
</D:propfind>
`;

const PROPFIND_HOMESET_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-home-set />
  </D:prop>
</D:propfind>
`;

export async function discoverIcloudCaldavBounds(params: {
  username: string;
  appSpecificPassword: string;
}): Promise<DiscoveryResult> {
  const headers = new Headers();
  headers.set(
    "authorization",
    basicAuthHeader(params.username, params.appSpecificPassword)
  );
  headers.set("user-agent", `permissions-broker/${randomBase64Url(6)}`);
  headers.set("content-type", "application/xml; charset=utf-8");

  // 1) Root -> current-user-principal
  const rootRes = await fetchWithRedirects({
    url: "https://caldav.icloud.com/",
    method: "PROPFIND",
    headers,
    body: PROPFIND_PRINCIPAL_BODY,
    maxRedirects: 5,
  });
  if (!rootRes.ok) {
    const t = await readTextWithLimit(rootRes, 64 * 1024);
    throw new Error(`discovery failed: ${rootRes.status} ${t.slice(0, 200)}`);
  }

  const rootXml = await readTextWithLimit(rootRes, 256 * 1024);
  const principalHref = extractHrefInProperty(
    rootXml,
    "current-user-principal"
  );
  if (!principalHref) throw new Error("missing principal href");
  const principalUrl = new URL(principalHref, rootRes.url);

  // 2) Principal -> calendar-home-set
  const principalRes = await fetchWithRedirects({
    url: principalUrl.toString(),
    method: "PROPFIND",
    headers,
    body: PROPFIND_HOMESET_BODY,
    maxRedirects: 5,
  });
  if (!principalRes.ok) {
    const t = await readTextWithLimit(principalRes, 64 * 1024);
    throw new Error(
      `principal discovery failed: ${principalRes.status} ${t.slice(0, 200)}`
    );
  }

  const principalXml = await readTextWithLimit(principalRes, 256 * 1024);
  const homeHref = extractHrefInProperty(principalXml, "calendar-home-set");
  if (!homeHref) throw new Error("missing calendar home-set href");
  const homeUrl = new URL(homeHref, principalRes.url);

  const allowedHosts = Array.from(
    new Set(["caldav.icloud.com", principalUrl.hostname, homeUrl.hostname])
  );
  const allowedPathPrefixes = Array.from(
    new Set([
      normalizePrefix(principalUrl.pathname),
      normalizePrefix(homeUrl.pathname),
    ])
  );

  return { allowedHosts, allowedPathPrefixes };
}
