import type { Context } from "hono";

// Where a request came from, for the API key audit trail. Location is the
// edge's IP geolocation (Cloudflare's request.cf); it's null under Bun or
// when the edge doesn't provide it. Nothing is sent to a third-party lookup.
export type RequestOrigin = {
  ip: string | null;
  userAgent: string | null;
  location: string | null;
};

type CfProperties = {
  city?: unknown;
  region?: unknown;
  country?: unknown;
};

function clean(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  return s ? s.slice(0, max) : null;
}

export function requestOrigin(c: Context): RequestOrigin {
  const ip =
    clean(c.req.header("cf-connecting-ip"), 64) ??
    clean(c.req.header("x-forwarded-for")?.split(",", 1)[0], 64) ??
    clean(c.req.header("x-real-ip"), 64);

  const cf = (c.req.raw as Request & { cf?: CfProperties }).cf;
  const parts = [cf?.city, cf?.region, cf?.country]
    .map((p) => clean(p, 64))
    .filter((p): p is string => p != null);
  const country = clean(c.req.header("cf-ipcountry"), 8);
  const location =
    parts.length > 0
      ? [...new Set(parts)].join(", ")
      : country && country !== "XX"
        ? country
        : null;

  return {
    ip,
    userAgent: clean(c.req.header("user-agent"), 512),
    location,
  };
}

export function describeOrigin(params: {
  ip: string | null;
  location: string | null;
}): string | null {
  if (params.location && params.ip) {
    return `${params.location} (${params.ip})`;
  }
  return params.location ?? params.ip;
}
