export type CachedResult = {
  status: number;
  contentType: string | null;
  body: Uint8Array;
  expiresAt: number;
};

const cache = new Map<string, CachedResult>();

export function setCachedResult(
  requestId: string,
  result: Omit<CachedResult, "expiresAt">,
  ttlMs: number
): void {
  cache.set(requestId, {
    ...result,
    expiresAt: Date.now() + ttlMs,
  });
}

export function getCachedResult(requestId: string): CachedResult | null {
  const v = cache.get(requestId);
  if (!v) return null;
  if (Date.now() > v.expiresAt) {
    cache.delete(requestId);
    return null;
  }
  return v;
}

export function consumeCachedResult(requestId: string): CachedResult | null {
  const v = getCachedResult(requestId);
  if (!v) return null;
  cache.delete(requestId);
  return v;
}

export function evictExpired(): number {
  const now = Date.now();
  let n = 0;
  for (const [k, v] of cache.entries()) {
    if (now > v.expiresAt) {
      cache.delete(k);
      n++;
    }
  }
  return n;
}
