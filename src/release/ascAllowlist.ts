// Which App Store Connect requests a release session may make, and which
// resource ids each response adds to the session. Everything not listed is
// refused: a session can read its own apps' builds and profiles and upload a
// build, nothing else (no certificates, profiles, devices or listing changes).

export type SessionScope = {
  bundleIds: string[];
  certificateId: string;
  appIds: string[];
  bundleResourceIds: string[];
  buildIds: string[];
  buildUploadIds: string[];
  buildUploadFileIds: string[];
};

// What to learn from a successful response.
export type Learn =
  | "apps"
  | "bundleIds"
  | "builds"
  | "buildUpload"
  | "buildUploadFile"
  | null;

export type AscDecision =
  | { ok: true; learn: Learn }
  | { ok: false; reason: string };

const ID = /^[A-Za-z0-9-]{1,64}$/;
const GENERIC_PARAM = /^(limit|include|sort|fields\[[A-Za-z]+\])$/;

function deny(reason: string): AscDecision {
  return { ok: false, reason };
}

// Only generic params plus the named filters; each named filter must hold one
// value (App Store Connect filters accept comma lists).
function checkParams(
  search: URLSearchParams,
  filters: Record<string, (value: string) => boolean>
): string | null {
  const seen = new Set<string>();
  for (const [key, value] of search) {
    if (seen.has(key)) return `repeated query parameter ${key}`;
    seen.add(key);
    if (GENERIC_PARAM.test(key)) continue;
    const check = filters[key];
    if (!check) return `query parameter ${key} is not allowed`;
    if (value.includes(",") || !check(value)) {
      return `${key} is not allowed for this session`;
    }
  }
  return null;
}

function relationshipId(body: unknown, relationship: string): string | null {
  const data = (body as { data?: unknown } | null)?.data as
    | { relationships?: Record<string, { data?: { id?: unknown } }> }
    | undefined;
  const id = data?.relationships?.[relationship]?.data?.id;
  return typeof id === "string" ? id : null;
}

export function authorizeAscRequest(params: {
  method: string;
  // Path after `/v1/`, e.g. `builds/123/buildBetaDetail`.
  path: string;
  search: URLSearchParams;
  body: unknown;
  scope: SessionScope;
}): AscDecision {
  const { scope, search } = params;
  const method = params.method.toUpperCase();
  const segments = params.path.split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) {
    return deny("malformed path");
  }
  const [collection, id, sub, ...extra] = segments;
  if (extra.length > 0) return deny("path is not allowed");
  if (id !== undefined && !ID.test(id)) return deny("malformed resource id");

  const approvedBundle = (v: string) => scope.bundleIds.includes(v);
  const knownApp = (v: string) => scope.appIds.includes(v);

  if (method === "GET") {
    if (collection === "apps" && id === undefined) {
      if (!search.has("filter[bundleId]"))
        return deny("filter[bundleId] is required");
      const bad = checkParams(search, { "filter[bundleId]": approvedBundle });
      return bad ? deny(bad) : { ok: true, learn: "apps" };
    }
    if (collection === "bundleIds" && id === undefined) {
      if (!search.has("filter[identifier]")) {
        return deny("filter[identifier] is required");
      }
      const bad = checkParams(search, { "filter[identifier]": approvedBundle });
      return bad ? deny(bad) : { ok: true, learn: "bundleIds" };
    }
    if (collection === "bundleIds" && id !== undefined && sub === "profiles") {
      if (!scope.bundleResourceIds.includes(id)) {
        return deny("bundle id is not approved for this session");
      }
      const bad = checkParams(search, {});
      return bad ? deny(bad) : { ok: true, learn: null };
    }
    if (
      collection === "certificates" &&
      id !== undefined &&
      sub === undefined
    ) {
      if (id !== scope.certificateId) {
        return deny("only the distribution certificate can be read");
      }
      const bad = checkParams(search, {});
      return bad ? deny(bad) : { ok: true, learn: null };
    }
    if (collection === "builds" && id === undefined) {
      if (!search.has("filter[app]")) return deny("filter[app] is required");
      const bad = checkParams(search, {
        "filter[app]": knownApp,
        "filter[version]": (v) => v.length > 0,
        "filter[preReleaseVersion.version]": (v) => v.length > 0,
      });
      return bad ? deny(bad) : { ok: true, learn: "builds" };
    }
    if (
      collection === "builds" &&
      id !== undefined &&
      (sub === undefined || sub === "buildBetaDetail")
    ) {
      if (!scope.buildIds.includes(id)) {
        return deny("build is not one this session has listed");
      }
      const bad = checkParams(search, {});
      return bad ? deny(bad) : { ok: true, learn: null };
    }
    if (
      collection === "buildUploads" &&
      id !== undefined &&
      sub === undefined
    ) {
      if (!scope.buildUploadIds.includes(id)) {
        return deny("build upload was not created by this session");
      }
      const bad = checkParams(search, {});
      return bad ? deny(bad) : { ok: true, learn: null };
    }
    return deny("request is not allowed");
  }

  if (search.size > 0) return deny("query parameters are not allowed here");

  if (method === "POST" && collection === "buildUploads" && id === undefined) {
    const appId = relationshipId(params.body, "app");
    if (!appId || !knownApp(appId))
      return deny("app is not approved for this session");
    return { ok: true, learn: "buildUpload" };
  }
  if (
    method === "POST" &&
    collection === "buildUploadFiles" &&
    id === undefined
  ) {
    const uploadId = relationshipId(params.body, "buildUpload");
    if (!uploadId || !scope.buildUploadIds.includes(uploadId)) {
      return deny("build upload was not created by this session");
    }
    return { ok: true, learn: "buildUploadFile" };
  }
  if (
    method === "PATCH" &&
    collection === "buildUploadFiles" &&
    id !== undefined &&
    sub === undefined
  ) {
    if (!scope.buildUploadFileIds.includes(id)) {
      return deny("build upload file was not created by this session");
    }
    return { ok: true, learn: null };
  }
  return deny("request is not allowed");
}

type Resource = { id?: unknown; attributes?: Record<string, unknown> };

function resources(body: unknown): Resource[] {
  const data = (body as { data?: unknown } | null)?.data;
  if (Array.isArray(data)) return data as Resource[];
  return data && typeof data === "object" ? [data as Resource] : [];
}

// Resource ids a successful response adds to the session's scope.
export function learnFromResponse(params: {
  learn: Learn;
  body: unknown;
  scope: SessionScope;
}): Partial<SessionScope> {
  const list = resources(params.body);
  const ids = (filter: (r: Resource) => boolean) =>
    list
      .filter((r) => typeof r.id === "string" && filter(r))
      .map((r) => r.id as string);
  const union = (a: string[], b: string[]) => [...new Set([...a, ...b])];
  const { scope } = params;

  switch (params.learn) {
    case "apps":
      return {
        appIds: union(
          scope.appIds,
          ids((r) => scope.bundleIds.includes(String(r.attributes?.bundleId)))
        ),
      };
    case "bundleIds":
      return {
        bundleResourceIds: union(
          scope.bundleResourceIds,
          ids((r) => scope.bundleIds.includes(String(r.attributes?.identifier)))
        ),
      };
    case "builds":
      return {
        buildIds: union(
          scope.buildIds,
          ids(() => true)
        ),
      };
    case "buildUpload":
      return {
        buildUploadIds: union(
          scope.buildUploadIds,
          ids(() => true)
        ),
      };
    case "buildUploadFile":
      return {
        buildUploadFileIds: union(
          scope.buildUploadFileIds,
          ids(() => true)
        ),
      };
    default:
      return {};
  }
}
