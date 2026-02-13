import type {
  InterpretedRequest,
  ProxyInterpretInput,
} from "../../proxy/interpret";
import type { ProxyProvider } from "../../proxy/provider";

type IcloudCredential = {
  username: string;
  appSpecificPassword: string;
  allowedHosts: string[];
  allowedPathPrefixes: string[];
};

function safeJsonParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function parseCredential(stored: string): IcloudCredential | null {
  const j = safeJsonParse(stored);
  if (!j || typeof j !== "object" || Array.isArray(j)) return null;
  const o = j as Record<string, unknown>;
  const username = typeof o.username === "string" ? o.username : null;
  const appSpecificPassword =
    typeof o.appSpecificPassword === "string" ? o.appSpecificPassword : null;
  const allowedHosts = Array.isArray(o.allowedHosts)
    ? (o.allowedHosts.filter((x) => typeof x === "string") as string[])
    : null;
  const allowedPathPrefixes = Array.isArray(o.allowedPathPrefixes)
    ? (o.allowedPathPrefixes.filter((x) => typeof x === "string") as string[])
    : null;

  if (
    !username ||
    !appSpecificPassword ||
    !allowedHosts ||
    !allowedPathPrefixes
  )
    return null;

  return { username, appSpecificPassword, allowedHosts, allowedPathPrefixes };
}

function basicAuthHeader(username: string, password: string): string {
  const raw = `${username}:${password}`;
  const b64 = Buffer.from(raw, "utf8").toString("base64");
  return `Basic ${b64}`;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

type IcsComponent = {
  kind: "VEVENT" | "VTODO" | "UNKNOWN";
  uid?: string;
  summary?: string;
  description?: string;
  location?: string;
  dtstart?: string;
  dtend?: string;
  due?: string;
  status?: string;
  tzid?: string;
};

function unfoldIcsLines(text: string): string[] {
  const raw = text.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  for (const line of raw) {
    if (!line) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && out.length > 0) {
      out[out.length - 1] = `${out[out.length - 1]}${line.trimStart()}`;
    } else {
      out.push(line);
    }
  }
  return out;
}

function parseIcsComponent(bodyText: string | undefined): IcsComponent | null {
  if (!bodyText) return null;

  const lines = unfoldIcsLines(bodyText);
  let current: IcsComponent | null = null;

  for (const line of lines) {
    const up = line.toUpperCase();
    if (up === "BEGIN:VEVENT") {
      current = { kind: "VEVENT" };
      continue;
    }
    if (up === "BEGIN:VTODO") {
      current = { kind: "VTODO" };
      continue;
    }
    if (up === "END:VEVENT" || up === "END:VTODO") {
      if (current) return current;
      continue;
    }

    if (!current) continue;
    const comp = current;

    const colon = line.indexOf(":");
    if (colon <= 0) continue;

    const left = line.slice(0, colon);
    const value = line.slice(colon + 1);
    const semi = left.indexOf(";");
    const key = (semi === -1 ? left : left.slice(0, semi)).toUpperCase();
    const params = semi === -1 ? "" : left.slice(semi + 1);

    if (key === "UID") comp.uid = value.trim();
    if (key === "SUMMARY") comp.summary = value.trim();
    if (key === "DESCRIPTION") comp.description = value.trim();
    if (key === "LOCATION") comp.location = value.trim();
    if (key === "STATUS") comp.status = value.trim();

    const maybeSetTzidFromParams = () => {
      if (comp.tzid) return;
      const m = params.match(/TZID=([^;:]+)/i);
      if (m) comp.tzid = m[1];
    };

    if (key === "DTSTART") {
      comp.dtstart = value.trim();
      maybeSetTzidFromParams();
    }
    if (key === "DTEND") {
      comp.dtend = value.trim();
      maybeSetTzidFromParams();
    }
    if (key === "DUE") {
      comp.due = value.trim();
      maybeSetTzidFromParams();
    }
  }

  return null;
}

function isValidIanaTimeZone(tz: string): boolean {
  try {
    // Throws RangeError for unknown zones.
    new Intl.DateTimeFormat("en-US", { timeZone: tz }).format(new Date());
    return true;
  } catch {
    return false;
  }
}

function formatDateTimeInZone(params: {
  date: Date;
  timeZone: string;
  includeTime: boolean;
}): string {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: params.timeZone,
    weekday: "short",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    ...(params.includeTime
      ? {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
          timeZoneName: "short",
        }
      : {}),
  });

  const parts = fmt.formatToParts(params.date);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const wd = get("weekday");
  const y = get("year");
  const m = get("month");
  const d = get("day");
  const hh = get("hour");
  const mi = get("minute");
  const tz = get("timeZoneName");

  if (!params.includeTime) return `${wd} ${y}-${m}-${d}`;
  return `${wd} ${y}-${m}-${d} ${hh}:${mi} ${tz}`.trim();
}

function formatIcsDateTime(
  value: string | undefined,
  tzid: string | undefined,
  renderTimeZoneHint: string | undefined
): string {
  if (!value) return "";
  // Common forms:
  // - 20260213T155720Z
  // - 20260213
  // - 20260213T155720
  const v = value.trim();
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(T(\d{2})(\d{2})(\d{2})Z?)?$/);
  if (!m) return tzid ? `${v} (${tzid})` : v;

  const yyyy = Number(m[1]);
  const mm = Number(m[2]);
  const dd = Number(m[3]);
  const hasTime = !!m[4];
  const hh = m[5];
  const mi = m[6];
  const ss = m[7];
  const isUtc = v.endsWith("Z");

  if (!hasTime) {
    // Date-only values are "floating" (all-day) in iCalendar. Avoid timezone
    // conversions entirely to prevent off-by-one-day rendering.
    const d = new Date(Date.UTC(yyyy, mm - 1, dd, 12, 0, 0));
    const weekday = new Intl.DateTimeFormat("en-US", {
      timeZone: "UTC",
      weekday: "short",
    }).format(d);
    return `${weekday} ${String(yyyy).padStart(4, "0")}-${String(mm).padStart(
      2,
      "0"
    )}-${String(dd).padStart(2, "0")}`;
  }

  const hour = Number(hh);
  const minute = Number(mi);
  const second = Number(ss);

  // If the ICS timestamp is UTC (ends with Z), we can render in an arbitrary zone.
  if (isUtc) {
    const zone =
      renderTimeZoneHint && isValidIanaTimeZone(renderTimeZoneHint)
        ? renderTimeZoneHint
        : "UTC";
    const d = new Date(Date.UTC(yyyy, mm - 1, dd, hour, minute, second));
    return formatDateTimeInZone({ date: d, timeZone: zone, includeTime: true });
  }

  // For floating times (no Z), we intentionally avoid converting to an instant.
  // Render the local wall-clock time with a best-effort zone label.
  const labelZone = (() => {
    if (tzid && isValidIanaTimeZone(tzid)) return tzid;
    if (renderTimeZoneHint && isValidIanaTimeZone(renderTimeZoneHint)) {
      return renderTimeZoneHint;
    }
    return undefined;
  })();

  const d = new Date(Date.UTC(yyyy, mm - 1, dd, 12, 0, 0));
  const weekday = new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC",
    weekday: "short",
  }).format(d);

  const datePart = `${weekday} ${String(yyyy).padStart(4, "0")}-${String(
    mm
  ).padStart(2, "0")}-${String(dd).padStart(2, "0")}`;
  const timePart = `${String(hour).padStart(2, "0")}:${String(minute).padStart(
    2,
    "0"
  )}`;
  return labelZone
    ? `${datePart} ${timePart} (${labelZone})`
    : `${datePart} ${timePart}`;
}

function interpretIcloud(
  input: ProxyInterpretInput
): InterpretedRequest | null {
  const url = input.url;
  const method = (input.method || "GET").toUpperCase();

  const depth = input.headers?.depth;
  const contentType = input.headers?.["content-type"]
    ? input.headers["content-type"].split(";", 1)[0]?.trim()
    : undefined;
  const bodyText = input.bodyText;

  function summarizeDavXml(): {
    props?: string[];
    components?: string[];
    timeRange?: { start?: string; end?: string };
  } {
    if (!bodyText) return {};

    const props: string[] = [];
    const components: string[] = [];
    let start: string | undefined;
    let end: string | undefined;

    const propBlock = bodyText.match(/<[^>]*prop[^>]*>[\s\S]*?<\/[^>]*prop>/i);
    if (propBlock) {
      const inner = propBlock[0];
      const propRe = /<([A-Za-z0-9_.-]+:)?([A-Za-z0-9_.-]+)\b[^>]*\/>/g;
      for (const m of inner.matchAll(propRe)) {
        const name = (m[2] ?? "").toLowerCase();
        if (!name) continue;
        if (name === "prop") continue;
        if (name === "propfind") continue;
        if (name === "filter") continue;
        if (!props.includes(name)) props.push(name);
      }
    }

    const compRe = /<[^>]*comp-filter\b[^>]*\bname\s*=\s*"([^"]+)"/gi;
    for (const m of bodyText.matchAll(compRe)) {
      const nm = (m[1] ?? "").trim();
      if (!nm) continue;
      if (!components.includes(nm)) components.push(nm);
    }

    const timeRe =
      /<[^>]*time-range\b[^>]*\bstart\s*=\s*"([^"]+)"[^>]*\bend\s*=\s*"([^"]+)"/i;
    const tm = bodyText.match(timeRe);
    if (tm) {
      start = tm[1];
      end = tm[2];
    }

    return {
      props: props.length ? props : undefined,
      components: components.length ? components : undefined,
      timeRange: start || end ? { start, end } : undefined,
    };
  }

  if (url.hostname.endsWith(".icloud.com")) {
    const xmlSummary = contentType?.includes("xml") ? summarizeDavXml() : {};

    if (method === "REPORT") {
      const lines: string[] = [];
      lines.push(`path: ${url.pathname}`);
      if (depth) lines.push(`depth: ${depth}`);
      if (xmlSummary.components?.length) {
        lines.push(`components: ${xmlSummary.components.join(",")}`);
      }
      if (xmlSummary.timeRange?.start || xmlSummary.timeRange?.end) {
        lines.push(
          `time-range: ${xmlSummary.timeRange?.start ?? ""}..${xmlSummary.timeRange?.end ?? ""}`
        );
      }
      if (contentType) lines.push(`content-type: ${contentType}`);

      return {
        summary: "Query iCloud CalDAV data",
        details: lines,
      };
    }

    if (method === "PROPFIND") {
      const lines: string[] = [];
      lines.push(`path: ${url.pathname}`);
      if (depth) lines.push(`depth: ${depth}`);
      if (xmlSummary.props?.length) {
        lines.push(`props: ${truncate(xmlSummary.props.join(","), 200)}`);
      }
      if (contentType) lines.push(`content-type: ${contentType}`);

      return {
        summary: "Read iCloud CalDAV properties",
        details: lines,
      };
    }

    if (method === "PUT") {
      const ics =
        contentType?.toLowerCase().startsWith("text/calendar") ||
        contentType?.toLowerCase() === "text/calendar"
          ? parseIcsComponent(bodyText)
          : null;

      const lines: string[] = [];
      if (contentType) lines.push(`content-type: ${contentType}`);

      if (ics) {
        if (ics.kind === "VEVENT") {
          lines.push("kind: Event");
          if (ics.summary) lines.push(`title: ${truncate(ics.summary, 140)}`);

          const tzHint = input.headers?.["x-pb-timezone"];
          const start = formatIcsDateTime(ics.dtstart, ics.tzid, tzHint);
          const end = formatIcsDateTime(ics.dtend, ics.tzid, tzHint);
          if (start || end) lines.push(`when: ${start} -> ${end}`.trim());
          if (ics.location)
            lines.push(`location: ${truncate(ics.location, 140)}`);
          if (ics.description)
            lines.push(`notes: ${truncate(ics.description, 180)}`);
        } else if (ics.kind === "VTODO") {
          lines.push("kind: Reminder");
          if (ics.summary) lines.push(`title: ${truncate(ics.summary, 140)}`);
          const tzHint = input.headers?.["x-pb-timezone"];
          const due = formatIcsDateTime(ics.due, ics.tzid, tzHint);
          if (due) lines.push(`due: ${due}`);
          if (ics.status) lines.push(`status: ${ics.status}`);
          if (ics.description)
            lines.push(`notes: ${truncate(ics.description, 180)}`);
        } else {
          lines.push(`kind: ${ics.kind}`);
          if (ics.summary) lines.push(`title: ${truncate(ics.summary, 140)}`);
        }
      }

      return {
        summary: "Write iCloud CalDAV object",
        details: lines,
      };
    }

    if (method === "DELETE") {
      return {
        summary: "Delete iCloud CalDAV object",
        details: [`path: ${url.pathname}`],
      };
    }
  }

  return null;
}

export const icloudProxyProvider: ProxyProvider = {
  id: "icloud",

  matchesUrl(url: URL): boolean {
    // Selection is intentionally broad; final allowlisting is based on per-user
    // discovery bounds stored in the linked account.
    return (
      url.hostname === "caldav.icloud.com" ||
      url.hostname.endsWith(".icloud.com")
    );
  },

  async isAllowedUpstreamUrl(params: {
    userId: string;
    url: URL;
    storedCredential?: string;
  }): Promise<{ allowed: boolean; message?: string }> {
    if (!params.storedCredential) {
      return { allowed: false, message: "missing linked iCloud account" };
    }

    const cred = parseCredential(params.storedCredential);
    if (!cred) return { allowed: false, message: "invalid iCloud credential" };

    const hostOk = cred.allowedHosts.includes(params.url.hostname);
    const path = params.url.pathname;
    const prefixOk = cred.allowedPathPrefixes.some((p) => path.startsWith(p));
    return hostOk && prefixOk
      ? { allowed: true }
      : {
          allowed: false,
          message: `URL not in allowed CalDAV scope: ${truncate(
            `${params.url.hostname}${params.url.pathname}`,
            200
          )}`,
        };
  },

  allowedMethods: new Set([
    "GET",
    "PUT",
    "DELETE",
    "PROPFIND",
    "REPORT",
    "MKCALENDAR",
    "MOVE",
    "COPY",
    "OPTIONS",
  ]),

  extraAllowedRequestHeaders: new Set([
    "depth",
    "destination",
    "brief",
    "prefer",
  ]),

  async getAuthorizationHeaderValue(params: {
    storedCredential: string;
  }): Promise<string> {
    const cred = parseCredential(params.storedCredential);
    if (!cred) throw new Error("invalid iCloud credential");
    return basicAuthHeader(cred.username, cred.appSpecificPassword);
  },

  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void {
    if (!params.headers.accept) {
      params.headers.accept = "application/xml, text/xml, text/calendar";
    }
  },

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null {
    return interpretIcloud(input);
  },
};
