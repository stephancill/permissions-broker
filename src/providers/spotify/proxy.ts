import { refreshAccessToken } from "../../oauth/flow";
import type {
  InterpretedRequest,
  ProxyInterpretInput,
} from "../../proxy/interpret";
import type { ProxyProvider } from "../../proxy/provider";
import { spotifyProvider } from "./oauth";

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function firstParam(url: URL, key: string): string | undefined {
  const v = url.searchParams.get(key);
  return v == null ? undefined : v;
}

function interpretSpotify(
  input: ProxyInterpretInput
): InterpretedRequest | null {
  const url = input.url;
  const method = (input.method || "GET").toUpperCase();
  const host = url.hostname;
  const path = url.pathname;

  if (host !== "api.spotify.com") return null;

  if (path === "/v1/me" && method === "GET") {
    return { summary: "Read Spotify profile", details: [] };
  }

  if (path === "/v1/me/player" && method === "GET") {
    const market = firstParam(url, "market");
    return {
      summary: "Read Spotify playback state",
      details: [market ? `market: ${market}` : ""].filter(Boolean),
    };
  }

  if (path === "/v1/me/player/currently-playing" && method === "GET") {
    const market = firstParam(url, "market");
    return {
      summary: "Read currently playing track",
      details: [market ? `market: ${market}` : ""].filter(Boolean),
    };
  }

  if (path === "/v1/me/tracks" && method === "GET") {
    const limit = firstParam(url, "limit");
    const offset = firstParam(url, "offset");
    return {
      summary: "List saved tracks",
      details: [
        limit ? `limit: ${limit}` : "",
        offset ? `offset: ${offset}` : "",
      ].filter(Boolean),
    };
  }

  const mPlaylist = path.match(/^\/v1\/playlists\/([^/]+)$/);
  if (mPlaylist && method === "GET") {
    return {
      summary: "Read playlist",
      details: [`playlistId: ${truncate(mPlaylist[1], 80)}`],
    };
  }

  const mPlaylistTracks = path.match(/^\/v1\/playlists\/([^/]+)\/tracks$/);
  if (mPlaylistTracks && method === "GET") {
    const limit = firstParam(url, "limit");
    const offset = firstParam(url, "offset");
    return {
      summary: "List playlist tracks",
      details: [
        `playlistId: ${truncate(mPlaylistTracks[1], 80)}`,
        limit ? `limit: ${limit}` : "",
        offset ? `offset: ${offset}` : "",
      ].filter(Boolean),
    };
  }

  if (
    path === "/v1/me/player/play" &&
    (method === "PUT" || method === "POST")
  ) {
    const deviceId = firstParam(url, "device_id");
    return {
      summary: "Start Spotify playback",
      details: [deviceId ? `device_id: ${truncate(deviceId, 80)}` : ""].filter(
        Boolean
      ),
    };
  }

  if (
    path === "/v1/me/player/pause" &&
    (method === "PUT" || method === "POST")
  ) {
    const deviceId = firstParam(url, "device_id");
    return {
      summary: "Pause Spotify playback",
      details: [deviceId ? `device_id: ${truncate(deviceId, 80)}` : ""].filter(
        Boolean
      ),
    };
  }

  return null;
}

export const spotifyProxyProvider: ProxyProvider = {
  id: "spotify",

  matchesUrl(url: URL): boolean {
    return url.hostname === "api.spotify.com";
  },

  async isAllowedUpstreamUrl(params: {
    userId: string;
    url: URL;
    storedCredential?: string;
  }): Promise<{ allowed: boolean; message?: string }> {
    // MVP: strict allowlist.
    return params.url.hostname === "api.spotify.com"
      ? { allowed: true }
      : { allowed: false };
  },

  allowedMethods: new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  extraAllowedRequestHeaders: new Set([]),

  async getAuthorizationHeaderValue(params: {
    storedCredential: string;
  }): Promise<string> {
    // Spotify stores refresh tokens.
    const token = await refreshAccessToken({
      provider: spotifyProvider(),
      refreshToken: params.storedCredential,
    });
    return `Bearer ${token.access_token}`;
  },

  applyUpstreamRequestHeaderDefaults(params: {
    headers: Record<string, string>;
  }): void {
    if (!params.headers.accept) {
      params.headers.accept = "application/json";
    }

    // Spotify APIs are JSON; defaulting content-type isn't safe for non-JSON bodies.
  },

  interpretRequest(input: ProxyInterpretInput): InterpretedRequest | null {
    return interpretSpotify(input);
  },
};
