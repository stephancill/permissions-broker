import { describe, expect, test } from "bun:test";

import { fmtRelative } from "../src/web/app";

const now = Date.parse("2026-11-22T12:00:00Z");
const ago = (ms: number) => new Date(now - ms).toISOString();
const MIN = 60_000;
const DAY = 24 * 60 * MIN;

describe("fmtRelative", () => {
  test("stays relative at every distance", () => {
    expect(fmtRelative({ iso: ago(10_000), now })).toBe("just now");
    expect(fmtRelative({ iso: ago(5 * MIN), now })).toBe("5 min ago");
    expect(fmtRelative({ iso: ago(3 * 60 * MIN), now })).toBe("3 h ago");
    expect(fmtRelative({ iso: ago(DAY), now })).toBe("1 day ago");
    expect(fmtRelative({ iso: ago(12 * DAY), now })).toBe("12 days ago");
    expect(fmtRelative({ iso: ago(65 * DAY), now })).toBe("2 months ago");
    expect(fmtRelative({ iso: ago(800 * DAY), now })).toBe("2 years ago");
  });

  test("clamps future timestamps", () => {
    expect(fmtRelative({ iso: ago(-MIN), now })).toBe("just now");
  });
});
