import { describe, expect, test } from "bun:test";

import {
  consumeCachedResult,
  getCachedResult,
  setCachedResult,
} from "../src/cache/resultCache";

describe("result cache", () => {
  test("stores and consumes once", () => {
    setCachedResult(
      "r1",
      {
        status: 200,
        contentType: "text/plain",
        body: new Uint8Array([1, 2, 3]),
      },
      10_000
    );

    expect(getCachedResult("r1")?.body.byteLength).toBe(3);
    expect(consumeCachedResult("r1")?.status).toBe(200);
    expect(getCachedResult("r1")).toBeNull();
  });
});
