import { describe, expect, test } from "bun:test";

import { readBodyWithLimit } from "../src/proxy/readLimit";

function streamFromChunks(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      controller.close();
    },
  });
}

describe("readBodyWithLimit", () => {
  test("reads within limit", async () => {
    const body = streamFromChunks([
      new Uint8Array([1, 2]),
      new Uint8Array([3]),
    ]);
    const out = await readBodyWithLimit(body, 10);
    expect([...out]).toEqual([1, 2, 3]);
  });

  test("throws when exceeding limit", async () => {
    const body = streamFromChunks([new Uint8Array([1, 2, 3, 4])]);
    await expect(readBodyWithLimit(body, 3)).rejects.toThrow(
      "response_too_large"
    );
  });
});
