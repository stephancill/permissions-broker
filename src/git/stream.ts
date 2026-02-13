export type PrefixReadResult = {
  prefixChunks: Uint8Array[];
  prefixBytes: number;
  sawFlush: boolean;
  // Bun's ReadableStreamDefaultReader type differs across lib targets.
  // Keep this as unknown to avoid DOM vs node:stream/web incompatibilities.
  reader: unknown;
};

export async function readPrefixUntilFlush(params: {
  body: ReadableStream<Uint8Array>;
  maxPrefixBytes: number;
}): Promise<PrefixReadResult> {
  const reader = params.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let sawFlush = false;

  // Look for pkt-line flush sequence "0000". This is ASCII and may be
  // split across chunks, so scan a sliding window.
  let tail = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;

    chunks.push(value);
    total += value.byteLength;
    if (total > params.maxPrefixBytes) {
      break;
    }

    const text = new TextDecoder().decode(value);
    const scan = tail + text;
    if (scan.includes("0000")) {
      sawFlush = true;
      break;
    }
    tail = scan.slice(-8);
  }

  return {
    prefixChunks: chunks,
    prefixBytes: total,
    sawFlush,
    reader,
  };
}

export function streamFromPrefixAndReader(params: {
  prefixChunks: Uint8Array[];
  reader: unknown;
}): ReadableStream<Uint8Array> {
  const { prefixChunks, reader } = params;
  const r = reader as ReadableStreamDefaultReader<Uint8Array>;
  let idx = 0;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (idx < prefixChunks.length) {
        controller.enqueue(prefixChunks[idx++]);
        return;
      }

      const { done, value } = await r.read();
      if (done) {
        controller.close();
        return;
      }
      if (value) controller.enqueue(value);
    },
    async cancel(reason) {
      await r.cancel(reason);
    },
  });
}

export function withByteLimit(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number
): ReadableStream<Uint8Array> | null {
  if (!body) return null;
  let total = 0;
  const ts = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      total += chunk.byteLength;
      if (total > maxBytes) {
        controller.error(new Error("body_too_large"));
        return;
      }
      controller.enqueue(chunk);
    },
  });
  return body.pipeThrough(ts);
}
