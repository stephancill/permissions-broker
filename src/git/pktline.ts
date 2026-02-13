export type ReceivePackCommand = {
  oldSha: string;
  newSha: string;
  ref: string;
};

function readAscii(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

function parsePktLen(hex4: string): number {
  const n = Number.parseInt(hex4, 16);
  if (!Number.isFinite(n) || n < 0) throw new Error("invalid pkt-line length");
  return n;
}

// Minimal pkt-line parser utilities.
// See: https://git-scm.com/docs/protocol-common

export function extractSymrefHeadFromInfoRefs(
  bodyPrefix: Uint8Array
): string | null {
  const text = readAscii(bodyPrefix);
  // We only care about the first pkt-line where capabilities appear.
  // GitHub typically includes: "...\0symref=HEAD:refs/heads/main ..."
  const m = text.match(/symref=HEAD:([^\s\0]+)/);
  return m ? m[1] : null;
}

export function parseReceivePackCommands(
  bodyPrefix: Uint8Array
): ReceivePackCommand[] {
  const cmds: ReceivePackCommand[] = [];
  let i = 0;

  while (i + 4 <= bodyPrefix.length) {
    const hex4 = readAscii(bodyPrefix.slice(i, i + 4));
    const len = parsePktLen(hex4);
    i += 4;

    if (len === 0) {
      // flush packet
      break;
    }

    const payloadLen = len - 4;
    if (payloadLen < 0 || i + payloadLen > bodyPrefix.length) {
      // Not enough data in prefix.
      break;
    }

    const payload = readAscii(bodyPrefix.slice(i, i + payloadLen));
    i += payloadLen;

    // First command line may include capabilities after a NUL.
    const line = payload.split("\0", 1)[0];
    // Format: "<old> <new> <ref>\n"
    const parts = line.trim().split(" ");
    if (parts.length < 3) continue;
    const [oldSha, newSha] = parts;
    const ref = parts.slice(2).join(" ");
    cmds.push({ oldSha, newSha, ref });
  }

  return cmds;
}

export function isAllZeroSha(sha: string): boolean {
  return /^0{40}$/.test(sha);
}
