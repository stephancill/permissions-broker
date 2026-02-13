import { describe, expect, test } from "bun:test";

import {
  extractSymrefHeadFromInfoRefs,
  isAllZeroSha,
  parseReceivePackCommands,
} from "../src/git/pktline";

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function pkt(payload: string): string {
  const n = new TextEncoder().encode(payload).byteLength + 4;
  const hex = n.toString(16).padStart(4, "0");
  return `${hex}${payload}`;
}

describe("pktline", () => {
  test("extractSymrefHeadFromInfoRefs finds HEAD symref", () => {
    const body =
      "001e# service=git-receive-pack\n" +
      "0000" +
      // First ref line with capabilities after NUL
      "007f01234567890123456789012345678901234567 refs/heads/main\0report-status symref=HEAD:refs/heads/main agent=git/2.39.0\n";

    const head = extractSymrefHeadFromInfoRefs(enc(body));
    expect(head).toBe("refs/heads/main");
  });

  test("parseReceivePackCommands parses command lines", () => {
    const payload =
      "0123456789012345678901234567890123456789 " +
      "abcdefabcdefabcdefabcdefabcdefabcdefabcd " +
      "refs/heads/feature/test\0report-status\n";
    const cmd = `${pkt(payload)}0000`;

    const cmds = parseReceivePackCommands(enc(cmd));
    expect(cmds.length).toBe(1);
    expect(cmds[0].ref).toBe("refs/heads/feature/test");
  });

  test("isAllZeroSha detects deletes", () => {
    expect(isAllZeroSha("0".repeat(40))).toBe(true);
    expect(isAllZeroSha("1".repeat(40))).toBe(false);
  });
});
