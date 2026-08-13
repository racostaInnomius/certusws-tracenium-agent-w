// test/plugins/cdp-process-owner.test.ts
//
// ADR-0004 (a). All three platforms come down to parsing one command's
// output, and every one of those formats has a trap in it — the macOS
// parser shipped broken the first time because `(LISTEN)` is its own
// whitespace-separated token, so "the last column" was the state, not
// the address. These tests use real output verbatim.

import { describe, it, expect } from "vitest";
import {
  parseLsofListeners,
  parsePsPaths,
  parseNetstatPids,
  parseTasklist,
  parseProcNetTcpInodes,
  resolveListenerOwners
} from "../../src/plugins/cdp/process-owner";

describe("parseLsofListeners (macOS)", () => {
  // Copied verbatim from a real `lsof -nP -iTCP -sTCP:LISTEN +c 0`.
  const OUTPUT = [
    "COMMAND                       PID          USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
    "rapportd                     1012 javierpacheco   13u  IPv4  0x95a9895b2773397      0t0  TCP *:58676 (LISTEN)",
    "figma_agent                 76553 javierpacheco   10u  IPv4 0x84d7c442ff5b96f8      0t0  TCP 127.0.0.1:44960 (LISTEN)"
  ].join("\n");

  it("finds the address even though (LISTEN) is the last token", () => {
    const owners = parseLsofListeners(OUTPUT);
    expect(owners.get(44960)).toEqual({ pid: 76553, name: "figma_agent" });
    expect(owners.get(58676)).toEqual({ pid: 1012, name: "rapportd" });
  });

  it("keeps the full command name, not lsof's 9-character truncation", () => {
    // Without `+c 0` this reads "figma_age", which would break any join
    // against the software inventory.
    expect(parseLsofListeners(OUTPUT).get(44960)!.name).toBe("figma_agent");
  });

  it("ignores the header and junk", () => {
    expect(parseLsofListeners("").size).toBe(0);
    expect(parseLsofListeners("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME").size).toBe(0);
    expect(parseLsofListeners("garbage\nmore garbage").size).toBe(0);
  });
});

describe("parsePsPaths (macOS)", () => {
  it("keeps a path containing spaces", () => {
    // Application Support paths are full of them; a naive split loses
    // everything after the first space.
    const out = parsePsPaths(
      "76553 /Users/j/Library/Application Support/Figma/FigmaAgent.app/Contents/MacOS/figma_agent\n" +
        " 1012 /usr/libexec/rapportd"
    );
    expect(out.get(76553)).toBe(
      "/Users/j/Library/Application Support/Figma/FigmaAgent.app/Contents/MacOS/figma_agent"
    );
    expect(out.get(1012)).toBe("/usr/libexec/rapportd");
  });
});

describe("parseNetstatPids (Windows)", () => {
  const OUTPUT = [
    "Active Connections",
    "  Proto  Local Address          Foreign Address        State           PID",
    "  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4",
    "  TCP    127.0.0.1:5985         0.0.0.0:0              LISTENING       1234",
    "  TCP    10.0.0.4:49670         10.0.0.9:443           ESTABLISHED     5678"
  ].join("\n");

  it("takes the PID from the last column and skips non-listening rows", () => {
    const out = parseNetstatPids(OUTPUT);
    expect(out.get(443)).toBe(4);
    expect(out.get(5985)).toBe(1234);
    expect(out.has(49670)).toBe(false);
  });
});

describe("parseTasklist (Windows)", () => {
  it("maps PIDs to image names from CSV", () => {
    const out = parseTasklist(
      '"System","4","Services","0","1,234 K"\n"nginx.exe","1234","Console","1","8,000 K"'
    );
    expect(out.get(4)).toBe("System");
    expect(out.get(1234)).toBe("nginx.exe");
  });

  it("survives an empty or headerless dump", () => {
    expect(parseTasklist("").size).toBe(0);
  });
});

describe("parseProcNetTcpInodes (Linux)", () => {
  const header =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

  it("pairs the listening port with its socket inode", () => {
    const table =
      header +
      "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 987654\n";
    expect(parseProcNetTcpInodes(table).get(443)).toBe("987654");
  });

  it("skips non-listening rows and inode 0", () => {
    const table =
      header +
      "   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 111\n" +
      "   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0\n";
    expect(parseProcNetTcpInodes(table).size).toBe(0);
  });
});

describe("resolveListenerOwners", () => {
  it("returns nothing for an empty port list without shelling out", async () => {
    expect((await resolveListenerOwners([])).size).toBe(0);
  });

  it("returns nothing on an unsupported platform instead of throwing", async () => {
    expect((await resolveListenerOwners([443], "aix" as NodeJS.Platform)).size).toBe(0);
  });
});
