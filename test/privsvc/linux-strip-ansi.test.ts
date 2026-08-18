// test/privsvc/linux-strip-ansi.test.ts
//
// apt 3.0 colourises its output even when stdout/stderr are pipes rather than
// a terminal. Two consequences, both seen or narrowly avoided in the field:
//
//   1. The escape bytes were stored verbatim in the scan `note` and shipped to
//      the dashboard tooltip. A real row from a production host held eight raw
//      ESC bytes; an operator would have been shown mojibake instead of the
//      reason their server stopped reporting patches.
//
//   2. The upgradable-package parser matches on line shape. Colourised stdout
//      simply would not match, producing zero items — indistinguishable from a
//      machine with nothing to upgrade. That silent-failure mode is precisely
//      what this plugin was already bitten by on Windows.
//
// The fixture below is the real string recorded for SRVOC-MainAgent.

import { describe, it, expect } from "vitest";
import { stripAnsi } from "../../privsvc/linux/src/patch-management";

const ESC = "\x1b";

describe("stripAnsi", () => {
  it("cleans the exact stderr recorded in production", () => {
    const raw =
      `apt list failed: ${ESC}[1;33mWarning: ${ESC}[0m${ESC}[1mUnable to read ` +
      `/etc/apt/apt.conf.d/ - opendir (13: Permission denied)${ESC}[0m\n` +
      `${ESC}[1;31mError: ${ESC}[0m${ESC}[1mError reading the CPU table${ESC}[0m`;

    const out = stripAnsi(raw);

    expect(out).not.toContain(ESC);
    expect(out).toBe(
      "apt list failed: Warning: Unable to read /etc/apt/apt.conf.d/ - opendir (13: Permission denied)\n" +
        "Error: Error reading the CPU table"
    );
  });

  it("leaves the message itself untouched", () => {
    // The diagnostic is the whole point; stripping colour must not eat words,
    // punctuation, paths, or the error codes an operator will search for.
    const plain =
      "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)";
    expect(stripAnsi(plain)).toBe(plain);
  });

  it("keeps package lines parseable when apt colourises stdout", () => {
    // The dangerous case: colour inside the line the scanner regex matches on.
    const coloured =
      `${ESC}[1mopenssl${ESC}[0m/jammy-security 3.0.2-0ubuntu1.21 amd64 ` +
      `[upgradable from: 3.0.2-0ubuntu1.18]`;
    const line = stripAnsi(coloured);

    const match = line.match(
      /^([^/]+)\/(\S+)\s+(\S+)\s+\S+\s*(?:\[upgradable from:\s*(\S+)\])?/
    );
    expect(match, "colourised line must still parse").not.toBeNull();
    expect(match![1]).toBe("openssl");
    expect(match![2]).toBe("jammy-security");
    expect(match![3]).toBe("3.0.2-0ubuntu1.21");
  });

  it("removes cursor and erase sequences, not just colour", () => {
    // Progress meters emit these; apt-get with a terminal-ish stderr can too.
    expect(stripAnsi(`${ESC}[2K${ESC}[1Gdownloading${ESC}[0m`)).toBe("downloading");
    expect(stripAnsi(`${ESC}[?25lhidden cursor${ESC}[?25h`)).toBe("hidden cursor");
  });

  it("removes OSC title sequences terminated either way", () => {
    expect(stripAnsi(`${ESC}]0;title\x07after`)).toBe("after");
    expect(stripAnsi(`${ESC}]0;title${ESC}\\after`)).toBe("after");
  });

  it("is a no-op on empty and plain input", () => {
    expect(stripAnsi("")).toBe("");
    expect(stripAnsi("no output")).toBe("no output");
  });
});
