// test/plugins/sdp-failure-detail.test.ts
//
// The `reason=` an operator reads when an install dies before the installer
// ever ran.
//
// Every real failure in production reached the dashboard as a bare
// `install_failed` with exit_code NULL — three out of three. The privsvc had
// written a message; the plugin kept only the code and dropped the rest one
// line before it could be sent. These tests pin the detail into the wire.

import { describe, it, expect } from "vitest";
import { failureReason } from "../../src/plugins/sdp/failure-detail";
import { readFileSync } from "fs";
import path from "path";

describe("failureReason", () => {
  it("carries what privsvc said, not just the code", () => {
    expect(failureReason("install_exec_failed", "msiexec not found in PATH", "install_failed"))
      .toBe("install_exec_failed: msiexec not found in PATH");
  });

  // The case that produced every real failure: privsvc named no code at all.
  it("falls back to the caller's label when there is no code", () => {
    expect(failureReason(undefined, undefined, "install_failed")).toBe("install_failed");
    expect(failureReason("", "", "uninstall_failed")).toBe("uninstall_failed");
  });

  it("still reports the message when only the code is missing", () => {
    expect(failureReason(null, "access is denied", "install_failed"))
      .toBe("install_failed: access is denied");
  });

  // "install_failed: install_failed" reads like a bug in us, not a diagnosis.
  it("does not repeat itself when the message echoes the code", () => {
    expect(failureReason("install_failed", "install_failed", "install_failed"))
      .toBe("install_failed");
  });

  // `;` separates segments in the ACK grammar; a message containing one would
  // split into a bogus key=value pair and corrupt everything after it.
  it("flattens anything that would break the ACK grammar", () => {
    const out = failureReason("io_error", "line one;\r\nline\ttwo", "install_failed");
    expect(out).not.toMatch(/[;\r\n\t]/);
    expect(out).toBe("io_error: line one line two");
  });

  it("collapses runs of whitespace so a table cell stays readable", () => {
    expect(failureReason("io_error", "a     b", "install_failed")).toBe("io_error: a b");
  });

  // The code is what an operator groups and searches by, so it must survive
  // whole; the sentence is what gets truncated.
  it("truncates the message, never the code", () => {
    const out = failureReason("some_specific_code", "x".repeat(500), "install_failed");
    expect(out.startsWith("some_specific_code: ")).toBe(true);
    expect(out.length).toBeLessThanOrEqual(180);
  });

  // The encoder slices extras at 200 and the backend reducer caps reason at
  // 240. Staying under both means nothing we emit is ever cut in transit.
  it("stays within what the encoder and the backend reducer accept", () => {
    const out = failureReason("c".repeat(300), "m".repeat(300), "install_failed");
    expect(out.length).toBeLessThanOrEqual(180);
  });

  it("survives non-string junk from the wire", () => {
    expect(failureReason({ a: 1 }, ["x"], "install_failed")).toBeTruthy();
    expect(failureReason(42, false, "install_failed")).toContain("42");
  });
});

// ── Regression guard ──────────────────────────────────────────────────
//
// index.ts carried a raw NUL byte inside a regex literal since its first
// commit. It compiled and ran correctly — but `file` classified the source as
// binary data, so grep and ripgrep SKIPPED IT ENTIRELY. Searches for symbols
// that were plainly in the file came back empty with no error, which is the
// worst kind of wrong: silent. `\x00` is the same regex and keeps it text.
describe("SDP sources stay searchable", () => {
  const files = ["index.ts", "failure-detail.ts", "reboot.ts", "mode.ts", "detection.ts"];

  it.each(files)("%s contains no raw NUL byte", (name) => {
    const buf = readFileSync(path.join(process.cwd(), "src/plugins/sdp", name));
    expect(buf.includes(0), `${name} has a NUL byte — grep will skip this file`).toBe(false);
  });

  it("still strips NUL from stderr, which is what the regex is for", () => {
    const src = readFileSync(
      path.join(process.cwd(), "src/plugins/sdp/index.ts"),
      "utf8"
    );
    expect(src).toContain(String.raw`replace(/\x00/g, "")`);
  });
});
