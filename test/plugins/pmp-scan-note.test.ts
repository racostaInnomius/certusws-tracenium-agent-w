// test/plugins/pmp-scan-note.test.ts
//
// Guards the diagnostic that explains an empty scan.
//
// Origin: tenant 111 had twelve servers reporting "Inventory Only, 0 patches"
// for weeks. The compliance collector saw 4–773 patches on the very same
// machines, so the data existed — only `patch.scan` was starving. privsvc knew
// why (an stderr tail, a timeout) and said so in its `note`, but the field was
// dropped on the way out, leaving twelve black boxes that looked healthy.
//
// These tests pin the two properties that matter: a real reason is never
// invented, and a real reason is never swallowed.

import { describe, it, expect } from "vitest";
import { deriveScanNote } from "../../src/plugins/pmp/scan-note";

describe("deriveScanNote", () => {
  it("passes privsvc's own note through verbatim", () => {
    // This is the string that actually explains the fault. Rewording or
    // truncating it would destroy the only evidence there is.
    const note = "empty_stdout; stderr_tail: 0x80240438 WU_E_NO_SERVER_CORE_SUPPORT";
    expect(deriveScanNote({ status: "unknown", note })).toBe(note);
  });

  it("prefers privsvc's note over the synthesized one", () => {
    const out = deriveScanNote({ status: "unknown", note: "real reason" });
    expect(out).toBe("real reason");
    expect(out).not.toContain("with no items");
  });

  it("synthesizes a note when the status is unexplained and privsvc gave none", () => {
    expect(deriveScanNote({ status: "unknown" })).toBe(
      'patch scan returned status="unknown" with no items'
    );
  });

  it.each(["updates_available", "healthy"])(
    "stays silent for the self-explanatory status %s",
    (status) => {
      // A note here would be noise on every healthy machine in the fleet, and
      // noise on the healthy path is how real notes stop being read.
      expect(deriveScanNote({ status })).toBeUndefined();
    }
  );

  it("stays silent when there is nothing to report", () => {
    expect(deriveScanNote(null)).toBeUndefined();
    expect(deriveScanNote(undefined)).toBeUndefined();
    expect(deriveScanNote({})).toBeUndefined();
  });

  it("treats a blank or whitespace-only note as absent", () => {
    // An empty string is falsy-adjacent but would still render as a tooltip
    // with nothing in it — worse than no tooltip, because it looks broken.
    expect(deriveScanNote({ status: "healthy", note: "   " })).toBeUndefined();
    expect(deriveScanNote({ status: "unknown", note: "" })).toBe(
      'patch scan returned status="unknown" with no items'
    );
  });

  it("trims a padded note rather than passing the padding along", () => {
    expect(deriveScanNote({ status: "unknown", note: "  timed out  " })).toBe("timed out");
  });

  it("ignores a non-string note instead of stringifying it", () => {
    // privsvc is a separate process; a malformed payload must not turn into
    // "[object Object]" in the operator's tooltip.
    expect(deriveScanNote({ status: "unknown", note: { a: 1 } as unknown })).toBe(
      'patch scan returned status="unknown" with no items'
    );
    expect(deriveScanNote({ status: 42 as unknown, note: undefined })).toBeUndefined();
  });

  it("reports an unexplained error status", () => {
    // The status most likely to reach a human, and the one they most need a
    // reason for.
    expect(deriveScanNote({ status: "error" })).toContain('status="error"');
  });
});
