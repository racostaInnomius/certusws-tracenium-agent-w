// test/update/update-source-report.test.ts
//
// Who served the installer for the version now running.
//
// The value of this field is entirely in its refusal to guess. It exists to
// answer "how much of the fleet came over the LAN"; a report that attributes
// bytes to the wrong version manufactures LAN traffic that never happened, and
// a KPI you cannot trust is worse than one you do not have.

import { describe, it, expect } from "vitest";
import {
  NAMESPACE,
  decideSourceReport,
  sourceReportPayload,
} from "../../src/update/update-source-report";

describe("decideSourceReport", () => {
  it("reports the tier when the attempted version is the one now running", () => {
    expect(
      decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toEqual({ version: "1.1.49", servedBy: "dp" });
  });

  it("carries origin as a real answer, not a blank", () => {
    expect(
      decideSourceReport({ lastServedBy: "origin", lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toEqual({ version: "1.1.49", servedBy: "origin" });
  });

  // The decisive case. A failed or abandoned update leaves lastServedBy behind;
  // attributing it to whatever the endpoint ended up running would invent LAN
  // traffic for a download that never landed.
  it("says nothing when the update did not land", () => {
    expect(
      decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, "1.1.48")
    ).toBeNull();
  });

  it("says nothing when no tier was recorded", () => {
    expect(decideSourceReport({ lastAttemptedVersion: "1.1.49" }, "1.1.49")).toBeNull();
    expect(
      decideSourceReport({ lastServedBy: null, lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toBeNull();
    expect(
      decideSourceReport({ lastServedBy: "  ", lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toBeNull();
  });

  it("says nothing when either version is missing", () => {
    expect(decideSourceReport({ lastServedBy: "dp" }, "1.1.49")).toBeNull();
    expect(
      decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, "")
    ).toBeNull();
    expect(
      decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, null)
    ).toBeNull();
  });

  it("survives a state file that is missing or unreadable", () => {
    expect(decideSourceReport(null, "1.1.49")).toBeNull();
    expect(decideSourceReport(undefined, "1.1.49")).toBeNull();
    expect(decideSourceReport({}, "1.1.49")).toBeNull();
  });
});

describe("sourceReportPayload", () => {
  // The sender loop derives the wire `namespace` and `namespaces` from these
  // keys, and the backend validator cross-checks the two against each other. A
  // payload shaped any other way is rejected at the envelope.
  it("nests the report under its namespace so the envelope validates", () => {
    expect(sourceReportPayload({ version: "1.1.49", servedBy: "dp" })).toEqual({
      namespaces: { agent_update: { version: "1.1.49", servedBy: "dp" } },
    });
  });

  it("keys the payload with the exported namespace", () => {
    const payload = sourceReportPayload({ version: "1.1.49", servedBy: "dp" }) as any;
    expect(Object.keys(payload.namespaces)).toEqual([NAMESPACE]);
  });

  // The outbox dedupes identical pending payloads by hash, so two boots before
  // a successful drain must not produce two rows.
  it("is stable for the same report, so the outbox can dedupe it", () => {
    const a = sourceReportPayload({ version: "1.1.49", servedBy: "dp" });
    const b = sourceReportPayload({ version: "1.1.49", servedBy: "dp" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
