// test/update/update-source-report.test.ts
//
// Who served the installer for the version now running.
//
// The value of this field is entirely in its refusal to guess. It exists to
// answer "how much of the fleet came over the LAN"; a report that attributes
// bytes to the wrong version manufactures LAN traffic that never happened, and
// a KPI you cannot trust is worse than one you do not have.

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import path from "path";
import {
  FACTS_SCHEMA_VERSION,
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

  // ⚠️ THE SHAPE THE PRODUCER ACTUALLY WRITES.
  //
  // `lastServedBy` is set ONLY inside the `if (viaDp)` branch of update-service.
  // A direct download leaves it EMPTY — it never contains the string "origin".
  // The first version of this module demanded a non-empty tier and so reported
  // nothing at all for WAN updates; the two endpoints that updated over the
  // internet right after it shipped produced no row. The old test passed
  // because it fed a value the producer cannot emit.
  it("reads an empty tier as origin, which is what a direct download leaves", () => {
    expect(
      decideSourceReport({ lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toEqual({ version: "1.1.49", servedBy: "origin" });
    expect(
      decideSourceReport({ lastServedBy: null, lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toEqual({ version: "1.1.49", servedBy: "origin" });
    expect(
      decideSourceReport({ lastServedBy: "   ", lastAttemptedVersion: "1.1.49" }, "1.1.49")
    ).toEqual({ version: "1.1.49", servedBy: "origin" });
  });

  // Silence has to land in the denominator: "how much came over the LAN" is not
  // a fraction if WAN updates simply vanish from the count.
  it("mirrors the default the ACK path already ships in production", () => {
    const viaDp = decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, "1.1.49");
    const direct = decideSourceReport({ lastAttemptedVersion: "1.1.49" }, "1.1.49");
    expect([viaDp?.servedBy, direct?.servedBy]).toEqual(["dp", "origin"]);
  });

  // The decisive case. A failed or abandoned update leaves lastServedBy behind;
  // attributing it to whatever the endpoint ended up running would invent LAN
  // traffic for a download that never landed.
  it("says nothing when the update did not land", () => {
    expect(
      decideSourceReport({ lastServedBy: "dp", lastAttemptedVersion: "1.1.49" }, "1.1.48")
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

  // An attempt that died before downloading leaves no tier — but it also leaves
  // the endpoint behind the version it was attempting, so the version guard
  // catches it before the origin default can turn a failure into a fake WAN
  // download. This is the pair that makes defaulting to origin safe.
  it("does not turn a failed attempt into a phantom origin download", () => {
    expect(decideSourceReport({ lastAttemptedVersion: "1.1.50" }, "1.1.49")).toBeNull();
  });

  // Re-reporting is deliberate: the backend upserts on (tenant, device,
  // version), so a boot that repeats the report is the same row written twice.
  // The first version cleared the state on enqueue and turned one lost delivery
  // into permanent loss.
  it("keeps reporting the same install across boots, idempotently", () => {
    const state = { lastServedBy: "dp", lastAttemptedVersion: "1.1.50" };
    const first = decideSourceReport(state, "1.1.50");
    const second = decideSourceReport(state, "1.1.50");
    expect(first).toEqual(second);
    expect(first).toEqual({ version: "1.1.50", servedBy: "dp" });
  });
});

describe("sourceReportPayload", () => {
  // The sender loop derives the wire `namespace` and `namespaces` from these
  // keys, and the backend validator cross-checks the two against each other. A
  // payload shaped any other way is rejected at the envelope.
  it("nests the report under its namespace so the envelope validates", () => {
    expect(sourceReportPayload({ version: "1.1.49", servedBy: "dp" })).toEqual({
      schemaVersion: FACTS_SCHEMA_VERSION,
      namespaces: { agent_update: { version: "1.1.49", servedBy: "dp" } },
    });
  });

  it("keys the payload with the exported namespace", () => {
    const payload = sourceReportPayload({ version: "1.1.49", servedBy: "dp" }) as any;
    expect(Object.keys(payload.namespaces)).toEqual([NAMESPACE]);
  });

  // The outbox dedupes identical pending payloads by hash, so two boots before
  // a successful drain must not produce two rows.
  // No timestamp anywhere in here, deliberately: the outbox dedupes identical
  // PENDING payloads by hash, and a `collectedAtUtc` would make every boot
  // produce a different hash and defeat it. The report has no time of its own —
  // it describes the running version, and reported_at is stamped server-side.
  it("is stable for the same report, so the outbox can dedupe it", () => {
    const a = sourceReportPayload({ version: "1.1.49", servedBy: "dp" });
    const b = sourceReportPayload({ version: "1.1.49", servedBy: "dp" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(JSON.stringify(a)).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });
});

// ⚠️ THE ENVELOPE, NOT JUST THE NAMESPACE.
//
// The control plane rejects a FACTS payload with no top-level `schemaVersion`
// — with status 2, which is PERMANENT, so the outbox discards the event and
// never retries. Three fleet-wide runs of this feature were built, enqueued and
// sent perfectly and then thrown away at the door, leaving one ACK line in the
// agent log as the only evidence.
//
// The cause was writing this payload by hand instead of copying the shape the
// real producer emits. So these tests read the real producer.
describe("sourceReportPayload — the envelope the backend demands", () => {
  const BUILDER = readFileSync(
    path.join(process.cwd(), "src/domain/device-facts-builder.ts"),
    "utf8"
  );

  it("declares schemaVersion, without which the payload is rejected outright", () => {
    const payload = sourceReportPayload({ version: "1.1.51", servedBy: "dp" }) as any;
    expect(payload.schemaVersion).toBeTruthy();
  });

  // Pinned against buildDeviceFacts — the only other thing that builds this
  // envelope. If it moves to 2.0 and this does not, the drift is caught here
  // rather than by a silent rejection in production.
  it("uses the same schemaVersion as the real facts builder", () => {
    const match = BUILDER.match(/schemaVersion:\s*"([^"]+)"/);
    expect(match, "buildDeviceFacts no longer declares a literal schemaVersion").toBeTruthy();
    expect(FACTS_SCHEMA_VERSION).toBe(match![1]);
  });

  it("carries the two fields the envelope validator requires", () => {
    const payload = sourceReportPayload({ version: "1.1.51", servedBy: "dp" }) as any;
    // Exactly what controlplane.ts checks, in order, before anything else.
    expect(payload.schemaVersion).toBeTruthy();
    expect(payload.namespaces).toBeTypeOf("object");
    expect(Array.isArray(payload.namespaces)).toBe(false);
  });

  it("still nests the report under its namespace", () => {
    const payload = sourceReportPayload({ version: "1.1.51", servedBy: "origin" }) as any;
    expect(payload.namespaces[NAMESPACE]).toEqual({
      version: "1.1.51",
      servedBy: "origin",
    });
  });
});
