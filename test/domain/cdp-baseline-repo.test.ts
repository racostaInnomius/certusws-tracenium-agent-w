// test/domain/cdp-baseline-repo.test.ts
//
// CDP delta contract: first scan → null (send full baseline); later
// scans → added/removed/updated vs the committed baseline. Drives the
// REAL SQLite repo against a temp file (same isolation pattern as
// baseline-clear.test.ts).

import { describe, it, expect, beforeAll } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";
import { vi } from "vitest";

const TMP_DB = path.join(os.tmpdir(), `tracenium-cdp-baseline-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  const dbPath = nodePath.join(nodeOs.tmpdir(), `tracenium-cdp-baseline-${process.pid}.db`);
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () => dbPath,
    getLegacySoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), "does-not-exist.db")
  };
});

beforeAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
});

import {
  clearCdpBaseline,
  commitCdpBaseline,
  computeCdpDelta
} from "../../src/domain/cdp-baseline-repo";
import type { CdpCertItem } from "../../src/domain/cdp-types";

function item(id: string, overrides: Partial<CdpCertItem> = {}): CdpCertItem {
  return {
    id,
    fingerprint256: `fp-${id}`,
    subjectCN: `cert-${id}`,
    notAfter: "2027-01-01T00:00:00.000Z",
    store: { id: "lm/my", name: "LocalMachine\\My", scope: "machine" },
    source: "store",
    ...overrides
  };
}

describe("cdp-baseline-repo delta contract", () => {
  it("returns null (full baseline send) when the baseline is empty", () => {
    clearCdpBaseline();
    expect(computeCdpDelta([item("a"), item("b")])).toBeNull();
  });

  it("detects added / removed / updated against the committed baseline", () => {
    clearCdpBaseline();
    commitCdpBaseline([item("a"), item("b")]);

    const delta = computeCdpDelta([
      item("a"),                                        // unchanged
      item("b", { notAfter: "2028-06-01T00:00:00.000Z" }), // renewed → updated
      item("c")                                         // new → added
      // "b" present, "a" present, no "removed"... and no item("d")
    ]);

    expect(delta).not.toBeNull();
    expect(delta!.added.map((i) => i.id)).toEqual(["c"]);
    expect(delta!.updated.map((i) => i.id)).toEqual(["b"]);
    expect(delta!.removed).toEqual([]);
  });

  it("reports removals and empties cleanly after recommit", () => {
    clearCdpBaseline();
    commitCdpBaseline([item("a"), item("b"), item("c")]);

    const scan = [item("a")];
    const delta = computeCdpDelta(scan)!;
    expect(delta.removed.map((r) => r.id).sort()).toEqual(["b", "c"]);

    // Committing the new scan makes the next diff a no-op.
    commitCdpBaseline(scan);
    const next = computeCdpDelta(scan)!;
    expect(next.added).toEqual([]);
    expect(next.updated).toEqual([]);
    expect(next.removed).toEqual([]);
  });
});
