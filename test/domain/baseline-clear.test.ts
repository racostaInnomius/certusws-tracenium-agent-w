// test/domain/baseline-clear.test.ts
//
// clearSoftwareBaseline / clearPrinterBaseline are the mechanism behind the
// control plane's `reset_baseline` self-heal: wiping the local baseline makes
// the next collection tick take the provider's first-run branch and re-send a
// FULL items[] snapshot (not an elided delta). Before this fix, reset_baseline
// cleared a `namespaceHash:amp` key that AMP never reads — a silent no-op that
// left an emptied backend projection permanently empty.
//
// We drive the REAL SQLite repos (shared agent.db) against a temp file so the
// clear actually round-trips through the DB, then assert the tables are empty.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";

// Built inside the (hoisted) mock factory too — keep the name in sync.
const TMP_DB = path.join(os.tmpdir(), `tracenium-baseline-clear-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  const dbPath = nodePath.join(nodeOs.tmpdir(), `tracenium-baseline-clear-${process.pid}.db`);
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () => dbPath,
    getLegacySoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), "does-not-exist.db")
  };
});

beforeAll(() => {
  // Start from a clean slate so a stale file from a crashed prior run
  // (same pid reused) can't leak rows into these assertions.
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
});

import {
  upsertSoftwareBaseline,
  loadSoftwareBaseline,
  clearSoftwareBaseline
} from "../../src/domain/software-baseline-repo";
import {
  upsertPrinterBaseline,
  loadPrinterBaseline,
  clearPrinterBaseline
} from "../../src/domain/printer-baseline-repo";
import type { Printer } from "../../src/domain/printer";

afterAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
});

describe("baseline clear (reset_baseline self-heal)", () => {
  it("clearSoftwareBaseline empties the software baseline so the next tick re-sends full", () => {
    upsertSoftwareBaseline([
      { installId: "app-1", name: "Firefox", source: "windows-registry", detectedAtUtc: "2026-01-01T00:00:00.000Z" } as any,
      { installId: "app-2", name: "7-Zip", source: "windows-registry", detectedAtUtc: "2026-01-01T00:00:00.000Z" } as any
    ]);
    expect(loadSoftwareBaseline().length).toBe(2);

    clearSoftwareBaseline();

    // Empty baseline ⇒ provider's `previous.length === 0` first-run branch fires.
    expect(loadSoftwareBaseline().length).toBe(0);
  });

  it("clearPrinterBaseline empties the printer baseline", () => {
    const printers: Printer[] = [
      { installId: "windows-spooler:HP", name: "HP LaserJet", source: "windows-spooler", isDefault: true, isNetwork: false, isShared: false, detectedAtUtc: "2026-01-01T00:00:00.000Z" } as any
    ];
    upsertPrinterBaseline(printers);
    expect(loadPrinterBaseline().length).toBe(1);

    clearPrinterBaseline();

    expect(loadPrinterBaseline().length).toBe(0);
  });

  it("clearing one baseline does not touch the other (independent wipes)", () => {
    upsertSoftwareBaseline([
      { installId: "app-x", name: "Chrome", source: "windows-registry", detectedAtUtc: "2026-01-01T00:00:00.000Z" } as any
    ]);
    upsertPrinterBaseline([
      { installId: "cups:office", name: "Office", source: "cups", isDefault: false, isNetwork: true, isShared: false, detectedAtUtc: "2026-01-01T00:00:00.000Z" } as any
    ]);

    clearSoftwareBaseline();

    expect(loadSoftwareBaseline().length).toBe(0);
    expect(loadPrinterBaseline().length).toBe(1);

    clearPrinterBaseline();
    expect(loadPrinterBaseline().length).toBe(0);
  });
});
