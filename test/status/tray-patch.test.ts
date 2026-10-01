// test/status/tray-patch.test.ts
//
// La bandeja dice lo que vio el último escaneo de parches, no el resultado de
// la última instalación congelado al arrancar (JPR-MacBookPro, 1-oct).

import { describe, expect, it } from "vitest";
import { trayPatchFromScan } from "../../src/status/tray-patch";
import type { PmpNamespace } from "../../src/domain/pmp-types";

const SCANNED = "2026-10-01T03:16:59.831Z";
const FAILED_INSTALL = {
  status: "failed" as const,
  rebootRequired: false,
  installedCount: 0,
  failedCount: 1,
  lastError: "patch_install failed",
  results: [],
};

const ns = (over: { overall?: PmpNamespace["overall"]; scan?: Partial<NonNullable<PmpNamespace["scan"]>> | null; remediation?: any } = {}): PmpNamespace => ({
  schemaVersion: "1.0",
  collector: { plugin: "pmp", version: "1.1.88" },
  hasChanges: true,
  overall: over.overall ?? { status: "healthy", score: 100 },
  scan:
    over.scan === null
      ? undefined
      : ({ scannedAtUtc: SCANNED, source: "apple_software_update", mode: "inventory_only", installedPatchCount: 0, securityPatchCount: 0, items: [], ...over.scan } as any),
  remediation: over.remediation ?? { status: "idle", rebootRequired: false, installedCount: 0, failedCount: 0, results: [] },
});

const item = (id: string) => ({ id, title: id }) as any;

describe("trayPatchFromScan", () => {
  it("⭐ instalación fallida y escaneo a cero (JPR-MacBookPro): «Up to date», sin el error viejo, con la hora del escaneo", () => {
    expect(trayPatchFromScan(ns({ remediation: FAILED_INSTALL }))).toEqual({
      status: "Up to date",
      lastScanAtUtc: SCANNED,
      rebootRequired: false,
      lastError: undefined,
    });
  });

  it("con algo pendiente, la instalación fallida sí se dice", () => {
    const p = trayPatchFromScan(ns({ overall: { status: "updates_available" }, scan: { items: [item("macOS 27.0.1-26A434")] }, remediation: FAILED_INSTALL }));
    expect(p).toMatchObject({ status: "1 update available", lastError: "patch_install failed" });
    expect(trayPatchFromScan(ns({ overall: { status: "updates_available" }, scan: { items: [item("a"), item("b")] } })).status).toBe("2 updates available");
  });

  it("❗ un escaneo que no contó (inventory_only, error) NO es «Up to date»", () => {
    expect(trayPatchFromScan(ns({ overall: { status: "inventory_only" }, scan: { note: "PrivSvc timeout" } }))).toMatchObject({
      status: "Scan incomplete",
      lastError: "PrivSvc timeout",
    });
    expect(trayPatchFromScan(ns({ overall: { status: "error", score: 0 } })).status).toBe("Scan failed");
    expect(trayPatchFromScan(ns({ scan: null })).status).toBe("Scan failed");
  });

  it("instalando: lo dice, sin error", () => {
    expect(trayPatchFromScan(ns({ remediation: { ...FAILED_INSTALL, status: "in_progress", lastError: undefined } }))).toMatchObject({
      status: "Installing updates",
      lastError: undefined,
    });
  });

  it("el reinicio sale del escaneo en vivo; sin él, de la última instalación", () => {
    expect(trayPatchFromScan(ns({ scan: { rebootPending: true } })).rebootRequired).toBe(true);
    expect(trayPatchFromScan(ns({ scan: { rebootPending: false }, remediation: { ...FAILED_INSTALL, rebootRequired: true } })).rebootRequired).toBe(false);
    expect(trayPatchFromScan(ns({ remediation: { ...FAILED_INSTALL, rebootRequired: true } })).rebootRequired).toBe(true);
  });
});
