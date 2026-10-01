// test/plugins/pmp-collect-tray.test.ts
//
// collectPMP es el punto por el que pasa TODO escaneo de parches: tiene que
// dejar la bandeja con lo que vio ese escaneo (1-oct, JPR-MacBookPro), y un
// fallo al escribirla no puede tirar el escaneo.

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import os from "os";

const scanned = {
  schemaVersion: "1.0",
  collector: { plugin: "pmp", version: "1.1.88" },
  hasChanges: true,
  overall: { status: "healthy", score: 100 },
  scan: { scannedAtUtc: "2026-10-01T03:16:59.831Z", source: "linux_apt", mode: "inventory_only", installedPatchCount: 0, securityPatchCount: 0, items: [] },
  remediation: { status: "failed", rebootRequired: false, installedCount: 0, failedCount: 1, lastError: "patch_install failed", results: [] },
};

vi.mock("../../src/plugins/pmp/providers/linux", () => ({ collectLinuxPmp: async () => scanned }));
vi.mock("../../src/plugins/pmp/providers/windows", () => ({ collectWindowsPmp: async () => scanned }));
vi.mock("../../src/plugins/pmp/providers/macos", () => ({ collectMacosPmp: async () => scanned }));
vi.mock("../../src/plugins/pmp/os-update-action", () => ({ refreshOsUpdateActionsAfterScan: () => {} }));

import { collectPMP } from "../../src/plugins/pmp";

beforeEach(() => {
  vi.spyOn(os, "platform").mockReturnValue("linux");
});
afterEach(() => vi.restoreAllMocks());

describe("collectPMP → bandeja", () => {
  it("⭐ cada escaneo escribe el bloque de parches de la bandeja", async () => {
    const setPatch = vi.fn();
    const ns = await collectPMP({ trayStatus: { setPatch }, config: { agentVersion: "1.1.88" } } as any);
    expect(ns).toBe(scanned);
    expect(setPatch).toHaveBeenCalledWith({
      status: "Up to date",
      lastScanAtUtc: "2026-10-01T03:16:59.831Z",
      rebootRequired: false,
      lastError: undefined,
    });
  });

  it("si escribir la bandeja falla, el escaneo sigue", async () => {
    const warn = vi.fn();
    const ns = await collectPMP({
      trayStatus: { setPatch: () => { throw new Error("disk full"); } },
      logger: { warn },
      config: { agentVersion: "1.1.88" },
    } as any);
    expect(ns).toBe(scanned);
    expect(warn).toHaveBeenCalled();
  });
});
