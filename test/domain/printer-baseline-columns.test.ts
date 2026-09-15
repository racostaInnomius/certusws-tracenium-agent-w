// test/domain/printer-baseline-columns.test.ts
//
// `shareName` y `hostAddress` (2026-09-15) viven en una tabla que YA existe en
// cada equipo. Si la baseline no los guardara —o no migrara el fichero viejo—
// la cola del servidor de impresión volvería de SQLite sin ellos y el delta la
// marcaría "actualizada" en CADA ciclo: un envío por ciclo, para siempre.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";

const TMP_DB = path.join(os.tmpdir(), `tracenium-printer-columns-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), `tracenium-printer-columns-${process.pid}.db`),
    getLegacySoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), "does-not-exist.db")
  };
});

beforeAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
  // El fichero tal como lo deja un agente anterior: sin las columnas nuevas y
  // con una fila dentro.
  const old = new Database(TMP_DB);
  old.exec(`
    CREATE TABLE printer_baseline (
      install_id TEXT PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
      driver TEXT, port TEXT, is_default INTEGER NOT NULL DEFAULT 0,
      is_network INTEGER NOT NULL DEFAULT 0, is_shared INTEGER NOT NULL DEFAULT 0,
      location TEXT, comments TEXT, status TEXT, detected_at_utc TEXT NOT NULL
    );
    INSERT INTO printer_baseline (install_id, name, source, port, is_network, detected_at_utc)
    VALUES ('windows-spooler:\\\\SRV\\Cola', '\\\\SRV\\Cola', 'windows-spooler', '\\\\SRV', 1, '2026-09-01T00:00:00.000Z');
  `);
  old.close();
});

afterAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
});

import { upsertPrinterBaseline, loadPrinterBaseline } from "../../src/domain/printer-baseline-repo";
import { computePrinterDelta } from "../../src/domain/printer-inventory-delta";
import type { Printer } from "../../src/domain/printer";

describe("printer baseline — shareName y hostAddress", () => {
  it("migra el fichero viejo sin perder la fila que ya tenía", () => {
    const rows = loadPrinterBaseline();
    expect(rows).toHaveLength(1);
    expect(rows[0].shareName).toBeNull();
    expect(rows[0].hostAddress).toBeNull();
  });

  it("⚠️ una cola de servidor vuelve de SQLite igual y el delta NO la ve cambiada", () => {
    const cola: Printer = {
      installId: "windows-spooler:CasticoPrintroom",
      name: "CasticoPrintroom",
      source: "windows-spooler",
      driver: "HP Universal Printing PCL 6",
      port: "IP_10.20.11.39",
      isDefault: false,
      isNetwork: true,
      isShared: true,
      shareName: "CasticoPrintroom",
      hostAddress: "10.20.11.39",
      location: "Castico",
      comments: null,
      status: "online",
      detectedAtUtc: "2026-09-15T00:00:00.000Z"
    };
    upsertPrinterBaseline([cola]);
    const guardada = loadPrinterBaseline().find((p) => p.installId === cola.installId)!;
    expect(guardada.shareName).toBe("CasticoPrintroom");
    expect(guardada.hostAddress).toBe("10.20.11.39");

    // computePrinterDelta(actual, anterior): lo recién leído contra la baseline.
    const r = computePrinterDelta(
      [...loadPrinterBaseline().filter((p) => p.installId !== cola.installId), cola],
      loadPrinterBaseline()
    );
    expect(r.delta.updated).toHaveLength(0);
    expect(r.hasChanges).toBe(false);
  });

  it("un cambio de dirección SÍ es una actualización", () => {
    const antes = loadPrinterBaseline();
    const despues = antes.map((p) =>
      p.installId === "windows-spooler:CasticoPrintroom" ? { ...p, hostAddress: "10.20.11.40" } : p
    );
    expect(computePrinterDelta(despues, antes).delta.updated.map((p) => p.installId)).toEqual([
      "windows-spooler:CasticoPrintroom"
    ]);
  });
});
