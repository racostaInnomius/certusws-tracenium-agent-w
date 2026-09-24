// test/domain/software-baseline-installed-on.test.ts
//
// La fecha de instalación en la baseline de SQLite. `isAppUpdated` la compara,
// así que si la baseline no la guardara, cada ciclo diría "cambió" para
// siempre: el bucle del 18-sep (ver software-baseline-identity-columns.test.ts).

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";

const TMP_DB = path.join(os.tmpdir(), `tracenium-software-installed-on-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () =>
      nodePath.join(nodeOs.tmpdir(), `tracenium-software-installed-on-${process.pid}.db`),
    getLegacySoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), "does-not-exist.db")
  };
});

beforeAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
  // El fichero tal como lo deja un agente anterior: sin las cuatro columnas de
  // identidad y con una fila dentro.
  const old = new Database(TMP_DB);
  old.exec(`
    CREATE TABLE software_baseline (
      install_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT,
      publisher TEXT,
      source TEXT NOT NULL,
      install_location TEXT,
      package_family_name TEXT,
      detected_at_utc TEXT NOT NULL
    );
    INSERT INTO software_baseline (install_id, name, version, publisher, source, detected_at_utc)
    VALUES ('sha256:0498627270', 'EPSON Scan OCR Component', '3.00.06', 'Seiko Epson Corporation',
            'win32-registry', '2026-09-17T04:26:01.652Z');
  `);
  old.close();
});

afterAll(() => {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
});

import { loadSoftwareBaseline, upsertSoftwareBaseline } from "../../src/domain/software-baseline-repo";
import { computeSoftwareDelta } from "../../src/domain/software-inventory-delta";
import type { SoftwareApplication } from "../../src/domain/normalize-app";

const EPSON: SoftwareApplication = {
  installId: "sha256:0498627270",
  name: "EPSON Scan OCR Component",
  version: "3.00.06",
  publisher: "Seiko Epson Corporation",
  source: "win32-registry",
  detectedAtUtc: "2026-09-17T14:12:11.316Z",
  installedOn: "2024-03-15"
};

describe("baseline de software — installed_on", () => {
  it("migra el fichero viejo sin perder la fila", () => {
    const rows = loadSoftwareBaseline();
    expect(rows).toHaveLength(1);
    expect(rows[0].installedOn).toBeUndefined();
  });

  it("la primera pasada tras actualizar el agente es un cambio (rellena la fecha)", () => {
    expect(computeSoftwareDelta([EPSON], loadSoftwareBaseline()).delta.updated).toHaveLength(1);
  });

  it("⭐ guardada y releída, la misma app ya no vuelve a salir como actualizada", () => {
    upsertSoftwareBaseline([EPSON]);
    expect(loadSoftwareBaseline()[0].installedOn).toBe("2024-03-15");
    expect(computeSoftwareDelta([EPSON], loadSoftwareBaseline()).hasChanges).toBe(false);
  });

  it("una lectura sin fecha no la borra de la comparación ni dispara un cambio", () => {
    const { installedOn: _omit, ...sinFecha } = EPSON;
    expect(computeSoftwareDelta([sinFecha as SoftwareApplication], loadSoftwareBaseline()).hasChanges).toBe(false);
  });
});
