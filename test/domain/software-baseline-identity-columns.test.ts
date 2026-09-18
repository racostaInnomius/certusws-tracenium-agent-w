// test/domain/software-baseline-identity-columns.test.ts
//
// 🔴 El bucle de AMP, medido en prod el 18-sep (T111, WES-MSIG-RC-JL): 147
// mensajes en una hora, todos con `hasChanges=true` y 98 apps "actualizadas"
// que no habían cambiado de versión ni de editor. `isAppUpdated` compara la
// identidad de ADR-0019 (productCode, uninstallString…) y la baseline de
// SQLite no guardaba ninguna de las cuatro: volvía en `undefined`, el
// inventario recién recogido sí las traía, y el delta decía "cambió" en cada
// ciclo. Cada ciclo es una reevaluación completa del equipo en el backend.
//
// Esta prueba fija las dos mitades: el fichero viejo se migra sin perder lo
// que ya tenía, y una app guardada vuelve IGUAL a como se guardó.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";

const TMP_DB = path.join(os.tmpdir(), `tracenium-software-identity-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () =>
      nodePath.join(nodeOs.tmpdir(), `tracenium-software-identity-${process.pid}.db`),
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
  productCode: "{E38D5E1E-8B69-4E7F-9C2D-0C3E7E2C0A11}",
  uninstallString: "MsiExec.exe /X{E38D5E1E-8B69-4E7F-9C2D-0C3E7E2C0A11}",
  quietUninstallString: "MsiExec.exe /X{E38D5E1E-8B69-4E7F-9C2D-0C3E7E2C0A11} /qn",
  uninstallKeyPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{E38D5E1E-8B69-4E7F-9C2D-0C3E7E2C0A11}"
};

describe("baseline de software — identidad de ADR-0019", () => {
  it("migra el fichero viejo sin perder la fila que ya tenía", () => {
    const rows = loadSoftwareBaseline();
    expect(rows).toHaveLength(1);
    expect(rows[0].installId).toBe("sha256:0498627270");
    expect(rows[0].productCode).toBeUndefined();
    expect(rows[0].uninstallString).toBeUndefined();
  });

  it("la primera pasada tras actualizar el agente SÍ es un cambio (rellena la identidad)", () => {
    const r = computeSoftwareDelta([EPSON], loadSoftwareBaseline());
    expect(r.delta.updated.map(a => a.installId)).toEqual(["sha256:0498627270"]);
    expect(r.hasChanges).toBe(true);
  });

  it("⚠️ guardada y releída, la MISMA app ya no vuelve a salir como actualizada", () => {
    upsertSoftwareBaseline([EPSON]);

    const guardada = loadSoftwareBaseline().find(a => a.installId === EPSON.installId)!;
    expect(guardada.productCode).toBe(EPSON.productCode);
    expect(guardada.uninstallString).toBe(EPSON.uninstallString);
    expect(guardada.quietUninstallString).toBe(EPSON.quietUninstallString);
    expect(guardada.uninstallKeyPath).toBe(EPSON.uninstallKeyPath);

    // El ciclo siguiente: el mismo inventario contra lo que quedó en SQLite.
    const r = computeSoftwareDelta([EPSON], loadSoftwareBaseline());
    expect(r.delta.updated).toHaveLength(0);
    expect(r.delta.added).toHaveLength(0);
    expect(r.hasChanges).toBe(false);
  });

  it("la hora de recogida no es un cambio: sólo cambia `detectedAtUtc`", () => {
    const otraPasada = { ...EPSON, detectedAtUtc: "2026-09-18T09:00:00.000Z" };
    const r = computeSoftwareDelta([otraPasada], loadSoftwareBaseline());
    expect(r.hasChanges).toBe(false);
  });

  it("un upgrade que cambia el ProductCode SÍ es una actualización", () => {
    const upgrade = {
      ...EPSON,
      productCode: "{11111111-2222-3333-4444-555555555555}",
      uninstallString: "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"
    };
    const r = computeSoftwareDelta([upgrade], loadSoftwareBaseline());
    expect(r.delta.updated.map(a => a.installId)).toEqual(["sha256:0498627270"]);

    // Y se guarda: no se queda pidiendo el cambio para siempre.
    upsertSoftwareBaseline([upgrade]);
    expect(computeSoftwareDelta([upgrade], loadSoftwareBaseline()).hasChanges).toBe(false);
  });
});
