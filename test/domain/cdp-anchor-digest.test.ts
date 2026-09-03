// test/domain/cdp-anchor-digest.test.ts
//
// ADR-0011 fase 0, paso 1 — la memoria que hace que un cambio de pin
// llegue al control plane.
//
// ⚠️ Lo que se defiende aquí tiene un modo de fallo silencioso y muy
// concreto. El planificador descarta el namespace CDP ENTERO cuando
// `hasChanges` es falso (`scheduler.ts`, «Skipping CDP FACTS enqueue»),
// así que colgar el estado del pin del inventario sin más significaría
// que una flota estable —la normal— no reportaría su pin casi nunca.
//
// Sería reproducir un nivel más arriba el fallo que este paso viene a
// arreglar: el modo `observe` observando hacia algo que nadie lee.

import { describe, it, expect, beforeAll } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";
import { vi } from "vitest";

const TMP_DB = path.join(os.tmpdir(), `tracenium-cdp-anchor-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  const dbPath = nodePath.join(nodeOs.tmpdir(), `tracenium-cdp-anchor-${process.pid}.db`);
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
  cdpAnchorDigestChanged,
  commitCdpAnchorDigest,
  hashCdpAnchorState
} from "../../src/domain/cdp-baseline-repo";

const ESTADO = {
  applicable: true,
  platform: "macos",
  mode: "observe",
  pinnedCount: 1,
  pinned: ["aa11"],
  last: null
};

describe("memoria del pin de anclas", () => {
  it("la primera vez cuenta como cambio: nunca se ha reportado", () => {
    expect(cdpAnchorDigestChanged(hashCdpAnchorState(ESTADO))).toBe(true);
  });

  it("tras confirmarlo, el mismo estado ya no fuerza envío", () => {
    const d = hashCdpAnchorState(ESTADO);
    commitCdpAnchorDigest(d);
    expect(cdpAnchorDigestChanged(d)).toBe(false);
  });

  it("⭐ un ancla NO FIJADA nueva sí fuerza envío", () => {
    // Es el evento entero de la fase 0. Si esto no disparara el envío,
    // el equipo vería el ancla desconocida, lo escribiría en su fichero
    // local, y el control plane no se enteraría jamás — que es
    // exactamente el estado del que venimos.
    commitCdpAnchorDigest(hashCdpAnchorState(ESTADO));
    const conHallazgo = {
      ...ESTADO,
      last: {
        at: "2026-09-03T10:00:00.000Z",
        mode: "observe",
        source: "renew",
        incoming: ["aa11", "bb22"],
        unpinned: ["bb22"],
        rejected: [],
        firstRun: false,
        unpinnedSeenTotal: 1
      }
    };
    expect(cdpAnchorDigestChanged(hashCdpAnchorState(conHallazgo))).toBe(true);
  });

  it("el digest no depende del orden de las claves", () => {
    // El estado llega por IPC como JSON; que el PrivSvc serialice en
    // otro orden no puede leerse como un cambio de pin, o cada ciclo
    // enviaría un falso positivo.
    const a = hashCdpAnchorState({ applicable: true, mode: "observe", pinnedCount: 0 });
    const b = hashCdpAnchorState({ pinnedCount: 0, mode: "observe", applicable: true });
    expect(a).toBe(b);
  });

  it("pasar de observe a enforce es un cambio reportable", () => {
    // Saber en qué modo está cada equipo es la mitad del paso 3: un
    // anillo en `enforce` que no se distinga de uno en `observe` hace
    // imposible medir el despliegue.
    const observe = hashCdpAnchorState(ESTADO);
    const enforce = hashCdpAnchorState({ ...ESTADO, mode: "enforce" });
    expect(observe).not.toBe(enforce);
  });
});
