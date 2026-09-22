// test/domain/cdp-file-cache-repo.test.ts
//
// Ola 1.1 — la caché del descubrimiento de ficheros contra SQLite REAL
// (fichero temporal, mismo aislamiento que cdp-baseline-repo.test.ts).
// Lo que importa: acierta solo con (tamaño, mtime, VERSIÓN) iguales —
// otra versión del agente relee— y la poda respeta las raíces a medias.

import { describe, it, expect, beforeAll, vi } from "vitest";
import os from "os";
import path from "path";
import fs from "fs";

const TMP_DB = path.join(os.tmpdir(), `tracenium-cdp-filecache-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), `tracenium-cdp-filecache-${process.pid}.db`)
  };
});

beforeAll(() => {
  for (const s of ["", "-wal", "-shm"]) {
    try { fs.unlinkSync(TMP_DB + s); } catch { /* ignore */ }
  }
});

import { openCdpFileScanCache } from "../../src/domain/cdp-file-cache-repo";

const rec = { origin: "default" as const, kind: "pem" as const, certs: [{ der: "MIIB", hasPrivateKey: false }], keys: [] };

describe("openCdpFileScanCache", () => {
  it("⭐ acierta solo con tamaño, mtime y versión iguales", () => {
    const v1 = openCdpFileScanCache("1:1.1.80");
    v1.put("/etc/a.crt", 10, 1000, rec);
    expect(v1.get("/etc/a.crt", 10, 1000)).toEqual(rec);
    expect(v1.get("/etc/a.crt", 11, 1000)).toBeUndefined();
    expect(v1.get("/etc/a.crt", 10, 1001)).toBeUndefined();
    // Un agente nuevo puede sacar campos nuevos del mismo fichero: relee.
    expect(openCdpFileScanCache("1:1.1.81").get("/etc/a.crt", 10, 1000)).toBeUndefined();
  });

  it("la poda quita lo no visto salvo lo de una raíz a medias", () => {
    const c = openCdpFileScanCache("1:x");
    c.put("/etc/seen.crt", 1, 1, rec);
    c.put("/etc/gone.crt", 1, 1, rec);
    c.put("/opt/unvisited.crt", 1, 1, rec);
    c.prune(new Set(["/etc/seen.crt"]), ["/opt/"]);
    expect(c.get("/etc/seen.crt", 1, 1)).toBeDefined();
    expect(c.get("/etc/gone.crt", 1, 1)).toBeUndefined();
    expect(c.get("/opt/unvisited.crt", 1, 1)).toBeDefined();
  });
});
