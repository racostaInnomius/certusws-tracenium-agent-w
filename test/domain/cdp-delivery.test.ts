// test/domain/cdp-delivery.test.ts
//
// La línea base de CDP sólo avanza cuando el control plane CONFIRMA el envío.
//
// Producción, 2026-10-01: la base se guardaba al recoger, antes de entregar.
// Un envío que no llegaba (payload por encima del límite gRPC) quedaba dado
// por entregado y el agente no lo reenviaba nunca: 5 equipos con 500–2000
// certificados que el servidor nunca tuvo. SQLite REAL en un fichero
// temporal, como cdp-baseline-repo.test.ts.

import { describe, it, expect, beforeEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { vi } from "vitest";

const TMP_DB = path.join(os.tmpdir(), `tracenium-cdp-delivery-${process.pid}.db`);

vi.mock("../../src/bootstrap/paths", async () => {
  const nodeOs = await import("os");
  const nodePath = await import("path");
  const dbPath = nodePath.join(nodeOs.tmpdir(), `tracenium-cdp-delivery-${process.pid}.db`);
  return {
    ensureAgentDataDir: () => {},
    getSoftwareBaselineDbPath: () => dbPath,
    getLegacySoftwareBaselineDbPath: () => nodePath.join(nodeOs.tmpdir(), "does-not-exist.db")
  };
});

for (const suffix of ["", "-wal", "-shm"]) {
  try { fs.unlinkSync(TMP_DB + suffix); } catch { /* ignore */ }
}

import {
  clearCdpBaseline,
  commitCdpBaseline,
  computeCdpDelta,
  isCdpDeliveryAcked,
  promoteCdpDelivery,
  stageCdpDelivery
} from "../../src/domain/cdp-baseline-repo";
import { readAdcsCursor, readCdpMeta } from "../../src/domain/cdp-adcs-repo";
import { attachCdpDelivery, peekCdpDelivery, stageAttachedCdpDelivery } from "../../src/domain/cdp-delivery";
import type { CdpCertItem } from "../../src/domain/cdp-types";

const item = (id: string): CdpCertItem =>
  ({
    id,
    fingerprint256: id.padEnd(64, "0"),
    store: { id: "mac/system", name: "System", scope: "machine" },
    source: "store",
    hasPrivateKey: false,
    isCA: false
  }) as CdpCertItem;

const ids = (d: ReturnType<typeof computeCdpDelta>) => ({
  added: d?.added.map((i) => i.id) ?? null,
  removed: d?.removed.map((i) => i.id) ?? null
});

let outbox = 100;
beforeEach(() => {
  clearCdpBaseline();
  commitCdpBaseline([item("a")]); // lo que el servidor YA tiene
  outbox += 10;
});

describe("entrega confirmada", () => {
  it("⭐ un agente que viene de una versión que guardaba sin confirmar NO se da por confirmado", () => {
    // Tiene base (beforeEach), pero nadie le ha confirmado nunca una entrega:
    // su base puede afirmar certificados que el servidor no tiene. El plugin
    // mandará la lista completa una vez. (Primer test del fichero: aún no
    // se ha promovido nada en esta base.)
    expect(isCdpDeliveryAcked()).toBe(false);
  });

  it("⭐ un envío sin ACK no mueve la base: el siguiente escaneo REENVÍA los mismos cambios", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a"), item("b")], meta: {} });

    // El envío se perdió (nunca llega el ACK). Antes, aquí `b` ya no era un alta.
    expect(ids(computeCdpDelta([item("a"), item("b")]))).toEqual({ added: ["b"], removed: [] });
  });

  it("⭐ con el ACK_OK, la base avanza y se aplican digests y cursores", async () => {
    stageCdpDelivery(outbox, {
      baseline: [item("a"), item("b")],
      meta: { process_libs_digest: "d1", "adcs_last_request_id:*": "42" }
    });

    expect(promoteCdpDelivery(outbox)).toBe("promoted");
    expect(ids(computeCdpDelta([item("a"), item("b")]))).toEqual({ added: [], removed: [] });
    expect(readCdpMeta("process_libs_digest")).toBe("d1");
    expect(readAdcsCursor("*")).toBe(42);
  });

  it("los digests y cursores tampoco se mueven sin ACK", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a")], meta: { os_tls_digest: `sin-ack-${outbox}` } });
    expect(readCdpMeta("os_tls_digest")).not.toBe(`sin-ack-${outbox}`);
  });

  it("un ACK de un envío sin CDP no toca nada", async () => {
    expect(promoteCdpDelivery(outbox + 999)).toBe("none");
    expect(ids(computeCdpDelta([item("a")]))).toEqual({ added: [], removed: [] });
  });

  it("⚠️ un ACK viejo que llega tras el de un escaneo posterior no retrocede la base", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a"), item("b")], meta: {} });
    stageCdpDelivery(outbox + 1, { baseline: [item("a"), item("b"), item("c")], meta: {} });

    expect(promoteCdpDelivery(outbox + 1)).toBe("promoted");
    expect(promoteCdpDelivery(outbox)).toBe("none"); // ya superado y limpiado
    expect(ids(computeCdpDelta([item("a"), item("b"), item("c")]))).toEqual({ added: [], removed: [] });
  });

  it("en orden normal, cada ACK aplica el suyo", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a"), item("b")], meta: {} });
    stageCdpDelivery(outbox + 1, { baseline: [item("a"), item("b"), item("c")], meta: {} });

    expect(promoteCdpDelivery(outbox)).toBe("promoted");
    expect(ids(computeCdpDelta([item("a"), item("b"), item("c")]))).toEqual({ added: ["c"], removed: [] });
    expect(promoteCdpDelivery(outbox + 1)).toBe("promoted");
    expect(ids(computeCdpDelta([item("a"), item("b"), item("c")]))).toEqual({ added: [], removed: [] });
  });

  it("el outbox deduplica payloads idénticos con el mismo id: vale el paquete más reciente", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a"), item("b")], meta: {} });
    stageCdpDelivery(outbox, { baseline: [item("a"), item("b"), item("c")], meta: {} });
    promoteCdpDelivery(outbox);
    expect(ids(computeCdpDelta([item("a"), item("b"), item("c")]))).toEqual({ added: [], removed: [] });
  });

  it("isCdpDeliveryAcked: true tras el primer ACK que aplica un paquete", async () => {
    stageCdpDelivery(outbox, { baseline: [item("a")], meta: {} });
    promoteCdpDelivery(outbox);
    expect(isCdpDeliveryAcked()).toBe(true);
  });
});

describe("cdp-delivery: del namespace al outbox", () => {
  it("el paquete viaja pegado al namespace pero NO se serializa al payload", () => {
    const ns = { hasChanges: true };
    attachCdpDelivery(ns, { baseline: [item("a"), item("z")], meta: {} });
    expect(JSON.stringify(ns)).toBe('{"hasChanges":true}');
    expect(peekCdpDelivery(ns)?.baseline).toHaveLength(2);
  });

  it("⭐ se asocia al id del outbox al encolar, y se aplica con SU ack", () => {
    const ns = { hasChanges: true };
    attachCdpDelivery(ns, { baseline: [item("a"), item("z")], meta: {} });

    expect(stageAttachedCdpDelivery(ns, outbox)).toBe(true);
    expect(peekCdpDelivery(ns)).toBeUndefined(); // consumido
    expect(ids(computeCdpDelta([item("a"), item("z")]))).toEqual({ added: ["z"], removed: [] });

    expect(promoteCdpDelivery(outbox)).toBe("promoted");
    expect(ids(computeCdpDelta([item("a"), item("z")]))).toEqual({ added: [], removed: [] });
  });

  it("sin paquete (namespace sin cambios) o sin id válido, no se asocia nada", () => {
    expect(stageAttachedCdpDelivery({}, outbox)).toBe(false);
    const ns = {};
    attachCdpDelivery(ns, { baseline: [], meta: {} });
    expect(stageAttachedCdpDelivery(ns, 0)).toBe(false);
  });
});
