// test/privsvc/facts-chunk-limits.test.ts
//
// Un envío de facts que el control plane acepta no puede morir en el
// PrivSvc del propio equipo. Y si de verdad no cabe, el rechazo tiene que
// decirlo con su código, para que el agente no tire la conexión.
//
// TNS-OPER-SNOC04 (Server 2022), 28-sep-2026: el PrivSvc de Windows tenía
// un tope de 512 KiB al reensamblar, el compliance del equipo pasó de ahí
// (17 trozos de ~32 KiB) y durante cuatro días el agente reenvió el mismo
// evento en bucle: el rechazo era un fallo cualquiera, el agente
// reconectaba y volvía a empezar. macOS y Linux tenían el mismo defecto con
// otro número: 64 trozos, 2 MiB.
//
// Aquí: macOS y Linux reensamblan lo que el servidor acepta (16 MiB) y
// rechazan con `facts_too_large` lo que no; y los TRES PrivSvc y el agente
// usan el mismo tope que el backend. Windows se prueba en
// FactsChunkAssemblerTests.cs.

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import path from "path";

vi.mock("../../privsvc/macos/src/logger", () => ({
  logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
}));
vi.mock("../../privsvc/macos/src/crypto-store", () => ({ loadInstalledIdentity: () => null }));
vi.mock("../../privsvc/macos/src/server-pin", () => ({
  makeCheckServerIdentity: () => undefined,
  readServerKeyPins: () => []
}));
vi.mock("../../privsvc/linux/src/logger", () => ({
  logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
}));
vi.mock("../../privsvc/linux/src/crypto-store", () => ({ loadInstalledIdentity: () => null }));
vi.mock("../../privsvc/linux/src/server-pin", () => ({
  makeCheckServerIdentity: () => undefined,
  readServerKeyPins: () => []
}));

// grpc-client se importa sólo por su constante; sin esto abriría el outbox.
vi.mock("../../src/queue/sqlite-outbox", () => ({ outbox: {} }));
vi.mock("../../src/domain/cdp-baseline-repo", () => ({ promoteCdpDelivery: () => "none" }));

import * as macBridge from "../../privsvc/macos/src/grpc-bridge";
import * as linuxBridge from "../../privsvc/linux/src/grpc-bridge";
import { FACTS_TOO_LARGE, MAX_FACTS_PAYLOAD_BYTES } from "../../privsvc/shared/facts-limits";
import { MAX_FACTS_PAYLOAD_BYTES as AGENT_MAX } from "../../src/transport/grpc-client";

// Los trozos del agente: 32 KiB de la cadena (grpc-client.ts FACTS_CHUNK_SIZE).
const CHUNK = 32 * 1024;
function trocear(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += CHUNK) out.push(s.slice(i, i + CHUNK));
  return out;
}

let seq = 0;
async function enviar(handle: (req: any) => Promise<any>, payload: string) {
  const eventId = `device-1:${++seq}`;
  const trozos = trocear(payload);
  let resp: any;
  for (let i = 0; i < trozos.length; i++) {
    resp = await handle({
      v: 1,
      id: `r${i}`,
      method: "grpc.facts.chunk",
      params: { eventId, chunkIndex: i, totalChunks: trozos.length, payloadChunk: trozos[i], namespaces: ["scp"] }
    });
    if (!resp.ok) return { resp, enviados: i + 1, total: trozos.length };
  }
  return { resp, enviados: trozos.length, total: trozos.length };
}

const plataformas = [
  { nombre: "macOS", bridge: macBridge },
  { nombre: "Linux", bridge: linuxBridge }
];

for (const { nombre, bridge } of plataformas) {
  describe(`grpc.facts.chunk — ${nombre}`, () => {
    beforeEach(() => {
      seq += 100;
    });

    it("⭐ un compliance como el de SNOC04 (~560 KB, 17 trozos) llega a enviarse", async () => {
      // Sin bridge conectado, «llegar a enviarse» es que el fallo sea el
      // del envío (grpc_not_connected), no el del reensamblado.
      const { resp, enviados, total } = await enviar(bridge.handleFactsChunk, "a".repeat(17 * 32_933));
      expect(total).toBe(18);
      expect(enviados).toBe(total);
      expect(resp.ok).toBe(false);
      expect(resp.error.code).toBe("facts_send_failed");
      expect(resp.error.message).toMatch(/grpc_not_connected/);
    });

    it("⭐ también lo que pasaba del tope viejo de 64 trozos (2 MiB)", async () => {
      const { resp, enviados, total } = await enviar(bridge.handleFactsChunk, "a".repeat(3 * 1024 * 1024));
      expect(total).toBe(96);
      expect(enviados).toBe(total);
      expect(resp.error.code).toBe("facts_send_failed");
    });

    it("⭐ más de 16 MiB se rechaza con facts_too_large en el trozo que pasa, no al final", async () => {
      const { resp, enviados, total } = await enviar(bridge.handleFactsChunk, "a".repeat(MAX_FACTS_PAYLOAD_BYTES + 1));
      expect(resp.ok).toBe(false);
      expect(resp.error.code).toBe(FACTS_TOO_LARGE);
      expect(enviados).toBe(total);
    });

    it("cuenta BYTES UTF-8, como el servidor: 9 M de «é» son 18 MiB", async () => {
      const { resp, enviados, total } = await enviar(bridge.handleFactsChunk, "é".repeat(9 * 1024 * 1024));
      expect(resp.error.code).toBe(FACTS_TOO_LARGE);
      // Se corta en cuanto pasa de 16 MiB: hacia la mitad, no al final.
      expect(enviados).toBeLessThan(total);
    });

    it("demasiados trozos anunciados también es facts_too_large, sin reservar nada", async () => {
      const resp = await bridge.handleFactsChunk({
        v: 1,
        id: "r",
        method: "grpc.facts.chunk",
        params: { eventId: `device-1:${++seq}`, chunkIndex: 0, totalChunks: 10_000_000, payloadChunk: "x" }
      } as any);
      expect(resp.ok).toBe(false);
      expect((resp as any).error.code).toBe(FACTS_TOO_LARGE);
    });

    it("un trozo mal formado sigue siendo bad_request (no se confunde con el tamaño)", async () => {
      const resp = await bridge.handleFactsChunk({
        v: 1,
        id: "r",
        method: "grpc.facts.chunk",
        params: { eventId: `device-1:${++seq}`, chunkIndex: 5, totalChunks: 2, payloadChunk: "x" }
      } as any);
      expect((resp as any).error.code).toBe("bad_request");
    });
  });
}

describe("el tope es el mismo en el agente, los tres PrivSvc y el backend", () => {
  // El valor del backend: certusws-tracenium/modules/grpc/payload-limits.ts
  // (MAX_FACTS_PAYLOAD_BYTES = 16 * 1024 * 1024). Es otro repositorio, así
  // que se fija aquí el número.
  const BACKEND = 16 * 1024 * 1024;

  it("macOS/Linux (shared) y el agente", () => {
    expect(MAX_FACTS_PAYLOAD_BYTES).toBe(BACKEND);
    expect(AGENT_MAX).toBe(BACKEND);
  });

  it("Windows (FactsChunkAssembler.cs)", () => {
    const cs = fs.readFileSync(
      path.join(__dirname, "../../privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/FactsChunkAssembler.cs"),
      "utf8"
    );
    const m = cs.match(/const long MaxPayloadBytes = ([0-9L *]+);/);
    expect(m).not.toBeNull();
    const valor = m![1]
      .replace(/L/g, "")
      .split("*")
      .map((n) => Number(n.trim()))
      .reduce((a, b) => a * b, 1);
    expect(valor).toBe(BACKEND);
    expect(cs).toContain(`TooLargeCode = "${FACTS_TOO_LARGE}"`);
  });
});
