// test/privsvc/renew-invalidates-bridge.test.ts
//
// Renovar tiene que INVALIDAR EL CANAL, o la renovación no sirve de nada.
//
// ⚠️ EL CERTIFICADO DE CLIENTE SE FIJA EN EL HANDSHAKE TLS, QUE ES POR
// CONEXIÓN, NO POR STREAM.
//
// `startConnection()` lee la identidad de disco y haría lo correcto, pero
// su primera línea es `if (state.connected || state.connecting) return;`.
// Así que tras instalar un certificado nuevo, el agente reiniciaba su
// stream, el privsvc veía la conexión viva y volvía de inmediato: el
// canal seguía presentando el certificado VIEJO.
//
// Medido en campo el 2026-09-10: un certificado emitido a las 04:39 quedó
// instalado en disco y no se activó hasta las 12:40 —ocho horas—, cuando
// el canal se cayó por su cuenta. Y como el control plane sólo da la
// rotación por terminada cuando el equipo se PRESENTA con el certificado
// nuevo, el job reintentaba mientras tanto y CADA REINTENTO EMITÍA OTRO
// CERTIFICADO. De una sola petición salieron cuatro: dos ladrillos, uno
// bueno, y uno más emitido diez minutos DESPUÉS de que ya hubiera
// funcionado.
//
// ── Por qué se dobla `grpc-bridge` ───────────────────────────────────
//
// Porque al importarse abre un canal de verdad. Doblándolo se puede
// probar la COMPOSICIÓN —que el router encadene renovar e invalidar— en
// vez de asertar texto sobre el fuente, que es lo único que se podía
// hacer antes.
//
// El orden importa y por eso se comprueba: la invalidación va ANTES de
// devolver la respuesta. El agente reinicia su stream en cuanto la
// recibe; si el puente siguiera en pie en ese instante, la guardia de
// `state.connected` lo devolvería al certificado viejo — que es
// exactamente el fallo.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ⚠️ El `import()` lleva la ruta LITERAL: con una parte variable, Vite
// avisa («A file extension must be included in the static part») y el
// análisis estático deja de encontrar el módulo. Mismo patrón que
// `hybrid-renewal.test.ts`.
const plataformas = [
  {
    nombre: "macOS",
    dir: "macos",
    cargarRouter: () => import("../../privsvc/macos/src/router")
  },
  {
    nombre: "Linux",
    dir: "linux",
    cargarRouter: () => import("../../privsvc/linux/src/router")
  }
];

for (const plat of plataformas) {
  describe(`crypto.cert.renew — ${plat.nombre}`, () => {
    let orden: string[];
    let invalidar: ReturnType<typeof vi.fn>;
    let renovar: ReturnType<typeof vi.fn>;
    let uidSpy: any;

    beforeEach(() => {
      vi.resetModules();
      orden = [];

      invalidar = vi.fn((motivo?: string) => {
        orden.push(`invalidar:${motivo ?? ""}`);
      });
      renovar = vi.fn(async (req: any) => {
        orden.push("renovar");
        return { v: 1, id: req.id, ok: true, result: { deviceId: "d1" } };
      });

      // El router exige root para `crypto.*`.
      uidSpy = vi.spyOn(process, "getuid" as any).mockReturnValue(0 as any);
    });

    afterEach(() => {
      uidSpy?.mockRestore();
      vi.restoreAllMocks();
    });

    async function cargarRouter() {
      vi.doMock(`../../privsvc/${plat.dir}/src/grpc-bridge`, () => ({
        invalidateBridgeForNewIdentity: invalidar,
        renewCertOverGrpc: vi.fn(),
        handleGrpcConnect: vi.fn(),
        handleFactsSend: vi.fn(),
        handleFactsChunk: vi.fn(),
        handleHeartbeat: vi.fn(),
        handleCatalogRequest: vi.fn(),
        handleSelfInstallRequest: vi.fn(),
        handleAck: vi.fn(),
        handleClose: vi.fn(),
        handleRemoteSessionAnswer: vi.fn(),
        handleRemoteSessionIce: vi.fn(),
        handleRemoteSessionClose: vi.fn(),
        handleRemoteSessionError: vi.fn(),
        handleRemoteSessionTranscript: vi.fn(),
        handleRemoteFileTransferAudit: vi.fn(),
        handleRemoteScreenAudit: vi.fn()
      }));
      vi.doMock(`../../privsvc/${plat.dir}/src/crypto-store`, () => ({
        handleRenewCert: renovar,
        handleGenerateCsr: vi.fn(),
        handleInstallCert: vi.fn(),
        handleStageBundle: vi.fn()
      }));
      return await plat.cargarRouter();
    }

    const peticion = () => ({
      v: 1,
      id: "r1",
      method: "crypto.cert.renew",
      params: { tenantId: "1", deviceId: "d1" },
      meta: { tenantId: "1", deviceId: "d1" }
    });

    it("⚠️ una renovación correcta invalida el canal", async () => {
      const { routeRequest } = await cargarRouter();

      const res = await routeRequest(peticion() as any, vi.fn());

      expect(res.ok).toBe(true);
      expect(invalidar).toHaveBeenCalledTimes(1);
    });

    it("⚠️ invalida DESPUÉS de renovar y ANTES de responder", async () => {
      // Si se invalidara antes, se derribaría el canal por el que viaja
      // el propio `RenewCert`. Si se hiciera después de responder, el
      // agente ya habría reiniciado su stream sobre el canal viejo.
      const { routeRequest } = await cargarRouter();

      await routeRequest(peticion() as any, vi.fn());

      expect(orden).toEqual(["renovar", "invalidar:cert_renewed"]);
    });

    it("una renovación FALLIDA no toca el canal", async () => {
      // El equipo conserva el certificado que funciona; derribar su
      // canal sólo le quitaría el camino por el que puede recibir el
      // arreglo.
      renovar.mockImplementation(async (req: any) => {
        orden.push("renovar");
        return {
          v: 1,
          id: req.id,
          ok: false,
          error: { code: "renew_grpc_error", message: "boom" }
        };
      });
      const { routeRequest } = await cargarRouter();

      const res = await routeRequest(peticion() as any, vi.fn());

      expect(res.ok).toBe(false);
      expect(invalidar).not.toHaveBeenCalled();
      expect(orden).toEqual(["renovar"]);
    });
  });
}

// ── Windows ─────────────────────────────────────────────────────────
//
// Tiene la MISMA guardia —`if (_state == Connected || _state ==
// Connecting) return;`— así que tenía el mismo fallo. Aquí se comprueba
// sobre el fuente y no ejecutando: el privsvc de Windows es C# y sus
// tests viven en su propio proyecto. Lo que se sostiene es estructural
// —«la renovación derriba el puente»— y una comprobación estructural
// basta para que nadie lo quite sin enterarse.
describe("crypto.cert.renew — Windows", () => {
  const fs = require("fs");
  const path = require("path");
  const fuente = () =>
    fs.readFileSync(
      path.join(
        __dirname, "..", "..",
        "privsvc", "windows", "Tracenium.PrivSvc.Windows", "Ipc", "CryptoCertRenew.cs"
      ),
      "utf8"
    );

  it("⚠️ la renovación cierra el puente para que reconecte con la identidad nueva", () => {
    expect(fuente()).toContain("GrpcBridgeSingleton.Instance.Close()");
  });

  it("lo hace DESPUÉS de instalar: un certificado sin instalar no cambia la identidad", () => {
    const src = fuente();
    const install = src.indexOf("cert_install_error");
    const close = src.indexOf("GrpcBridgeSingleton.Instance.Close()");
    expect(install).toBeGreaterThan(-1);
    expect(close).toBeGreaterThan(install);
  });

  it("un fallo al cerrar no convierte en fallida una renovación buena", () => {
    // El certificado ya está instalado y es bueno. Lo peor que puede
    // pasar es que el canal tarde en reciclarse — el comportamiento que
    // había antes de este arreglo.
    const src = fuente();
    const close = src.indexOf("GrpcBridgeSingleton.Instance.Close()");
    expect(src.slice(close - 200, close)).toContain("try");
  });
});
