// test/plugins/cdp-windows-key-info.test.ts
//
// Ola 1.3b — lo que PrivSvc sabe de la clave de un certificado de
// LocalMachine (proveedor y política de exportación, leídos sin exportar)
// llega al item. Un PrivSvc antiguo no lo manda, y un valor fuera de la
// lista cerrada no se cuela: en los dos casos, «no se sabe» (ausente).

import { describe, it, expect } from "vitest";
import { collectWindowsCdp } from "../../src/plugins/cdp/providers/windows";
import { FIXTURE_CERT } from "./tls-fixture";

const der = Buffer.from(FIXTURE_CERT.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64");

function ctxWith(certs: any[]) {
  return {
    enrollment: { tenantId: "t", deviceId: "d" },
    priv: {
      call: async (req: any) =>
        req.method === "cdp.certs.read"
          ? { ok: true, result: { certificates: certs } }
          : { ok: false, error: { code: "not_supported" } }
    }
  } as any;
}

describe("collectWindowsCdp — almacenamiento y exportabilidad de la clave", () => {
  it("⭐ TPM no exportable llega tal cual", async () => {
    const r = await collectWindowsCdp(ctxWith([{ store: "My", rawDerBase64: der, hasPrivateKey: true, keyExportable: false, keyStorage: "tpm" }]));
    expect(r.items[0]).toMatchObject({ hasPrivateKey: true, keyExportable: false, keyStorage: "tpm" });
  });

  it("PrivSvc antiguo (sin campos) o valor desconocido: ausente, no inventado", async () => {
    const r = await collectWindowsCdp(ctxWith([
      { store: "My", rawDerBase64: der, hasPrivateKey: true },
      { store: "WebHosting", rawDerBase64: der, hasPrivateKey: true, keyExportable: null, keyStorage: "hsm-magico" }
    ]));
    for (const i of r.items) {
      expect(i.keyExportable).toBeUndefined();
      expect(i.keyStorage).toBeUndefined();
    }
  });

  it("sin clave privada no se manda nada de la clave", async () => {
    const r = await collectWindowsCdp(ctxWith([{ store: "Root", rawDerBase64: der, hasPrivateKey: false, keyExportable: true, keyStorage: "software" }]));
    expect(r.items[0].keyExportable).toBeUndefined();
    expect(r.items[0].keyStorage).toBeUndefined();
  });
});
