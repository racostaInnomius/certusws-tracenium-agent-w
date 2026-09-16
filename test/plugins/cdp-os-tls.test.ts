// test/plugins/cdp-os-tls.test.ts
//
// ¿La pila TLS del sistema hace ML-KEM? Medido, no deducido (15-sep). El
// servidor de bucle local es real; el «cliente del sistema» se sustituye
// por un cliente Node en las pruebas que ejercitan el servidor, y por
// resultados fijos en las que ejercitan el veredicto.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import tls from "tls";
import {
  CONTROL_GROUP,
  makeEphemeralCertificate,
  measureOsTlsCapability,
  startLoopbackServer,
  verdictFrom,
  windowsScript,
} from "../../src/plugins/cdp/providers/os-tls-capability";
import { HYBRID_KEM_GROUP, kemProbeSupported } from "../../src/plugins/cdp/providers/tls-listeners";

const canHybrid = kemProbeSupported();

function nodeHandshake(port: number, group: string): Promise<{ ok: boolean; error?: string | null; protocol?: string | null }> {
  return new Promise((resolve) => {
    const s = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false, ecdhCurve: group, servername: "tracenium-loopback" }, () => {
      const protocol = s.getProtocol();
      s.end();
      resolve({ ok: true, protocol });
    });
    s.on("error", (e: any) => resolve({ ok: false, error: e?.code || e?.message }));
    s.setTimeout(3000, () => {
      s.destroy();
      resolve({ ok: false, error: "timeout" });
    });
  });
}

describe("makeEphemeralCertificate", () => {
  it("emite un X.509 autofirmado EC P-256 que Node parsea y que vale hoy", () => {
    const now = new Date("2026-09-15T12:00:00Z");
    const { certDer, certPem, keyPem } = makeEphemeralCertificate(now);
    const x = new crypto.X509Certificate(certDer);
    expect(x.subject).toMatch(/CN=tracenium-loopback/);
    expect(x.issuer).toBe(x.subject);
    expect(new Date(x.validFrom).getTime()).toBeLessThan(now.getTime());
    expect(new Date(x.validTo).getTime()).toBeGreaterThan(now.getTime());
    expect(x.verify(crypto.createPublicKey(keyPem))).toBe(true);
    expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n$/);
    // Dos llamadas, dos claves: nada reutilizable entre mediciones.
    expect(makeEphemeralCertificate(now).certDer.equals(certDer)).toBe(false);
  });
});

describe.runIf(canHybrid)("startLoopbackServer (OpenSSL con el grupo)", () => {
  it("⭐ el servidor de prueba sólo acepta X25519MLKEM768 y anota el grupo que negoció; el de control acepta X25519", async () => {
    const cert = makeEphemeralCertificate();
    const hybrid = await startLoopbackServer(HYBRID_KEM_GROUP, cert);
    const control = await startLoopbackServer(CONTROL_GROUP, cert);
    try {
      expect((await nodeHandshake(hybrid.port, HYBRID_KEM_GROUP)).ok).toBe(true);
      // El cliente acaba antes de que el servidor procese su Finished.
      await new Promise((r) => setTimeout(r, 150));
      expect(hybrid.negotiated.some((g) => /MLKEM/i.test(g))).toBe(true);
      // Un cliente que sólo trae X25519 no entra en el de prueba…
      expect((await nodeHandshake(hybrid.port, CONTROL_GROUP)).ok).toBe(false);
      // …pero sí en el de control: así se separa «sin grupo» de «sin TLS 1.3».
      expect((await nodeHandshake(control.port, CONTROL_GROUP)).ok).toBe(true);
    } finally {
      await hybrid.close();
      await control.close();
    }
  });
});

describe("verdictFrom", () => {
  const seen = ["X25519MLKEM768"];
  it("⭐ entra en el de prueba y el servidor lo vio negociar → supported=true", () => {
    expect(verdictFrom({ hybrid: { ok: true, protocol: "Tls13" }, control: { ok: true } }, seen)).toMatchObject({ supported: true, detail: expect.stringMatching(/negotiated X25519MLKEM768/) });
  });
  it("⭐ entra sólo en el de control → supported=false: el grupo falta o está apagado por política", () => {
    const v = verdictFrom({ hybrid: { ok: false, error: "The client and server cannot communicate, because they do not possess a common algorithm" }, control: { ok: true } }, []);
    expect(v.supported).toBe(false);
    expect(v.detail).toMatch(/absent or disabled by policy/);
    expect(v.error).toMatch(/common algorithm/);
  });
  it("no entra en ninguno → null, y se dice que ni TLS 1.3", () => {
    expect(verdictFrom({ hybrid: { ok: false, error: "x" }, control: { ok: false, error: "y" } }, []).supported).toBeNull();
  });
  it("el «ok» del cliente sin eco del servidor no vale", () => {
    // Si el cliente dice ok pero el servidor no vio MLKEM, algo no cuadra: no se afirma.
    expect(verdictFrom({ hybrid: { ok: true }, control: { ok: true } }, []).supported).toBe(false);
  });
  it("si el script no corrió → null con el motivo", () => {
    expect(verdictFrom({ hybrid: { ok: false }, control: { ok: false }, runError: "spawn powershell.exe ENOENT" }, [])).toMatchObject({ supported: null, error: "spawn powershell.exe ENOENT" });
  });
});

describe("measureOsTlsCapability", () => {
  it("fuera de Windows no se mide y se dice por qué", async () => {
    const mac = await measureOsTlsCapability({ platform: "darwin" });
    expect(mac).toMatchObject({ platform: "macos", supported: null, method: "not_measured", group: HYBRID_KEM_GROUP });
    expect((await measureOsTlsCapability({ platform: "linux" })).platform).toBe("linux");
  });

  it.runIf(canHybrid)("⭐ en Windows levanta los dos servidores, deja que el cliente del sistema los pruebe y añade build/UBR", async () => {
    const r = await measureOsTlsCapability({
      platform: "win32",
      now: () => new Date("2026-09-15T12:00:00Z"),
      systemClient: async (hybridPort, controlPort) => ({
        hybrid: await nodeHandshake(hybridPort, HYBRID_KEM_GROUP),
        control: await nodeHandshake(controlPort, CONTROL_GROUP),
        osBuild: "26200",
        ubr: 6725,
        displayVersion: "25H2",
      }),
    });
    expect(r).toMatchObject({ platform: "windows", method: "loopback_schannel", supported: true, osBuild: "26200", ubr: 6725, displayVersion: "25H2", measuredAt: "2026-09-15T12:00:00.000Z" });
  });

  it.runIf(canHybrid)("un cliente del sistema sin el grupo → false; uno que no corre → null", async () => {
    const off = await measureOsTlsCapability({
      platform: "win32",
      systemClient: async (hybridPort, controlPort) => ({ hybrid: await nodeHandshake(hybridPort, CONTROL_GROUP), control: await nodeHandshake(controlPort, CONTROL_GROUP) }),
    });
    expect(off.supported).toBe(false);
    const dead = await measureOsTlsCapability({ platform: "win32", systemClient: async () => ({ hybrid: { ok: false }, control: { ok: false }, runError: "timeout" }) });
    expect(dead).toMatchObject({ supported: null, error: "timeout" });
  });
});

describe("windowsScript", () => {
  it("prueba el de control ANTES que el de prueba, lee UBR/DisplayVersion y devuelve un JSON", () => {
    const s = windowsScript(4431, 4432);
    expect(s.indexOf("Try-Handshake 4432")).toBeLessThan(s.indexOf("Try-Handshake 4431"));
    expect(s).toMatch(/CurrentVersion'/);
    expect(s).toMatch(/UBR/);
    expect(s).toMatch(/SslProtocols\]::None/);
    expect(s).toMatch(/ConvertTo-Json/);
  });
});
