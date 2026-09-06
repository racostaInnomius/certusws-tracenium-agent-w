// test/privsvc/cert-install-split.test.ts
//
// ADR-0015 punto 10 — cadena y hoja en mensajes IPC separados.
//
// ⚠️ EL TOPE QUE ESTO ESQUIVA NO MUERDE EN ESTE SISTEMA.
//
// El IPC es JSON delimitado por saltos de línea, o sea que un mensaje es
// UNA línea. En Windows el pipe corta a 64 KB por línea; en macOS y Linux
// el socket no tiene ese tope. Así que estos tests corren donde el
// problema NO existe, y aun así hay que escribirlos: el contrato es el
// mismo en las tres plataformas a propósito, y la razón es la cicatriz
// que ya tiene este producto — el enrolamiento de Windows se rompió
// porque cada privsvc hacía lo suyo con `keyAlgorithm`.
//
// El caso que sí se puede comprobar aquí es el que importa de verdad: que
// la línea que se manda quepa. Se mide con una cadena híbrida del tamaño
// que va a existir.

import { describe, it, expect, beforeEach, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "cert-split-"));
process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(raiz, "data");
process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(raiz, "etc");
process.env.TRACENIUM_PRIVSVC_LOG_DIR = path.join(raiz, "log");
process.env.TRACENIUM_PRIVSVC_SOCKET_PATH = path.join(raiz, "privsvc.sock");

/** El tope de una línea del pipe de Windows. Ver privsvc/windows. */
const TOPE_LINEA_WINDOWS = 64 * 1024;

const plataformas = [
  {
    nombre: "macOS",
    cargar: async () => await import("../../privsvc/macos/src/crypto-store"),
    certDir: () => path.join(raiz, "data", "certs")
  },
  {
    nombre: "Linux",
    cargar: async () => await import("../../privsvc/linux/src/crypto-store"),
    certDir: () => path.join(raiz, "etc", "certs")
  }
];

const CA_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBkTCCATegAwIBAgIUX0000000000000000000000000000wCgYIKoZIzj0EAwIw\n" +
  "-----END CERTIFICATE-----\n";

afterAll(() => {
  try { fs.rmSync(raiz, { recursive: true, force: true }); } catch {}
});

for (const plat of plataformas) {
  describe(`crypto.cert.stage — ${plat.nombre}`, () => {
    let mod: any;

    beforeEach(async () => {
      mod = await plat.cargar();
      try { fs.rmSync(plat.certDir(), { recursive: true, force: true }); } catch {}
    });

    it("⚠️ deja el bundle EN ESPERA, no instalado", async () => {
      // La diferencia entera. Instalar la cadena sin la hoja dejaría al
      // equipo confiando en una CA nueva sin certificado con que
      // hablarle: un estado a medias que nadie observa. El punto de
      // compromiso sigue siendo `crypto.cert.install`.
      const r = await mod.handleStageBundle({
        v: 1, id: "s1", method: "crypto.cert.stage",
        params: { caBundlePem: CA_PEM }, meta: {}
      });
      expect(r.ok).toBe(true);
      expect(r.result.staged).toBe(true);

      const dir = plat.certDir();
      expect(fs.existsSync(path.join(dir, "ca-bundle.crt.pem.staged"))).toBe(true);
      // Y el definitivo NO se ha tocado.
      expect(fs.existsSync(path.join(dir, "ca-bundle.crt.pem"))).toBe(false);
    });

    it("un bundle que no es un certificado se rechaza", async () => {
      const r = await mod.handleStageBundle({
        v: 1, id: "s2", method: "crypto.cert.stage",
        params: { caBundlePem: "no soy un PEM" }, meta: {}
      });
      expect(r.ok).toBe(false);
      expect(r.error.code).toBe("invalid_ca_bundle");
    });

    it("⚠️ install sin bundle y sin nada en espera falla, y lo DICE", async () => {
      // El mensaje tiene que nombrar las dos formas de aportarlo, o el
      // día que alguien mande sólo la hoja por error el fallo no sugiere
      // dónde mirar.
      const r = await mod.handleInstallCert({
        v: 1, id: "i1", method: "crypto.cert.install",
        params: { clientCertPem: CA_PEM, deviceId: "11111111-2222-3333-4444-555555555555" },
        meta: {}
      });
      expect(r.ok).toBe(false);
      expect(r.error.code).toBe("invalid_ca_bundle");
      expect(r.error.message).toMatch(/stage/);
    });

    it("⚠️ el bundle sigue aceptándose en el MISMO mensaje", async () => {
      // Compatibilidad durante una actualización. agent-core y privsvc
      // viajan en el mismo paquete pero pueden no coincidir un rato, y un
      // enrolamiento que fallara en esa ventana sería un equipo sin
      // certificado esperando una visita. Se comprueba que el camino
      // viejo llega más allá de la validación de entrada: falla luego,
      // por la clave privada que este test no crea.
      const r = await mod.handleInstallCert({
        v: 1, id: "i2", method: "crypto.cert.install",
        params: {
          clientCertPem: CA_PEM, caBundlePem: CA_PEM,
          deviceId: "11111111-2222-3333-4444-555555555555"
        },
        meta: {}
      });
      expect(r.ok).toBe(false);
      expect(r.error.code).not.toBe("invalid_ca_bundle");
    });
  });
}

describe("el tamaño de la línea IPC contra el tope de Windows", () => {
  it("⚠️ una cadena híbrida y la hoja JUNTAS se acercan al tope; separadas no", () => {
    // La medida que justifica el cambio. Los tamaños salen de lo medido
    // el 2026-09-05: un certificado catalyst pesa ~5,9 KB en DER, que en
    // PEM son ~8,1 KB, y una cadena de tres ronda los 24 KB.
    //
    // Se calcula sobre el JSON REAL —con el escapado de los saltos de
    // línea, que es lo que de verdad viaja— porque medir el PEM en crudo
    // se quedaría corto justo en el margen que importa.
    const hojaPem = "-----BEGIN CERTIFICATE-----\n" + "A".repeat(8100).replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
    const cadenaPem = hojaPem.repeat(3);

    const juntos = JSON.stringify({
      v: 1, id: "x", method: "crypto.cert.install",
      params: { clientCertPem: hojaPem, caBundlePem: cadenaPem }
    }).length;

    const soloHoja = JSON.stringify({
      v: 1, id: "x", method: "crypto.cert.install",
      params: { clientCertPem: hojaPem }
    }).length;

    const soloCadena = JSON.stringify({
      v: 1, id: "x", method: "crypto.cert.stage",
      params: { caBundlePem: cadenaPem }
    }).length;

    console.log(
      `[IPC] juntos ${juntos} B · hoja sola ${soloHoja} B · cadena sola ${soloCadena} B · tope Windows ${TOPE_LINEA_WINDOWS} B`
    );

    // Separados, cada mensaje queda con holgura.
    expect(soloHoja).toBeLessThan(TOPE_LINEA_WINDOWS / 2);
    expect(soloCadena).toBeLessThan(TOPE_LINEA_WINDOWS);
    // Y juntos consumen más de la mitad del tope: no es que hoy reviente,
    // es que deja de haber margen para una cadena más larga o un
    // ML-DSA-87.
    expect(juntos).toBeGreaterThan(TOPE_LINEA_WINDOWS / 2);
  });
});
