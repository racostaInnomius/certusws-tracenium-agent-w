// test/privsvc/cdp-keys-contract.test.ts
//
// ADR-0011 FASE 2 — el contrato de nombres, que es el núcleo de
// seguridad de la fase.
//
// Lo que se defiende aquí no es una comodidad: la corrección medida de
// ADR-0004 dice que invocar el CSR de enrolamiento para un certificado
// arbitrario **sobrescribiría la clave de enrolamiento del agente**, es
// decir una caída de flota. La separación tiene que ser ESTRUCTURAL —el
// llamante no nombra el sitio, lo deriva este código— y eso es lo que
// se prueba aquí.
//
// ⚠️ Se prueban las DOS implementaciones TS contra la MISMA tabla. El
// ADR dice que las tres se mantienen paralelas a propósito, «porque dos
// implementaciones de la misma regla que divergen son peores que una
// sola». Una afirmación así no se sostiene con un comentario: si macOS
// y Linux dejan de coincidir, esto se pone rojo.

import { describe, it, expect, beforeAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

let mac: any;
let lin: any;

beforeAll(async () => {
  // Las rutas son `const` de módulo, así que el entorno se fija ANTES
  // de importar o no tiene efecto.
  const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-contract-"));
  process.env.TRACENIUM_PRIVSVC_DATA_DIR = path.join(raiz, "mac");
  process.env.TRACENIUM_PRIVSVC_CONFIG_DIR = path.join(raiz, "lin");
  mac = await import("../../privsvc/macos/src/cdp-keys");
  lin = await import("../../privsvc/linux/src/cdp-keys");
});

/**
 * La tabla. Un solo sitio donde mirar qué se acepta y qué no.
 *
 * Los rechazos no son hipotéticos: `../client`, `client.key.pem` y
 * `tracenium-<deviceId>` son exactamente los tres nombres con los que
 * alguien —o un control plane comprometido— alcanzaría la identidad
 * mTLS del agente.
 */
const CASOS: Array<[string, boolean, string]> = [
  ["web01", true, "lo normal"],
  ["a", true, "un solo carácter"],
  ["cert-2026.09.01_x", true, "puntos, guiones y guion bajo sí"],
  ["", false, "vacío"],
  ["../client", false, "⭐ escape de ruta hacia el enrolamiento"],
  ["..", false, "solo puntos"],
  ["a..b", false, "`..` incrustado"],
  ["client.key.pem", true, "no es especial POR EL NOMBRE: lo que protege es el prefijo derivado"],
  ["/etc/tracenium/certs/client.key.pem", false, "ruta absoluta"],
  ["web01/../../x", false, "separadores"],
  ["web01\\x", false, "separador de Windows"],
  ["Web01", false, "mayúsculas: serían dos claves en un sistema y una en otro"],
  ["-empieza-con-guion", false, "el primer carácter tiene que ser alfanumérico"],
  ["con espacio", false, "espacios"],
  ["x".repeat(64), true, "en el límite"],
  ["x".repeat(65), false, "pasado el límite"]
];

describe("cdp-keys: contrato de keyId", () => {
  it.each(CASOS)("keyId %j → %s (%s)", (keyId, esperado) => {
    expect(mac.isValidKeyId(keyId)).toBe(esperado);
    // La misma respuesta en las dos. Si divergen, nadie sabe cuál manda.
    expect(lin.isValidKeyId(keyId)).toBe(esperado);
  });

  it("rechaza lo que no es cadena", () => {
    for (const v of [null, undefined, 42, {}, ["web01"], true]) {
      expect(mac.isValidKeyId(v as any)).toBe(false);
      expect(lin.isValidKeyId(v as any)).toBe(false);
    }
  });
});

describe("cdp-keys: la derivación no la elige el llamante", () => {
  it("macOS: la etiqueta lleva SIEMPRE el prefijo reservado", () => {
    expect(mac.cdpKeyLabel("web01")).toBe("tracenium-cdp-web01");
    // Y lo lleva incluso cuando el keyId parece la clave de enrolamiento:
    // el prefijo es lo que hace imposible la colisión, no una lista negra
    // de nombres.
    expect(mac.cdpKeyLabel("client.key.pem")).toBe("tracenium-cdp-client.key.pem");
  });

  it("Linux: la ruta cae dentro del directorio propio, nunca en el de enrolamiento", () => {
    const p = lin.cdpKeyPath("web01");
    expect(p).toContain(`${path.sep}cdp-keys${path.sep}`);
    expect(p.endsWith("web01.key.pem")).toBe(true);
    // Lo que importa: NO es la clave del agente.
    expect(path.basename(path.dirname(p))).toBe("cdp-keys");
  });

  it("⭐ un keyId que intenta escapar no produce ruta, produce excepción", () => {
    // Si esto dejara de lanzar, la ruta derivada podría acabar en
    // /etc/tracenium/certs/client.key.pem — la caída de flota.
    for (const malo of ["../client", "../../etc/passwd", "a/../../b", ""]) {
      expect(() => lin.cdpKeyPath(malo)).toThrow();
      expect(() => mac.cdpKeyLabel(malo)).toThrow();
    }
  });

  it("macOS: assertNotEnrollmentKey rechaza una etiqueta sin el prefijo", () => {
    expect(() => mac.assertNotEnrollmentKey("tracenium-cdp-web01")).not.toThrow();
    // Una etiqueta fabricada a mano, saltándose la derivación.
    expect(() => mac.assertNotEnrollmentKey("tracenium-abc123")).toThrow(
      /refuses_to_touch_enrollment_key/
    );
    expect(() => mac.assertNotEnrollmentKey("client.key.pem")).toThrow(
      /refuses_to_touch_enrollment_key/
    );
  });

  it("los dos usan el mismo prefijo, o el contrato no es uno", () => {
    expect(mac.CDP_KEY_PREFIX).toBe(lin.CDP_KEY_PREFIX);
    expect(mac.CDP_KEY_PREFIX).toBe("tracenium-cdp-");
  });
});

describe("cdp-keys: extensiones del CSR (Linux)", () => {
  it("cada SAN lleva su prefijo de tipo", () => {
    const a = lin.buildCsrExtArgs(["a.corp", "b.corp"], ["spiffe://x"], "serverAuth");
    expect(a).toContain("extendedKeyUsage=serverAuth");
    expect(a).toContain("keyUsage=critical,digitalSignature");
    expect(a).toContain("subjectAltName=DNS:a.corp,DNS:b.corp,URI:spiffe://x");
  });

  it("sin SAN no emite la extensión: una vacía hace fallar a openssl", () => {
    const a = lin.buildCsrExtArgs([], [], "clientAuth");
    expect(a.join(" ")).not.toContain("subjectAltName");
  });

  it("va por argumentos, sin fichero de config", () => {
    // No es cosmético: con `-config` hace falta `distinguished_name` y
    // una sección `[dn]` que `-subj` deja vacía, y ahí openssl aborta
    // con un error que no menciona el sujeto. Las dos variantes se
    // midieron antes de elegir esta.
    expect(lin.buildCsrExtArgs([], [], "clientAuth").every((x: string) =>
      x === "-addext" || !x.startsWith("-")
    )).toBe(true);
  });
});
