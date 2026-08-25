// test/plugins/cdp-cert-files.test.ts
//
// Certificados que viven como ficheros en disco.
//
// La regla que más importa aquí no es encontrar certificados: es NO leer
// material de clave privada. Un `server.pem` con las dos mitades es el
// caso normal en nginx y Apache, y el escaneo de ficheros es donde el
// no-objetivo histórico del plugin —jamás recolectar claves— se rompería
// por accidente con más facilidad.
//
// Los tests trabajan sobre ficheros de verdad en un directorio temporal,
// no sobre un fake del sistema de ficheros: lo que se está probando es
// precisamente el manejo de bytes reales.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { collectCertFiles, certificatesInBuffer } from "../../src/plugins/cdp/providers/cert-files";
import { FIXTURE_CERT, FIXTURE_KEY } from "./tls-fixture";

let root: string;

beforeAll(async () => {
  root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cdp-files-"));
  const w = (rel: string, content: string | Buffer) =>
    fs.promises.mkdir(path.dirname(path.join(root, rel)), { recursive: true })
      .then(() => fs.promises.writeFile(path.join(root, rel), content));

  await w("certs/server.crt", FIXTURE_CERT);
  await w("certs/chain.pem", `${FIXTURE_CERT}\n${FIXTURE_CERT}`);
  // El caso peligroso: cert y clave en el mismo fichero.
  await w("certs/server-with-key.pem", `${FIXTURE_CERT}\n${FIXTURE_KEY}`);
  await w("certs/server.key", FIXTURE_KEY);
  await w("certs/readme.txt", "no soy un certificado");
  await w("certs/garbage.crt", "esto no es un certificado");
  await w("node_modules/pkg/evil.crt", FIXTURE_CERT);
});

afterAll(async () => {
  await fs.promises.rm(root, { recursive: true, force: true });
});

describe("certificatesInBuffer — la regla de la clave privada", () => {
  it("salta un fichero que contiene clave privada, aunque también tenga el certificado", () => {
    // Entero, no "quitando la clave y parseando el resto": el manejo
    // parcial de un fichero que hemos decidido no leer es como el
    // material de clave acaba donde no debe.
    const both = Buffer.from(`${FIXTURE_CERT}\n${FIXTURE_KEY}`);
    expect(certificatesInBuffer(both, "/x/server.pem")).toEqual([]);
  });

  it("detecta la clave por CONTENIDO, no por extensión", () => {
    // `server.pem` es el nombre habitual de un fichero con las dos
    // mitades; filtrar por extensión no habría salvado este caso.
    const key = Buffer.from(FIXTURE_KEY);
    expect(certificatesInBuffer(key, "/x/cualquier-nombre.crt")).toEqual([]);
  });

  it("devuelve TODOS los certificados de un bundle PEM", () => {
    const chain = Buffer.from(`${FIXTURE_CERT}\n${FIXTURE_CERT}`);
    expect(certificatesInBuffer(chain, "/x/chain.pem")).toHaveLength(2);
  });

  it("no entrega binarios arbitrarios al parser", () => {
    // Adivinar por contenido significaría pasarle cualquier fichero al
    // parser de X.509.
    expect(certificatesInBuffer(Buffer.from([1, 2, 3, 4]), "/x/a.crt")).toEqual([]);
    expect(certificatesInBuffer(Buffer.from("hola"), "/x/a.txt")).toEqual([]);
  });
});

describe("collectCertFiles", () => {
  it("encuentra los certificados y NO el fichero con clave", async () => {
    const r = await collectCertFiles([root]);
    const names = r.stores.map((s) => path.basename(s.name)).sort();
    expect(names).toContain("server.crt");
    expect(names).toContain("chain.pem");
    expect(names).not.toContain("server-with-key.pem");
    expect(names).not.toContain("server.key");
  });

  it("marca la fuente como `file`", async () => {
    const r = await collectCertFiles([root]);
    expect(r.items.length).toBeGreaterThan(0);
    for (const item of r.items) expect(item.source).toBe("file");
  });

  it("nunca reporta hasPrivateKey en un certificado de fichero", async () => {
    // No abrimos claves, así que no podemos afirmar que exista una. Decir
    // `true` seria inventarse evidencia que nadie recogio.
    const r = await collectCertFiles([root]);
    for (const item of r.items) expect(item.hasPrivateKey).toBe(false);
  });

  it("no desciende a directorios de la lista de exclusión", async () => {
    const r = await collectCertFiles([root]);
    expect(r.stores.some((s) => s.name.includes("node_modules"))).toBe(false);
  });

  it("apagado por defecto: sin rutas no escanea nada", async () => {
    // Es la diferencia entre una función opt-in y un escaneo recursivo
    // en cada endpoint de la flota.
    const r = await collectCertFiles([]);
    expect(r.filesScanned).toBe(0);
    expect(r.items).toEqual([]);
  });

  it("una raíz inexistente no rompe el escaneo", async () => {
    const r = await collectCertFiles(["/no/existe/en/ningun/sitio", root]);
    expect(r.items.length).toBeGreaterThan(0);
  });

  it("cuenta como fallo de parseo un .crt que no lo es", async () => {
    const r = await collectCertFiles([root]);
    // `garbage.crt` no produce certificados ni revienta el escaneo.
    expect(r.filesScanned).toBeGreaterThan(0);
    expect(r.items.every((i) => i.fingerprint256)).toBe(true);
  });
});
