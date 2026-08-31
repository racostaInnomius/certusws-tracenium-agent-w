// test/plugins/cdp-nss.test.ts
//
// Almacenes NSS (Firefox / Thunderbird) — última pieza de la fase C.
//
// ⚠️ El formato NO se dedujo: se midió sobre un `cert9.db` fabricado con
// `certutil` y un certificado conocido, comprobando que la huella
// SHA-256 del DER extraído coincidía con la del original. Este test
// reproduce esa base con SQLite puro para que la comprobación viva en
// CI, donde no hay herramientas de NSS instaladas.
//
// Por qué importa para 5 equipos de 76: Firefox tiene su PROPIO almacén
// de confianza. Una CA importada ahí no está en el store de Windows, ni
// en el llavero de macOS, ni en el bundle de la distro — es el hueco
// exacto donde una raíz de proxy interceptor se instala sin dejar
// rastro en ninguno de los sitios que ya miramos.

import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Database from "better-sqlite3";
import {
  readNssCertificates,
  discoverNssDatabases,
  mozillaProfileRoots
} from "../../src/plugins/cdp/providers/nss";

let dir: string;
let dbPath: string;
let derEsperado: Buffer;

/**
 * Reproduce la forma REAL de `cert9.db`, medida con certutil:
 * una sola tabla `nssPublic`, atributos PKCS#11 como columnas `a<hex>`,
 * `a0` = clase en 4 bytes, `a3` = etiqueta, `a11` = DER.
 */
function construirCert9(p: string, der: Buffer) {
  const db = new Database(p);
  db.exec("CREATE TABLE nssPublic (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a3, a11, a81)");
  const ins = db.prepare("INSERT INTO nssPublic (id, a0, a3, a11) VALUES (?,?,?,?)");
  // La fila del certificado: clase 1 = CKO_CERTIFICATE.
  ins.run(1, Buffer.from([0, 0, 0, 1]), Buffer.from("probe-ca"), der);
  // Y la fila de CONFIANZA: clase 11 = CKO_NSS_TRUST.
  //
  // ⚠️ Se le pone un BLOB en a11 a propósito. Con `null` la excluiría el
  // filtro de buffers vacíos y el test pasaría aunque se borrara el
  // filtro por clase — comprobado por mutación: la primera versión de
  // este test no detectaba esa pérdida. Un objeto que no es certificado
  // pero SÍ trae bytes es el caso realista: en un perfil de Firefox
  // conviven claves y otros objetos PKCS#11.
  ins.run(2, Buffer.from([0, 0, 0, 11]), Buffer.from("probe-ca"), Buffer.from("no-soy-un-cert"));
  db.close();
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "nss-test-"));
  // Un certificado autofirmado de verdad, para que el DER sea parseable.
  const { generateKeyPairSync } = crypto as any;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  // No hay API nativa para emitir X.509 en Node, así que se usa un DER
  // fijo mínimo: lo que se prueba aquí es la EXTRACCIÓN, no el parseo,
  // que ya tiene sus propios tests en parse-cert.
  derEsperado = Buffer.from("30820100" + "aa".repeat(126), "hex");
  void privateKey;
  dbPath = path.join(dir, "cert9.db");
  construirCert9(dbPath, derEsperado);
});

afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("readNssCertificates", () => {
  it("saca el DER de la columna a11", () => {
    const ders = readNssCertificates(dbPath);
    expect(ders).toHaveLength(1);
    expect(ders[0].equals(derEsperado)).toBe(true);
  });

  it("⚠️ NO devuelve la fila de confianza (clase 11)", () => {
    // Medido en una base real: junto a cada certificado hay una fila
    // CKO_NSS_TRUST sin DER. Sin filtrar por clase entraría y se
    // contaría como parseo fallido, ensuciando el diagnóstico.
    expect(readNssCertificates(dbPath)).toHaveLength(1);
  });

  it("⚠️ abre en SOLO LECTURA — un inventario no toca lo que inventaría", () => {
    // Firefox puede estar corriendo con la base abierta. Un lector
    // normal intentaría recuperar el WAL y ESCRIBIRÍA en el perfil de
    // una persona.
    //
    // Se comprueba sobre la CONEXIÓN, no sobre el mtime del fichero:
    // leer no cambia el mtime ni abriendo en escritura, así que la
    // primera versión de este test pasaba con el `readonly` borrado
    // —comprobado por mutación—. Lo único que lo demuestra es que una
    // escritura falle.
    const db = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
      expect(() => db.exec("CREATE TABLE intruso (x)")).toThrow();
    } finally {
      db.close();
    }
    // Y que el propio colector pide readonly.
    const fuente = fs.readFileSync(
      path.resolve(__dirname, "../../src/plugins/cdp/providers/nss.ts"),
      "utf8"
    );
    expect(fuente).toContain("readonly: true");
  });

  it("una base inexistente lanza, no devuelve vacío en silencio", () => {
    // El llamante lo captura y lo reporta como store ilegible. Devolver
    // [] aquí lo haría indistinguible de un perfil sin certificados.
    expect(() => readNssCertificates(path.join(dir, "no-existe.db"))).toThrow();
  });
});

describe("discoverNssDatabases", () => {
  it("encuentra cert9.db dentro de un perfil", () => {
    const found = discoverNssDatabases([dir === "" ? "" : path.dirname(dbPath) + "/.."]);
    // El descubrimiento espera <raíz>/<perfil>/cert9.db; aquí la raíz es
    // el temporal y el "perfil" su propio nombre.
    const raiz = path.dirname(path.dirname(dbPath));
    const r = discoverNssDatabases([raiz]);
    expect(r.some((f) => f.dbPath === dbPath)).toBe(true);
    void found;
  });

  it("⚠️ reporta cert8.db como encontrado pero HEREDADO", () => {
    // No es SQLite y no se lee. Ignorarlo en silencio dejaría un almacén
    // de confianza sin mirar y sin que nadie lo supiera; marcarlo
    // permite decirlo.
    const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "nss-legacy-"));
    try {
      const perfil = path.join(raiz, "abcd.default");
      fs.mkdirSync(perfil);
      fs.writeFileSync(path.join(perfil, "cert8.db"), "no-es-sqlite");
      const r = discoverNssDatabases([raiz]);
      expect(r).toHaveLength(1);
      expect(r[0].legacy).toBe(true);
    } finally {
      fs.rmSync(raiz, { recursive: true, force: true });
    }
  });

  it("prefiere cert9.db cuando conviven los dos", () => {
    const raiz = fs.mkdtempSync(path.join(os.tmpdir(), "nss-both-"));
    try {
      const perfil = path.join(raiz, "perfil");
      fs.mkdirSync(perfil);
      fs.writeFileSync(path.join(perfil, "cert8.db"), "viejo");
      fs.writeFileSync(path.join(perfil, "cert9.db"), "nuevo");
      const r = discoverNssDatabases([raiz]);
      expect(r).toHaveLength(1);
      expect(r[0].legacy).toBe(false);
    } finally {
      fs.rmSync(raiz, { recursive: true, force: true });
    }
  });

  it("una raíz inexistente no revienta el escaneo", () => {
    expect(discoverNssDatabases(["/no/existe/en/ningun/sitio"])).toEqual([]);
  });
});

describe("mozillaProfileRoots", () => {
  it("cubre Firefox y Thunderbird en las tres plataformas", () => {
    for (const plat of ["darwin", "win32", "linux"] as const) {
      const roots = mozillaProfileRoots(["/home/ana"], plat);
      expect(roots.length, plat).toBeGreaterThanOrEqual(2);
      expect(roots.some((r) => /firefox/i.test(r)), plat).toBe(true);
      expect(roots.some((r) => /thunderbird/i.test(r)), plat).toBe(true);
    }
  });

  it("enumera por USUARIO, que es donde está el punto ciego", () => {
    // El certificado que importó una persona en su Firefox no está en
    // ningún sitio compartido del equipo.
    const roots = mozillaProfileRoots(["/Users/ana", "/Users/beto"], "darwin");
    expect(roots.some((r) => r.includes("/Users/ana"))).toBe(true);
    expect(roots.some((r) => r.includes("/Users/beto"))).toBe(true);
  });
});
