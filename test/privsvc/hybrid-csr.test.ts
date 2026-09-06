// test/privsvc/hybrid-csr.test.ts
//
// ADR-0015 puntos 7 y 8 — el CSR híbrido que construye el agente.
//
// ⚠️ EL JUEZ ES `openssl`, NO ESTE FICHERO.
//
// Un test que construyera el CSR y lo volviera a leer con el mismo código
// pasaría en verde con el DER mal formado, con la longitud en forma corta
// donde toca la larga, o con el BIT STRING sin su octeto de relleno. Lo
// que hay que demostrar es que un TERCERO lo entiende, porque el tercero
// que importa —el validador del backend— tampoco es este código.
//
// Así que cada caso pasa por el `openssl` del sistema: `req -verify` para
// la firma clásica y `req -text` para comprobar que las tres extensiones
// catalyst están donde deben, dentro del extensionRequest.
//
// La mitad alternativa `openssl` no la sabe verificar (ninguna pila lo
// hace, ése es el punto de catalyst), así que ésa se comprueba aquí
// rehaciendo el paso que el backend rehará: quitar la 74 del cuerpo y
// verificar la firma sobre lo que queda. Si el orden estuviera mal, esto
// falla — y es el único sitio donde falla.

import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

import { buildCsr } from "../../privsvc/shared/pkcs10";
import { getMlDsaProvider } from "../../privsvc/shared/mldsa";
import { readTlv, children, contentOf, rawOf, DER_SEQUENCE } from "../../privsvc/shared/der";
import { OPENSSL, opensslVerificaCsr, mencionaExtension } from "./openssl-compat";

let tmp: string;

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hybrid-csr-"));
});

function claveClasica(alg: "RSA_2048" | "EC_P384"): crypto.KeyObject {
  if (alg === "RSA_2048") {
    return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  }
  return crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).privateKey;
}

function guarda(nombre: string, pem: string): string {
  const p = path.join(tmp, nombre);
  fs.writeFileSync(p, pem);
  return p;
}

/** El texto que `openssl req -text` produce para este CSR. */
function opensslText(pem: string, nombre: string): string {
  return execFileSync(OPENSSL, ["req", "-in", guarda(nombre, pem), "-text", "-noout"], {
    encoding: "utf8"
  });
}

// ── Rehacer el paso (a): el cuerpo SIN la 74 ────────────────────────
//
// Es exactamente lo que hace `csrInfoWithoutAltSignature` en el backend.
// Se reimplementa aquí a propósito, en el otro repositorio y sin mirar
// aquél: si las dos versiones no coincidieran, este test se pondría rojo
// y ésa es justo la divergencia que hay que cazar.

function infoSinAlt74(csrDer: Buffer): Buffer | null {
  const raiz = readTlv(csrDer, 0)!;
  const info = children(csrDer, raiz)[0];
  const partes = children(csrDer, info);
  const attrs = partes.find((p) => p.tag === 0xa0);
  if (!attrs) return null;

  const extReq = children(csrDer, attrs).find((a) => {
    const cs = children(csrDer, a);
    return cs[0] && contentOf(csrDer, cs[0]).equals(Buffer.from("2a864886f70d01090e", "hex"));
  });
  if (!extReq) return null;

  const valores = children(csrDer, extReq)[1];
  const extSeq = children(csrDer, valores)[0];
  const exts = children(csrDer, extSeq);

  const alt74 = Buffer.from("551d4a", "hex");
  const conservadas = exts.filter((e) => {
    const id = children(csrDer, e)[0];
    return !(id && contentOf(csrDer, id).equals(alt74));
  });
  if (conservadas.length === exts.length) return null; // no era híbrido

  // Se rearma el CertificationRequestInfo con las extensiones que quedan.
  const len = (n: number): Buffer => {
    if (n < 0x80) return Buffer.from([n]);
    const b: number[] = [];
    let v = n;
    while (v > 0) { b.unshift(v & 0xff); v >>>= 8; }
    return Buffer.from([0x80 | b.length, ...b]);
  };
  const t = (tag: number, c: Buffer) => Buffer.concat([Buffer.from([tag]), len(c.length), c]);
  const s = (...p: Buffer[]) => t(DER_SEQUENCE, Buffer.concat(p));

  const extsDer = s(...conservadas.map((e) => rawOf(csrDer, e)));
  const attrDer = t(0xa0, s(
    rawOf(csrDer, children(csrDer, extReq)[0]),
    t(0x31, extsDer)
  ));

  return s(
    rawOf(csrDer, partes[0]),
    rawOf(csrDer, partes[1]),
    rawOf(csrDer, partes[2]),
    attrDer
  );
}

/** La firma alternativa (contenido de la 74, sin el octeto de relleno). */
function firmaAlt(csrDer: Buffer): Buffer | null {
  const raiz = readTlv(csrDer, 0)!;
  const info = children(csrDer, raiz)[0];
  const attrs = children(csrDer, info).find((p) => p.tag === 0xa0);
  if (!attrs) return null;
  const extReq = children(csrDer, attrs)[0];
  const valores = children(csrDer, extReq)[1];
  const extSeq = children(csrDer, valores)[0];

  for (const e of children(csrDer, extSeq)) {
    const cs = children(csrDer, e);
    if (!contentOf(csrDer, cs[0]).equals(Buffer.from("551d4a", "hex"))) continue;
    const octeto = cs[cs.length - 1];
    const bits = readTlv(csrDer, octeto.start)!;
    return csrDer.subarray(bits.start + 1, bits.end); // +1 salta el relleno
  }
  return null;
}

/** La SPKI alternativa declarada en la 72. */
function altSpkiDe(csrDer: Buffer): Buffer | null {
  const raiz = readTlv(csrDer, 0)!;
  const info = children(csrDer, raiz)[0];
  const attrs = children(csrDer, info).find((p) => p.tag === 0xa0);
  if (!attrs) return null;
  const extReq = children(csrDer, attrs)[0];
  const extSeq = children(csrDer, children(csrDer, extReq)[1])[0];

  for (const e of children(csrDer, extSeq)) {
    const cs = children(csrDer, e);
    if (!contentOf(csrDer, cs[0]).equals(Buffer.from("551d48", "hex"))) continue;
    return contentOf(csrDer, cs[cs.length - 1]);
  }
  return null;
}

// ── Lo clásico, que es el 100 % de la flota hoy ─────────────────────

describe("CSR clásico (sin clave alternativa)", () => {
  for (const alg of ["RSA_2048", "EC_P384"] as const) {
    it(`⚠️ ${alg}: openssl req -verify lo acepta`, () => {
      const { pem, hybrid } = buildCsr({
        classicKey: claveClasica(alg),
        classicAlgorithm: alg,
        commonName: "SRVOC-MainAgent",
        tenantId: "1",
        deviceId: "dev-1",
        dnsName: "SRVOC-MainAgent"
      });
      expect(hybrid).toBe(false);

      // `-verify` comprueba la prueba de posesión clásica: que la firma
      // del PKCS#10 cuadre con la clave pública que el propio CSR
      // declara. Es lo que el backend rehará antes de emitir.
      expect(opensslVerificaCsr(guarda(`clasico-${alg}.pem`, pem)))
        .toMatch(/verify OK/i);
    });
  }

  it("lleva el SAN URI con el tenant y el equipo", () => {
    const { pem } = buildCsr({
      classicKey: claveClasica("EC_P384"),
      classicAlgorithm: "EC_P384",
      commonName: "eq-1",
      tenantId: "111",
      deviceId: "abc-123"
    });
    expect(opensslText(pem, "san.pem")).toContain("tracenium://tenant/111/device/abc-123");
  });

  it("⚠️ EC no lleva parámetros NULL y RSA sí", () => {
    // Se equivoca fácil porque las dos formas «funcionan» en un OpenSSL
    // laxo. Se comprueba sobre el DER: el AlgorithmIdentifier de un
    // ecdsa-with-SHA384 tiene UN hijo, el de sha256WithRSA tiene dos.
    const ec = buildCsr({
      classicKey: claveClasica("EC_P384"), classicAlgorithm: "EC_P384",
      commonName: "x", tenantId: "1", deviceId: "d"
    });
    const rsa = buildCsr({
      classicKey: claveClasica("RSA_2048"), classicAlgorithm: "RSA_2048",
      commonName: "x", tenantId: "1", deviceId: "d"
    });
    const algIdHijos = (der: Buffer) => {
      const raiz = readTlv(der, 0)!;
      return children(der, children(der, raiz)[1]).length;
    };
    expect(algIdHijos(ec.der)).toBe(1);
    expect(algIdHijos(rsa.der)).toBe(2);
  });
});

// ── Lo híbrido ──────────────────────────────────────────────────────

describe("CSR híbrido catalyst", () => {
  function hibrido(alg: "RSA_2048" | "EC_P384" = "EC_P384") {
    const alt = getMlDsaProvider().generateKeyPair();
    const built = buildCsr({
      classicKey: claveClasica(alg),
      classicAlgorithm: alg,
      commonName: "SRVOC-MainAgent",
      tenantId: "1",
      deviceId: "dev-hibrido",
      dnsName: "SRVOC-MainAgent",
      altPrivateKeyPkcs8: alt.pkcs8Der,
      altPublicKeySpki: alt.spkiDer
    });
    return { built, alt };
  }

  it("⚠️ la mitad CLÁSICA sigue verificando con openssl", () => {
    // Lo que hace desplegable todo esto: un verificador que no sepa nada
    // de catalyst ve un CSR normal y lo acepta. Si esto fallara, el
    // formato híbrido rompería el enrolamiento en vez de ampliarlo.
    const { built } = hibrido();
    expect(opensslVerificaCsr(guarda("hibrido.pem", built.pem))).toMatch(/verify OK/i);
  });

  it("⚠️ openssl NOMBRA las tres extensiones catalyst dentro del extensionRequest", () => {
    // Evidencia de tercero, y más fuerte de lo que yo esperaba.
    //
    // Escribí primero este test buscando los OID en crudo («2.5.29.72»),
    // dando por hecho que OpenSSL no conocería catalyst y los imprimiría
    // sin nombre. Falso: OpenSSL 3.6.3 los conoce y los rotula
    // «Subject Alternative Public Key Info», «Alternative Signature
    // Algorithm» y «Alternative Signature Value».
    //
    // Que los NOMBRE demuestra más que un OID suelto en el volcado:
    // demuestra que decodifica la estructura completa y la reconoce. Lo
    // que sigue sin hacer —y por eso existe el punto 9— es VERIFICARLAS.
    // Conocer el formato y comprobar la firma son cosas distintas.
    const texto = opensslText(hibrido().built.pem, "hibrido-text.pem");
    expect(mencionaExtension(texto, "2.5.29.72", "X509v3 Subject Alternative Public Key Info")).toBe(true);
    expect(mencionaExtension(texto, "2.5.29.73", "X509v3 Alternative Signature Algorithm")).toBe(true);
    expect(mencionaExtension(texto, "2.5.29.74", "X509v3 Alternative Signature Value")).toBe(true);
  });

  it("⚠️ la firma alternativa verifica sobre el cuerpo SIN la 74", () => {
    // EL TEST DEL ORDEN. Si la 74 se firmara sobre el cuerpo que ya la
    // contiene —el error natural— esto sería el único sitio que se entera.
    const { built, alt } = hibrido();
    const cuerpo = infoSinAlt74(built.der);
    const firma = firmaAlt(built.der);
    expect(cuerpo).not.toBeNull();
    expect(firma).not.toBeNull();
    expect(firma!.length).toBe(3309);
    expect(getMlDsaProvider().verify(firma!, cuerpo!, alt.spkiDer)).toBe(true);
  });

  it("⚠️ y NO verifica sobre el cuerpo CON la 74", () => {
    // El contrapunto del anterior: sin esto, un `verify` que devolviera
    // true para cualquier cuerpo pasaría los dos.
    const { built, alt } = hibrido();
    const raiz = readTlv(built.der, 0)!;
    const conTodo = rawOf(built.der, children(built.der, raiz)[0]);
    expect(getMlDsaProvider().verify(firmaAlt(built.der)!, conTodo, alt.spkiDer)).toBe(false);
  });

  it("la SPKI alternativa del CSR es la de la clave generada", () => {
    const { built, alt } = hibrido();
    expect(altSpkiDe(built.der)!.equals(alt.spkiDer)).toBe(true);
  });

  it("⚠️ una firma alternativa de OTRA clave no verifica", () => {
    const { built } = hibrido();
    const otra = getMlDsaProvider().generateKeyPair();
    expect(
      getMlDsaProvider().verify(firmaAlt(built.der)!, infoSinAlt74(built.der)!, otra.spkiDer)
    ).toBe(false);
  });

  it("funciona igual con sujeto RSA", () => {
    const { built, alt } = hibrido("RSA_2048");
    expect(getMlDsaProvider().verify(firmaAlt(built.der)!, infoSinAlt74(built.der)!, alt.spkiDer)).toBe(true);
  });

  it("⚠️ media pareja de claves alternativas es un error, no un CSR clásico", () => {
    // Emitir la SPKI sin poder firmar la prueba produce un CSR que el
    // backend RECHAZA por diseño (punto 3). Degradar en silencio dejaría
    // al equipo creyendo que pidió un híbrido.
    const alt = getMlDsaProvider().generateKeyPair();
    expect(() =>
      buildCsr({
        classicKey: claveClasica("EC_P384"), classicAlgorithm: "EC_P384",
        commonName: "x", tenantId: "1", deviceId: "d",
        altPublicKeySpki: alt.spkiDer // sin la privada
      })
    ).toThrow(/incompleta/);
  });

  it("[medida] tamaño del CSR híbrido", () => {
    // El stopper 6 del ADR decía que un CSR híbrido no cabía en 10.000
    // caracteres. Medido en el backend resultó falso; se vuelve a medir
    // AQUÍ, con el constructor del agente, porque es el que produce el
    // CSR de verdad.
    const ec = hibrido("EC_P384").built;
    const rsa = hibrido("RSA_2048").built;
    console.log(
      `[tamaños CSR del agente] híbrido con sujeto EC P-384: ${ec.pem.length} · con sujeto RSA-2048: ${rsa.pem.length} caracteres`
    );
    expect(ec.pem.length).toBeLessThan(64 * 1024);
    expect(rsa.pem.length).toBeLessThan(64 * 1024);
  });
});
