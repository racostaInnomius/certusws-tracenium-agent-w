// test/plugins/cdp-hybrid.test.ts
//
// Lectura de certificados híbridos "catalyst" (ITU-T X.509 2019).
//
// POR QUÉ EXISTE. Medido en producción el 2026-08-27: 10.277 certificados
// en la flota, los 10.277 clasificados `quantum_broken`, 0 OIDs sin
// catalogar. Si alguno fuera híbrido lo diríamos igual — se lee su mitad
// clásica y la post-cuántica, que vive en tres extensiones no críticas,
// era invisible. Un falso negativo en la herramienta que vendemos como
// inventario PQC.
//
// LO QUE MÁS SE VIGILA AQUÍ NO ES LA DETECCIÓN, ES SU AUSENCIA. Un falso
// POSITIVO sería peor: marcaría como híbridos certificados corrientes en
// un parque de diez mil, y el número que sostiene toda la narrativa PQC
// —"el 100% es vulnerable"— dejaría de ser cierto sin que nadie lo note.
// Por eso el certificado real del fixture se comprueba explícitamente.
//
// Los bytes son DER de verdad, construidos aquí con un codificador
// mínimo. No es un mock del parser: el parser recorre estos bytes con las
// mismas primitivas (readTlv/children/decodeOid) que ya cubre
// cdp-der.test.ts, y el codificador se valida contra el certificado real
// antes de usarlo.

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import {
  extractHybridOids,
  extractExtension,
  children,
  readTlv,
  decodeOid,
  EXT_SUBJECT_ALT_PUBLIC_KEY_INFO,
  EXT_ALT_SIGNATURE_ALGORITHM,
  EXT_ALT_SIGNATURE_VALUE
} from "../../src/plugins/cdp/der";
import { parseCertToItem } from "../../src/plugins/cdp/parse-cert";
import { FIXTURE_CERT } from "./tls-fixture";

const FIXTURE_DER = new crypto.X509Certificate(FIXTURE_CERT).raw;
const STORE = { id: "test/store", name: "Test", scope: "machine" as const };

// ── Codificador DER mínimo ────────────────────────────────────────────

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(content.length), content]);
}

const seq = (...parts: Buffer[]) => tlv(0x30, Buffer.concat(parts));
const octet = (b: Buffer) => tlv(0x04, b);
const bitString = (b: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0x00]), b]));

/** OID en DER, desde su forma con puntos. */
function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const body: number[] = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let v = part >> 7;
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

/** Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } */
function extension(id: string, value: Buffer): Buffer {
  return seq(oid(id), octet(value));
}

/**
 * Un Certificate con las extensiones que se le pasen.
 *
 * Sólo lleva los campos que el lector recorre para llegar a las
 * extensiones: no pretende ser un certificado utilizable, pretende ser
 * DER estructuralmente correcto por el camino que se está probando.
 */
function certWithExtensions(...exts: Buffer[]): Buffer {
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([0x02]))), // [0] version v3
    tlv(0x02, Buffer.from([0x01])),            // serialNumber
    seq(oid("1.2.840.113549.1.1.11")),         // signature (sha256WithRSA)
    seq(),                                     // issuer
    seq(),                                     // validity
    seq(),                                     // subject
    seq(seq(oid("1.2.840.113549.1.1.1")), bitString(Buffer.alloc(4))), // SPKI
    tlv(0xa3, seq(...exts))                    // [3] extensions
  );
  return seq(tbs, seq(oid("1.2.840.113549.1.1.11")), bitString(Buffer.alloc(4)));
}

const ML_DSA_65 = "2.16.840.1.101.3.4.3.18";

function hybridCert() {
  return certWithExtensions(
    extension(EXT_SUBJECT_ALT_PUBLIC_KEY_INFO, seq(seq(oid(ML_DSA_65)), bitString(Buffer.alloc(32)))),
    extension(EXT_ALT_SIGNATURE_ALGORITHM, seq(oid(ML_DSA_65))),
    extension(EXT_ALT_SIGNATURE_VALUE, bitString(Buffer.alloc(64)))
  );
}

// ── El codificador, validado antes de confiar en él ───────────────────

describe("el codificador DER del test", () => {
  it("produce bytes que las primitivas ya probadas saben recorrer", () => {
    // Si esto falla, todo lo de abajo estaría probando el parser contra
    // basura y pasaría o fallaría por el motivo equivocado.
    const der = hybridCert();
    const cert = readTlv(der, 0)!;
    expect(cert.tag).toBe(0x30);
    const tbs = children(der, cert)[0];
    expect(tbs.tag).toBe(0x30);
    const extsWrapper = children(der, tbs).find((c) => c.tag === 0xa3);
    expect(extsWrapper, "no se encontró el [3] de extensiones").toBeTruthy();
    expect(children(der, children(der, extsWrapper!)[0])).toHaveLength(3);
  });

  it("codifica OIDs igual que los decodifica el lector", () => {
    // Ida y vuelta contra decodeOid, que ya tiene sus propios tests.
    for (const dotted of [ML_DSA_65, "1.2.840.113549.1.1.11", "2.5.29.72"]) {
      const buf = oid(dotted);
      expect(decodeOid(buf, readTlv(buf, 0)), dotted).toBe(dotted);
    }
  });
});

// ── Ausencia: lo que más importa ──────────────────────────────────────

describe("un certificado corriente NO es híbrido", () => {
  it("el certificado real del fixture da los tres campos vacíos", () => {
    // El falso positivo es el error caro: marcaría como híbridos
    // certificados normales en un parque de 10.277 y rompería la única
    // conclusión que hoy sostiene el panel PQC.
    expect(extractHybridOids(FIXTURE_DER)).toEqual({
      altSignatureOid: null,
      altPublicKeyOid: null,
      hasAltSignatureValue: false
    });
  });

  it("un certificado con OTRAS extensiones tampoco", () => {
    const der = certWithExtensions(
      extension("2.5.29.31", seq()),      // CRL distribution points
      extension("1.3.6.1.5.5.7.1.1", seq()) // authority info access
    );
    expect(extractHybridOids(der).altSignatureOid).toBeNull();
    expect(extractHybridOids(der).hasAltSignatureValue).toBe(false);
  });

  it("parseCertToItem no añade campos híbridos a un certificado normal", () => {
    // Se mandan sólo cuando existen: un `false` en cada uno de los 10.277
    // certificados engorda un payload que ya tiene tope.
    const item = parseCertToItem(FIXTURE_CERT, { store: STORE })!;
    expect(item.altSignatureOid).toBeUndefined();
    expect(item.altPublicKeyOid).toBeUndefined();
    expect(item.hasAltSignature).toBeUndefined();
  });
});

// ── Presencia ─────────────────────────────────────────────────────────

describe("un certificado catalyst SÍ lo es", () => {
  it("lee el OID de la firma alternativa y el de la clave alternativa", () => {
    expect(extractHybridOids(hybridCert())).toEqual({
      altSignatureOid: ML_DSA_65,
      altPublicKeyOid: ML_DSA_65,
      hasAltSignatureValue: true
    });
  });

  it("las tres extensiones se leen por su OID, no por su posición", () => {
    // El orden de las extensiones no está fijado por el estándar.
    const invertido = certWithExtensions(
      extension(EXT_ALT_SIGNATURE_VALUE, bitString(Buffer.alloc(64))),
      extension("2.5.29.31", seq()),
      extension(EXT_ALT_SIGNATURE_ALGORITHM, seq(oid(ML_DSA_65))),
      extension(EXT_SUBJECT_ALT_PUBLIC_KEY_INFO, seq(seq(oid(ML_DSA_65)), bitString(Buffer.alloc(32))))
    );
    expect(extractHybridOids(invertido).altSignatureOid).toBe(ML_DSA_65);
    expect(extractHybridOids(invertido).altPublicKeyOid).toBe(ML_DSA_65);
  });

  it("sigue siendo híbrido con la firma presente aunque falte su algoritmo", () => {
    // Decir "no hay nada" ahí sería el mismo falso negativo que este
    // módulo viene a cerrar.
    const parcial = certWithExtensions(
      extension(EXT_ALT_SIGNATURE_VALUE, bitString(Buffer.alloc(64)))
    );
    const r = extractHybridOids(parcial);
    expect(r.hasAltSignatureValue).toBe(true);
    expect(r.altSignatureOid).toBeNull();
  });

  it("un OID no catalogado viaja crudo, no se pierde", () => {
    // La regla del ADR-0004: la clasificación es server-side, así que un
    // algoritmo que el agente no conoce tiene que llegar igual. Es lo que
    // permitirá reconocer composite sin desplegar la flota.
    const inventado = "1.3.6.1.4.1.99999.1.1";
    const der = certWithExtensions(extension(EXT_ALT_SIGNATURE_ALGORITHM, seq(oid(inventado))));
    expect(extractHybridOids(der).altSignatureOid).toBe(inventado);
  });
});

// ── Entrada hostil ────────────────────────────────────────────────────

describe("bytes que no son un certificado", () => {
  it("devuelve vacío en vez de lanzar", () => {
    // Esto parsea bytes recolectados de endpoints. Una excepción aquí
    // tumba el escaneo entero del equipo.
    for (const bad of [
      Buffer.alloc(0),
      Buffer.from("30", "hex"),
      Buffer.from("ffffffffffffffff", "hex"),
      Buffer.alloc(64, 0xaa),
      FIXTURE_DER.subarray(0, 20)
    ]) {
      expect(() => extractHybridOids(bad)).not.toThrow();
      expect(extractHybridOids(bad).hasAltSignatureValue).toBe(false);
    }
  });

  it("una extensión truncada no cuelga la lectura", () => {
    const der = hybridCert();
    expect(() => extractHybridOids(der.subarray(0, der.length - 10))).not.toThrow();
  });

  it("extractExtension sigue devolviendo null para un OID ausente", () => {
    expect(extractExtension(hybridCert(), "2.5.29.99")).toBeNull();
  });
});
