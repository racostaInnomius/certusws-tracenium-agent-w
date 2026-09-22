// src/plugins/cdp/private-key-info.ts
//
// Ola 1.1 — PRESENCIA de claves privadas sueltas en disco, sin leer el
// material de clave.
//
// Una clave suelta es la mitad del inventario que Keyfactor y AgileSec
// enseñan y nosotros no: `server.key` al lado de `server.crt`, un `.p8`
// olvidado en /opt, el PKCS#8 que alguien copió para una prueba. La
// pregunta del operador es «¿dónde hay claves, de qué tipo, están
// cifradas y a qué certificado pertenecen?» — y ninguna de esas
// respuestas necesita el secreto.
//
// ── Qué se lee y qué no ──────────────────────────────────────────────
//
// Solo campos PÚBLICOS de la estructura:
//   · el OID del algoritmo (y la curva) de PrivateKeyInfo;
//   · en RSA, el módulo `n` y el exponente público `e` — ambos públicos,
//     están en cualquier certificado de esa clave;
//   · en EC (SEC1) y en OneAsymmetricKey v2, la clave PÚBLICA opcional que
//     la propia estructura trae en claro ([1] publicKey).
// Con esas piezas se rearma la SubjectPublicKeyInfo y su sha256 es el
// mismo `publicKeyHash` que llevan los certificados: así se casa la clave
// con su certificado sin tocar el escalar privado.
//
// Nunca: descifrar una clave cifrada (se dice «cifrada» y nada más), leer
// `d`/`p`/`q`/el escalar EC, ni pasar la clave a OpenSSL
// (`crypto.createPublicKey` sobre un PKCS#8 CARGA la privada para derivar
// la pública — justo lo que no queremos). Los buffers decodificados se
// ponen a cero al terminar.
//
// Todo es fallo-blando: una estructura que no se entiende produce un
// resultado con menos campos, nunca una excepción.

import crypto from "crypto";
import { children, decodeOid, readTlv, type Tlv } from "./der";
import { algorithmName, curveName } from "./algorithm-oids";
import type { CdpLooseKey } from "../../domain/cdp-types";

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_CTX0 = 0xa0;
const TAG_CTX1 = 0xa1;
/** OneAsymmetricKey v2: `[1] IMPLICIT BIT STRING` → primitivo 0x81. */
const TAG_CTX1_IMPLICIT = 0x81;

const OID_RSA = "1.2.840.113549.1.1.1";
const OID_RSA_PSS = "1.2.840.113549.1.1.10";
const OID_EC = "1.2.840.10045.2.1";
const OID_DSA = "1.2.840.10040.4.1";

/** Bits de los tamaños de curva que el algoritmo no dice por sí solo. */
const CURVE_BITS: Record<string, number> = {
  "1.2.840.10045.3.1.7": 256,
  "1.3.132.0.34": 384,
  "1.3.132.0.35": 521,
  "1.3.132.0.10": 256,
  "1.2.840.10045.3.1.1": 192,
  "1.3.132.0.33": 224
};

/** Lo que se sabe de una clave, antes de casarla con un certificado. */
export type KeyFacts = Omit<CdpLooseKey, "path" | "certMatch" | "matchedFingerprint256">;

const PEM_KEY_RE = /-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----([\s\S]*?)-----END \1-----/g;

/** ¿Hay algo que parezca una clave privada en estos bytes? Barato, para decidir. */
export function mayContainPrivateKey(buf: Buffer): boolean {
  const text = buf.toString("latin1");
  return /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(text) || looksLikeDerPrivateKey(buf);
}

function bitLength(buf: Buffer, tlv: Tlv): number | undefined {
  let start = tlv.start;
  while (start < tlv.end && buf[start] === 0) start += 1;
  if (start >= tlv.end) return undefined;
  const first = buf[start];
  return (tlv.end - start - 1) * 8 + (32 - Math.clz32(first));
}

/** SEQUENCE { contenido... } con la cabecera DER correcta. */
function derSequence(content: Buffer): Buffer {
  return Buffer.concat([derHeader(TAG_SEQUENCE, content.length), content]);
}

function derHeader(tag: number, len: number): Buffer {
  if (len < 0x80) return Buffer.from([tag, len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([tag, 0x80 | bytes.length, ...bytes]);
}

function spkiHash(algId: Buffer, bitStringContent: Buffer): string {
  const spki = derSequence(Buffer.concat([algId, derHeader(TAG_BIT_STRING, bitStringContent.length), bitStringContent]));
  return crypto.createHash("sha256").update(spki).digest("hex");
}

/** RSAPrivateKey / RSAPublicKey → { bits, hash } desde n y e (públicos). */
function rsaFacts(buf: Buffer, seq: Tlv, algId: Buffer): { keySizeBits?: number; publicKeyHash?: string } {
  const parts = children(buf, seq);
  // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, ... }
  // Solo se miran los dos primeros enteros tras la versión.
  const [version, n, e] = parts;
  if (!version || version.tag !== TAG_INTEGER || !n || n.tag !== TAG_INTEGER || !e || e.tag !== TAG_INTEGER) return {};
  const keySizeBits = bitLength(buf, n);
  const rsaPublicKey = derSequence(Buffer.concat([buf.subarray(n.headerStart, n.next), buf.subarray(e.headerStart, e.next)]));
  const publicKeyHash = spkiHash(algId, Buffer.concat([Buffer.from([0]), rsaPublicKey]));
  rsaPublicKey.fill(0);
  return { keySizeBits, publicKeyHash };
}

const RSA_ALG_ID = Buffer.from("300d06092a864886f70d0101010500", "hex");

function ecAlgId(curveOidTlvBytes: Buffer): Buffer {
  // AlgorithmIdentifier { id-ecPublicKey, namedCurve }
  const ecOid = Buffer.from("06072a8648ce3d0201", "hex");
  return derSequence(Buffer.concat([ecOid, curveOidTlvBytes]));
}

/** ECPrivateKey (SEC1) → curva desde [0] (o la dada) y hash desde [1] publicKey. */
function sec1Facts(
  buf: Buffer,
  seq: Tlv,
  outerCurve?: { oid: string; bytes: Buffer }
): { curve?: string; keySizeBits?: number; publicKeyHash?: string; curveOid?: string } {
  const parts = children(buf, seq);
  let curve = outerCurve;
  let pub: Tlv | undefined;
  for (const p of parts.slice(2)) {
    if (p.tag === TAG_CTX0) {
      const oidTlv = children(buf, p)[0];
      const oid = decodeOid(buf, oidTlv ?? null);
      if (oid && oidTlv) curve = { oid, bytes: buf.subarray(oidTlv.headerStart, oidTlv.next) };
    } else if (p.tag === TAG_CTX1) {
      const bs = children(buf, p)[0];
      if (bs && bs.tag === TAG_BIT_STRING) pub = bs;
    }
  }
  const out: { curve?: string; keySizeBits?: number; publicKeyHash?: string } = {};
  if (curve) {
    out.curve = curveName(curve.oid);
    out.keySizeBits = CURVE_BITS[curve.oid];
    if (pub) out.publicKeyHash = spkiHash(ecAlgId(curve.bytes), buf.subarray(pub.start, pub.end));
  }
  return out;
}

/** PrivateKeyInfo / OneAsymmetricKey (RFC 5958), sin cifrar. */
function pkcs8Facts(buf: Buffer): KeyFacts | null {
  const top = readTlv(buf, 0);
  if (!top || top.tag !== TAG_SEQUENCE) return null;
  const parts = children(buf, top);
  const [version, algIdTlv, privateKey] = parts;
  if (!version || version.tag !== TAG_INTEGER || !algIdTlv || algIdTlv.tag !== TAG_SEQUENCE) return null;
  if (!privateKey || privateKey.tag !== TAG_OCTET_STRING) return null;

  const algParts = children(buf, algIdTlv);
  const oid = decodeOid(buf, algParts[0] ?? null);
  if (!oid) return null;
  const facts: KeyFacts = { format: "pkcs8", encrypted: false, readable: true, keyAlgorithm: algorithmName(oid) };
  const algId = buf.subarray(algIdTlv.headerStart, algIdTlv.next);

  const inner = readTlv(buf, privateKey.start);
  if (oid === OID_RSA || oid === OID_RSA_PSS) {
    facts.keyAlgorithm = oid === OID_RSA ? "RSA" : "RSASSA-PSS";
    if (inner && inner.tag === TAG_SEQUENCE && inner.next <= privateKey.end) {
      Object.assign(facts, rsaFacts(buf, inner, algId));
    }
  } else if (oid === OID_EC) {
    facts.keyAlgorithm = "EC";
    const param = algParts[1];
    const curveOid = param && param.tag === TAG_OID ? decodeOid(buf, param) : null;
    const outer = curveOid && param ? { oid: curveOid, bytes: buf.subarray(param.headerStart, param.next) } : undefined;
    if (inner && inner.tag === TAG_SEQUENCE && inner.next <= privateKey.end) {
      const ec = sec1Facts(buf, inner, outer);
      Object.assign(facts, { curve: ec.curve, keySizeBits: ec.keySizeBits, publicKeyHash: ec.publicKeyHash });
    } else if (outer) {
      facts.curve = curveName(outer.oid);
      facts.keySizeBits = CURVE_BITS[outer.oid];
    }
  } else if (oid === OID_DSA) {
    facts.keyAlgorithm = "DSA";
    // Dss-Parms { p, q, g }: el tamaño es el de p, que es público.
    const params = algParts[1];
    const p = params && params.tag === TAG_SEQUENCE ? children(buf, params)[0] : undefined;
    if (p && p.tag === TAG_INTEGER) facts.keySizeBits = bitLength(buf, p);
  }

  // OneAsymmetricKey v2 trae la clave pública en claro: [1] IMPLICIT BIT
  // STRING. Es el único camino de casar Ed25519/Ed448 o ML-DSA sin la
  // privada. Solo si no se derivó ya por la vía del algoritmo.
  if (!facts.publicKeyHash) {
    const pub = parts.slice(3).find((p) => p.tag === TAG_CTX1_IMPLICIT);
    // El AlgorithmIdentifier de la SPKI es el mismo que el de la clave.
    if (pub) facts.publicKeyHash = spkiHash(algId, buf.subarray(pub.start, pub.end));
  }
  return stripUndefined(facts);
}

/** EncryptedPrivateKeyInfo { SEQUENCE { OID, params }, OCTET STRING }. */
function isEncryptedPkcs8(buf: Buffer): boolean {
  const top = readTlv(buf, 0);
  if (!top || top.tag !== TAG_SEQUENCE || top.next !== buf.length) return false;
  const [alg, data] = children(buf, top);
  if (!alg || alg.tag !== TAG_SEQUENCE || !data || data.tag !== TAG_OCTET_STRING) return false;
  const oid = decodeOid(buf, children(buf, alg)[0] ?? null);
  // PBES2 (1.2.840.113549.1.5.13), PBES1 (…1.5.x) o PBE de PKCS#12 (…1.12.1.x).
  return !!oid && /^1\.2\.840\.113549\.1\.(5|12\.1)\./.test(oid);
}

/** DER sin armadura con forma de PKCS#8 (claro o cifrado). */
export function looksLikeDerPrivateKey(buf: Buffer): boolean {
  if (buf.length < 16 || buf[0] !== TAG_SEQUENCE) return false;
  if (isEncryptedPkcs8(buf)) return true;
  const top = readTlv(buf, 0);
  if (!top || top.next !== buf.length) return false;
  const [version, alg, key] = children(buf, top);
  return (
    !!version && version.tag === TAG_INTEGER && version.end - version.start === 1 && buf[version.start] <= 1 &&
    !!alg && alg.tag === TAG_SEQUENCE && !!key && key.tag === TAG_OCTET_STRING
  );
}

function stripUndefined<T extends Record<string, unknown>>(o: T): T {
  for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
  return o;
}

function factsFromPemBlock(label: string, body: string): KeyFacts {
  const encryptedHeader = /Proc-Type:\s*4,\s*ENCRYPTED/i.test(body);
  const kind = label.replace(" PRIVATE KEY", "").replace("PRIVATE KEY", "").trim();
  if (label === "ENCRYPTED PRIVATE KEY") return { format: "pkcs8-encrypted", encrypted: true, readable: true };
  if (encryptedHeader) {
    // PEM heredado cifrado (OpenSSL «traditional»): el tipo lo dice la
    // etiqueta; el resto está cifrado y así se queda.
    const alg = kind === "RSA" ? "RSA" : kind === "EC" ? "EC" : kind === "DSA" ? "DSA" : undefined;
    return stripUndefined({ format: "pem-encrypted", encrypted: true, readable: true, keyAlgorithm: alg });
  }

  const der = Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  try {
    if (label === "PRIVATE KEY") {
      return pkcs8Facts(der) ?? { format: "pkcs8", encrypted: false, readable: true };
    }
    const seq = readTlv(der, 0);
    if (label === "RSA PRIVATE KEY") {
      const facts: KeyFacts = { format: "pkcs1", encrypted: false, readable: true, keyAlgorithm: "RSA" };
      if (seq && seq.tag === TAG_SEQUENCE) Object.assign(facts, rsaFacts(der, seq, RSA_ALG_ID));
      return stripUndefined(facts);
    }
    if (label === "EC PRIVATE KEY") {
      const facts: KeyFacts = { format: "sec1", encrypted: false, readable: true, keyAlgorithm: "EC" };
      if (seq && seq.tag === TAG_SEQUENCE) {
        const ec = sec1Facts(der, seq);
        Object.assign(facts, { curve: ec.curve, keySizeBits: ec.keySizeBits, publicKeyHash: ec.publicKeyHash });
      }
      return stripUndefined(facts);
    }
    // DSA PRIVATE KEY ::= SEQUENCE { 0, p, q, g, y, x }: tamaño de p.
    const facts: KeyFacts = { format: "dsa", encrypted: false, readable: true, keyAlgorithm: "DSA" };
    if (seq && seq.tag === TAG_SEQUENCE) {
      const p = children(der, seq)[1];
      if (p && p.tag === TAG_INTEGER) facts.keySizeBits = bitLength(der, p);
    }
    return stripUndefined(facts);
  } finally {
    der.fill(0);
  }
}

/**
 * Cada clave privada de un fichero, descrita sin su secreto.
 *
 * PEM: un fichero puede traer varias (raro, pero `cat *.key > todo.pem`
 * existe). DER: una, si tiene forma de PKCS#8. Vacío = no hay clave.
 */
export function describePrivateKeys(buf: Buffer): KeyFacts[] {
  const text = buf.toString("latin1");
  const out: KeyFacts[] = [];
  PEM_KEY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PEM_KEY_RE.exec(text)) !== null && out.length < 16) {
    try {
      out.push(factsFromPemBlock(m[1], m[2]));
    } catch {
      out.push({ format: "unknown", encrypted: null, readable: true });
    }
  }
  if (out.length > 0) return out;

  if (buf.length > 0 && buf[0] === TAG_SEQUENCE) {
    try {
      if (isEncryptedPkcs8(buf)) return [{ format: "pkcs8-encrypted", encrypted: true, readable: true }];
      if (looksLikeDerPrivateKey(buf)) {
        const facts = pkcs8Facts(buf);
        if (facts) return [facts];
      }
    } catch {
      // Estructura rara: no es una clave que sepamos describir.
    }
  }
  return [];
}
