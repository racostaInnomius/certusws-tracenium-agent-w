// src/plugins/cdp/pkcs12.ts
//
// Lector mínimo de PKCS#12 (.p12 / .pfx, RFC 7292) para el escaneo de
// ficheros de CDP. Node no trae uno (crypto no abre PFX) y el agente no
// depende de node-forge ni de @peculiar, así que se lee con el mismo
// lector DER que ya usan los OIDs, catalyst y los punteros de revocación.
//
// ── Lo que hace y lo que NO hace ─────────────────────────────────────
//
// Solo saca CERTIFICADOS. Las bolsas de clave privada (keyBag y
// pkcs8ShroudedKeyBag) nunca se descifran ni se decodifican por dentro:
// de ellas se leen únicamente sus ATRIBUTOS (localKeyId), que en PKCS#12
// van fuera del cifrado. Con eso basta para decir qué certificado tiene
// su clave en el fichero (`hasPrivateKey`) sin tocar material de clave.
// Mismo principio que jks.ts: el parser no puede filtrar lo que nunca
// descifra.
//
// Contraseña: se prueba SOLO la vacía (en sus dos codificaciones: la
// BMPString de "" —dos ceros— y la ausencia de contraseña, que OpenSSL
// trata distinto). Un PFX que necesita una real lanza Pkcs12Error con
// una razón, y quien llama lo reporta como almacén ILEGIBLE — nunca como
// fichero vacío (ver 2a80f2c: un almacén que no se pudo leer no es un
// almacén vacío). No se piden ni se prueban contraseñas.
//
// Cifrados soportados para las bolsas de certificados:
//   * PBES2 + PBKDF2 (HMAC-SHA1/224/256/384/512) + AES-CBC o 3DES — el
//     defecto de OpenSSL 3 y de Windows moderno.
//   * PBE de PKCS#12 con SHA-1: 3DES (3 y 2 claves) y RC2 (40 y 128) —
//     el defecto de OpenSSL 1.x y de exportaciones antiguas de Windows.
//     RC2 va en JS porque el OpenSSL 3 de Node lo tiene en el proveedor
//     "legacy", que no carga.
//
// No soportado (→ Pkcs12Error, o sea ilegible con razón): el modo de
// integridad por clave pública (authSafe signedData), el modo de
// privacidad por clave pública (envelopedData) y las codificaciones BER
// de longitud indefinida.
//
// SEGURIDAD: entrada hostil leída como root/LocalSystem. Todo acceso
// pasa por readTlv (acotado), la profundidad de anidamiento está
// limitada y el número de iteraciones de las KDF también — un fichero
// con 2^31 iteraciones no puede colgar el escaneo.

import crypto from "crypto";
import { readTlv, children, decodeOid, type Tlv } from "./der";

export class Pkcs12Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Pkcs12Error";
  }
}

export type Pkcs12Cert = {
  /** El certificado en DER. */
  der: Buffer;
  /** Su clave privada está en el mismo PFX (casada por localKeyId). */
  hasPrivateKey: boolean;
};

const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OCTET_STRING_CONSTRUCTED = 0x24;
const TAG_CONTEXT_0_EXPLICIT = 0xa0;
const TAG_CONTEXT_0_PRIMITIVE = 0x80;

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
const OID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";

const BAG_KEY = "1.2.840.113549.1.12.10.1.1";
const BAG_SHROUDED_KEY = "1.2.840.113549.1.12.10.1.2";
const BAG_CERT = "1.2.840.113549.1.12.10.1.3";
const BAG_SAFE_CONTENTS = "1.2.840.113549.1.12.10.1.6";
const CERT_TYPE_X509 = "1.2.840.113549.1.9.22.1";
const ATTR_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";

const OID_PBES2 = "1.2.840.113549.1.5.13";
const OID_PBKDF2 = "1.2.840.113549.1.5.12";

/** Digest OIDs → [nombre de Node, tamaño de bloque v en bytes]. */
const DIGESTS: Record<string, [string, number]> = {
  "1.3.14.3.2.26": ["sha1", 64],
  "2.16.840.1.101.3.4.2.4": ["sha224", 64],
  "2.16.840.1.101.3.4.2.1": ["sha256", 64],
  "2.16.840.1.101.3.4.2.2": ["sha384", 128],
  "2.16.840.1.101.3.4.2.3": ["sha512", 128]
};

/** PRF de PBKDF2 → nombre de Node. */
const HMAC_PRFS: Record<string, string> = {
  "1.2.840.113549.2.7": "sha1",
  "1.2.840.113549.2.8": "sha224",
  "1.2.840.113549.2.9": "sha256",
  "1.2.840.113549.2.10": "sha384",
  "1.2.840.113549.2.11": "sha512"
};

/** Esquemas de cifrado de PBES2 → [cifrado de Node, longitud de clave]. */
const PBES2_CIPHERS: Record<string, [string, number]> = {
  "2.16.840.1.101.3.4.1.2": ["aes-128-cbc", 16],
  "2.16.840.1.101.3.4.1.22": ["aes-192-cbc", 24],
  "2.16.840.1.101.3.4.1.42": ["aes-256-cbc", 32],
  "1.2.840.113549.3.7": ["des-ede3-cbc", 24]
};

/** PBE de PKCS#12 (SHA-1) → [cifrado, longitud de clave, bits efectivos RC2]. */
const PKCS12_PBE: Record<string, [string, number, number]> = {
  "1.2.840.113549.1.12.1.3": ["des-ede3-cbc", 24, 0],
  "1.2.840.113549.1.12.1.4": ["des-ede-cbc", 16, 0],
  "1.2.840.113549.1.12.1.5": ["rc2", 16, 128],
  "1.2.840.113549.1.12.1.6": ["rc2", 5, 40]
};

/** OpenSSL usa 2048 por defecto; Windows, 2000. Muy por encima de eso
 *  no hay un PFX legítimo, hay un fichero que quiere colgar el escaneo. */
const MAX_ITERATIONS = 1_000_000;
const MAX_DEPTH = 4;
const MAX_CERTS = 64;

// ── DER ──────────────────────────────────────────────────────────────

function tlvAt(buf: Buffer, offset: number, what: string): Tlv {
  const t = readTlv(buf, offset);
  if (!t) throw new Pkcs12Error(`malformed or BER-encoded ${what}`);
  return t;
}

function expectTag(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t || t.tag !== tag) throw new Pkcs12Error(`unexpected structure at ${what}`);
  return t;
}

function smallInt(buf: Buffer, t: Tlv | undefined, what: string): number {
  expectTag(t, TAG_INTEGER, what);
  const len = t!.end - t!.start;
  if (len === 0 || len > 6 || (buf[t!.start] & 0x80) !== 0) {
    throw new Pkcs12Error(`${what}: integer out of range`);
  }
  let v = 0;
  for (let i = t!.start; i < t!.end; i++) v = v * 256 + buf[i];
  return v;
}

function iterations(buf: Buffer, t: Tlv | undefined, what: string): number {
  const n = smallInt(buf, t, what);
  if (n < 1 || n > MAX_ITERATIONS) throw new Pkcs12Error(`${what}: iteration count ${n} out of range`);
  return n;
}

/** Contenido de un OCTET STRING, primitivo o construido (BER por trozos,
 *  que Windows y Java emiten en el authSafe). */
function octets(buf: Buffer, t: Tlv, what: string, primitiveTag = TAG_OCTET_STRING): Buffer {
  if (t.tag === primitiveTag) return buf.subarray(t.start, t.end);
  if (t.tag === (primitiveTag | 0x20)) {
    const parts = children(buf, t).map((c) => {
      if (c.tag !== TAG_OCTET_STRING) throw new Pkcs12Error(`${what}: bad constructed octet string`);
      return buf.subarray(c.start, c.end);
    });
    return Buffer.concat(parts);
  }
  throw new Pkcs12Error(`unexpected structure at ${what}`);
}

// ── KDF de PKCS#12 (RFC 7292, apéndice B.2) ──────────────────────────

/** La contraseña como BMPString big-endian terminada en dos ceros. `null`
 *  = sin contraseña (cadena de longitud cero, no la BMP de ""). */
function bmpPassword(password: string | null): Buffer {
  if (password === null) return Buffer.alloc(0);
  const out = Buffer.alloc((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) out.writeUInt16BE(password.charCodeAt(i), i * 2);
  return out;
}

export function pkcs12Kdf(
  hash: string,
  v: number,
  password: Buffer,
  salt: Buffer,
  id: number,
  iter: number,
  size: number
): Buffer {
  const u = crypto.createHash(hash).digest().length;
  const fill = (src: Buffer): Buffer => {
    if (src.length === 0) return Buffer.alloc(0);
    const len = v * Math.ceil(src.length / v);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) out[i] = src[i % src.length];
    return out;
  };
  const D = Buffer.alloc(v, id);
  const I = Buffer.concat([fill(salt), fill(password)]);
  const out = Buffer.alloc(size);
  let written = 0;

  while (written < size) {
    let A = crypto.createHash(hash).update(D).update(I).digest();
    for (let i = 1; i < iter; i++) A = crypto.createHash(hash).update(A).digest();
    A.copy(out, written, 0, Math.min(u, size - written));
    written += u;
    if (written >= size) break;

    // I_j = (I_j + B + 1) mod 2^(8v), con B = A repetido hasta v bytes.
    const B = Buffer.alloc(v);
    for (let i = 0; i < v; i++) B[i] = A[i % u];
    for (let j = 0; j < I.length; j += v) {
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const sum = I[j + k] + B[k] + carry;
        I[j + k] = sum & 0xff;
        carry = sum >> 8;
      }
    }
  }
  return out;
}

// ── RC2 (RFC 2268), solo descifrado CBC ──────────────────────────────

const PITABLE = Buffer.from(
  "d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2" +
  "179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82" +
  "54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626" +
  "6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7" +
  "08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec" +
  "c2e0416e0f51cbcc2491af50a1f47039997c3a8523b8b47afc02365b25559731" +
  "2d5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a9" +
  "0d38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad",
  "hex"
);

function rc2ExpandKey(key: Buffer, effectiveBits: number): Uint16Array {
  const T = key.length;
  const T8 = Math.ceil(effectiveBits / 8);
  const TM = 0xff % (1 << (8 + effectiveBits - 8 * T8));
  const L = Buffer.alloc(128);
  key.copy(L);
  for (let i = T; i < 128; i++) L[i] = PITABLE[(L[i - 1] + L[i - T]) & 0xff];
  L[128 - T8] = PITABLE[L[128 - T8] & TM];
  for (let i = 127 - T8; i >= 0; i--) L[i] = PITABLE[L[i + 1] ^ L[i + T8]];
  const K = new Uint16Array(64);
  for (let i = 0; i < 64; i++) K[i] = L[2 * i] | (L[2 * i + 1] << 8);
  return K;
}

function rc2DecryptBlock(K: Uint16Array, block: Buffer): Buffer {
  const R = [block.readUInt16LE(0), block.readUInt16LE(2), block.readUInt16LE(4), block.readUInt16LE(6)];
  const S = [1, 2, 3, 5];
  let j = 63;
  const rmix = () => {
    for (let i = 3; i >= 0; i--) {
      R[i] = ((R[i] >>> S[i]) | (R[i] << (16 - S[i]))) & 0xffff;
      R[i] = (R[i] - K[j] - (R[(i + 3) % 4] & R[(i + 2) % 4]) - (~R[(i + 3) % 4] & R[(i + 1) % 4])) & 0xffff;
      j--;
    }
  };
  const rmash = () => {
    for (let i = 3; i >= 0; i--) R[i] = (R[i] - K[R[(i + 3) % 4] & 63]) & 0xffff;
  };
  for (let n = 0; n < 5; n++) rmix();
  rmash();
  for (let n = 0; n < 6; n++) rmix();
  rmash();
  for (let n = 0; n < 5; n++) rmix();
  const out = Buffer.alloc(8);
  for (let i = 0; i < 4; i++) out.writeUInt16LE(R[i], i * 2);
  return out;
}

/** Exportado para los vectores del RFC 2268. Sin quitar el relleno. */
export function rc2DecryptEcbBlock(key: Buffer, effectiveBits: number, block: Buffer): Buffer {
  return rc2DecryptBlock(rc2ExpandKey(key, effectiveBits), block);
}

function rc2CbcDecrypt(key: Buffer, effectiveBits: number, iv: Buffer, data: Buffer): Buffer {
  if (data.length === 0 || data.length % 8 !== 0) throw new Pkcs12Error("bad RC2 ciphertext length");
  const K = rc2ExpandKey(key, effectiveBits);
  const out = Buffer.alloc(data.length);
  let prev = iv;
  for (let off = 0; off < data.length; off += 8) {
    const c = data.subarray(off, off + 8);
    const p = rc2DecryptBlock(K, c);
    for (let i = 0; i < 8; i++) out[off + i] = p[i] ^ prev[i];
    prev = c;
  }
  return stripPkcs7(out);
}

function stripPkcs7(buf: Buffer): Buffer {
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 8) throw new Pkcs12Error("decryption failed");
  for (let i = buf.length - pad; i < buf.length; i++) {
    if (buf[i] !== pad) throw new Pkcs12Error("decryption failed");
  }
  return buf.subarray(0, buf.length - pad);
}

// ── Descifrado de un EncryptedContentInfo ────────────────────────────

function decipher(name: string, key: Buffer, iv: Buffer, data: Buffer): Buffer {
  try {
    const d = crypto.createDecipheriv(name, key, iv);
    return Buffer.concat([d.update(data), d.final()]);
  } catch {
    // Relleno inválido = contraseña equivocada en la inmensa mayoría de
    // los casos. No se distingue de un fichero corrupto, y no hace falta:
    // las dos cosas son "no se pudo leer".
    throw new Pkcs12Error("decryption failed");
  }
}

function decrypt(buf: Buffer, algId: Tlv, data: Buffer, password: string | null): Buffer {
  const parts = children(buf, expectTag(algId, TAG_SEQUENCE, "encryption algorithm"));
  const oid = decodeOid(buf, parts[0]);

  if (oid && PKCS12_PBE[oid]) {
    const [cipher, keyLen, rc2Bits] = PKCS12_PBE[oid];
    const params = children(buf, expectTag(parts[1], TAG_SEQUENCE, "PBE params"));
    const salt = buf.subarray(expectTag(params[0], TAG_OCTET_STRING, "PBE salt").start, params[0].end);
    const iter = iterations(buf, params[1], "PBE");
    const pw = bmpPassword(password);
    const key = pkcs12Kdf("sha1", 64, pw, salt, 1, iter, keyLen);
    const iv = pkcs12Kdf("sha1", 64, pw, salt, 2, iter, 8);
    return cipher === "rc2" ? rc2CbcDecrypt(key, rc2Bits, iv, data) : decipher(cipher, key, iv, data);
  }

  if (oid === OID_PBES2) {
    const params = children(buf, expectTag(parts[1], TAG_SEQUENCE, "PBES2 params"));
    const kdf = children(buf, expectTag(params[0], TAG_SEQUENCE, "PBES2 kdf"));
    if (decodeOid(buf, kdf[0]) !== OID_PBKDF2) throw new Pkcs12Error("unsupported PBES2 key derivation");
    const kp = children(buf, expectTag(kdf[1], TAG_SEQUENCE, "PBKDF2 params"));
    const salt = buf.subarray(expectTag(kp[0], TAG_OCTET_STRING, "PBKDF2 salt").start, kp[0].end);
    const iter = iterations(buf, kp[1], "PBKDF2");
    let prf = "sha1";
    // keyLength (INTEGER) y prf (SEQUENCE) son opcionales, en ese orden.
    for (const extra of kp.slice(2)) {
      if (extra.tag === TAG_SEQUENCE) {
        const prfOid = decodeOid(buf, children(buf, extra)[0]);
        if (!prfOid || !HMAC_PRFS[prfOid]) throw new Pkcs12Error("unsupported PBKDF2 PRF");
        prf = HMAC_PRFS[prfOid];
      }
    }
    const enc = children(buf, expectTag(params[1], TAG_SEQUENCE, "PBES2 cipher"));
    const encOid = decodeOid(buf, enc[0]);
    if (!encOid || !PBES2_CIPHERS[encOid]) throw new Pkcs12Error(`unsupported PBES2 cipher ${encOid ?? "?"}`);
    const [cipher, keyLen] = PBES2_CIPHERS[encOid];
    const iv = buf.subarray(expectTag(enc[1], TAG_OCTET_STRING, "PBES2 IV").start, enc[1].end);
    // PBES2 dentro de PKCS#12 deriva de la contraseña en UTF-8, no en BMP.
    const key = crypto.pbkdf2Sync(Buffer.from(password ?? "", "utf8"), salt, iter, keyLen, prf);
    return decipher(cipher, key, iv, data);
  }

  throw new Pkcs12Error(`unsupported encryption ${oid ?? "?"}`);
}

// ── MAC ──────────────────────────────────────────────────────────────

/**
 * ¿Abre la contraseña este PFX? `null` = no se puede saber (sin MacData o
 * algoritmo de MAC que no conocemos, p. ej. PBMAC1): entonces decide el
 * descifrado.
 */
function macMatches(buf: Buffer, macData: Tlv, authSafe: Buffer, password: string | null): boolean | null {
  const parts = children(buf, expectTag(macData, TAG_SEQUENCE, "MacData"));
  const digestInfo = children(buf, expectTag(parts[0], TAG_SEQUENCE, "MAC DigestInfo"));
  const alg = children(buf, expectTag(digestInfo[0], TAG_SEQUENCE, "MAC algorithm"));
  const digestOid = decodeOid(buf, alg[0]);
  if (!digestOid || !DIGESTS[digestOid]) return null;
  const [hash, v] = DIGESTS[digestOid];
  const expected = buf.subarray(expectTag(digestInfo[1], TAG_OCTET_STRING, "MAC digest").start, digestInfo[1].end);
  const salt = buf.subarray(expectTag(parts[1], TAG_OCTET_STRING, "MAC salt").start, parts[1].end);
  const iter = parts[2] ? iterations(buf, parts[2], "MAC") : 1;
  const key = pkcs12Kdf(hash, v, bmpPassword(password), salt, 3, iter, expected.length);
  const actual = crypto.createHmac(hash, key).update(authSafe).digest();
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// ── Bolsas ───────────────────────────────────────────────────────────

type Collected = { certs: { der: Buffer; keyId: string | null }[]; keyIds: Set<string> };

function localKeyId(buf: Buffer, attrs: Tlv | undefined): string | null {
  if (!attrs || attrs.tag !== TAG_SET) return null;
  for (const attr of children(buf, attrs)) {
    if (attr.tag !== TAG_SEQUENCE) continue;
    const [id, values] = children(buf, attr);
    if (decodeOid(buf, id) !== ATTR_LOCAL_KEY_ID || !values || values.tag !== TAG_SET) continue;
    const v = children(buf, values)[0];
    if (v && v.tag === TAG_OCTET_STRING) return buf.subarray(v.start, v.end).toString("hex");
  }
  return null;
}

function readSafeContents(buf: Buffer, out: Collected, depth: number): void {
  if (depth > MAX_DEPTH) throw new Pkcs12Error("SafeContents nested too deep");
  const seq = expectTag(tlvAt(buf, 0, "SafeContents"), TAG_SEQUENCE, "SafeContents");

  for (const bag of children(buf, seq)) {
    if (bag.tag !== TAG_SEQUENCE) continue;
    const [idTlv, valueWrap, attrs] = children(buf, bag);
    const bagId = decodeOid(buf, idTlv);

    if (bagId === BAG_KEY || bagId === BAG_SHROUDED_KEY) {
      // SOLO el atributo. El valor de la bolsa —la clave, cifrada o no—
      // no se mira ni se copia.
      const id = localKeyId(buf, attrs);
      if (id) out.keyIds.add(id);
      continue;
    }

    if (bagId === BAG_CERT) {
      const certBag = children(buf, expectTag(valueWrap, TAG_CONTEXT_0_EXPLICIT, "CertBag"))[0];
      const [typeTlv, certWrap] = children(buf, expectTag(certBag, TAG_SEQUENCE, "CertBag"));
      // sdsiCertificate y otros tipos exóticos: no son X.509, se ignoran.
      if (decodeOid(buf, typeTlv) !== CERT_TYPE_X509) continue;
      const inner = children(buf, expectTag(certWrap, TAG_CONTEXT_0_EXPLICIT, "certValue"))[0];
      if (!inner) throw new Pkcs12Error("empty certValue");
      if (out.certs.length >= MAX_CERTS) throw new Pkcs12Error("too many certificates");
      out.certs.push({ der: Buffer.from(octets(buf, inner, "certValue")), keyId: localKeyId(buf, attrs) });
      continue;
    }

    if (bagId === BAG_SAFE_CONTENTS) {
      const nested = children(buf, expectTag(valueWrap, TAG_CONTEXT_0_EXPLICIT, "safeContentsBag"))[0];
      if (!nested) continue;
      readSafeContents(buf.subarray(nested.headerStart, nested.end), out, depth + 1);
    }
    // crlBag, secretBag: ni certificados ni asunto nuestro.
  }
}

function readAuthSafe(authSafe: Buffer, password: string | null): Collected {
  const out: Collected = { certs: [], keyIds: new Set() };
  const seq = expectTag(tlvAt(authSafe, 0, "AuthenticatedSafe"), TAG_SEQUENCE, "AuthenticatedSafe");

  for (const ci of children(authSafe, seq)) {
    const [typeTlv, contentWrap] = children(authSafe, expectTag(ci, TAG_SEQUENCE, "ContentInfo"));
    const type = decodeOid(authSafe, typeTlv);
    const content = children(authSafe, expectTag(contentWrap, TAG_CONTEXT_0_EXPLICIT, "ContentInfo content"))[0];
    if (!content) continue;

    if (type === OID_DATA) {
      readSafeContents(octets(authSafe, content, "SafeContents"), out, 0);
    } else if (type === OID_ENCRYPTED_DATA) {
      const ed = children(authSafe, expectTag(content, TAG_SEQUENCE, "EncryptedData"));
      const eci = children(authSafe, expectTag(ed[1], TAG_SEQUENCE, "EncryptedContentInfo"));
      if (!eci[2]) continue; // sin contenido cifrado: nada que leer
      const ciphertext = octets(authSafe, eci[2], "encryptedContent", TAG_CONTEXT_0_PRIMITIVE);
      const plain = decrypt(authSafe, eci[1], ciphertext, password);
      readSafeContents(plain, out, 0);
    } else if (type === OID_ENVELOPED_DATA) {
      throw new Pkcs12Error("public-key privacy mode (envelopedData) not supported");
    } else {
      throw new Pkcs12Error(`unsupported content type ${type ?? "?"}`);
    }
  }
  return out;
}

/** ¿Tiene pinta de PFX? SEQUENCE { INTEGER 3, SEQUENCE … }. */
export function looksLikePkcs12(buf: Buffer): boolean {
  const pfx = readTlv(buf, 0);
  if (!pfx || pfx.tag !== TAG_SEQUENCE) return false;
  const [version] = children(buf, pfx);
  return !!version && version.tag === TAG_INTEGER && version.end - version.start === 1 && buf[version.start] === 3;
}

/**
 * Los certificados de un PFX abierto con la contraseña vacía.
 *
 * Lanza Pkcs12Error si el fichero no se puede abrir así (contraseña real,
 * corrupto o variante no soportada). El mensaje es una razón legible para
 * el operador y NUNCA contiene bytes del fichero.
 */
export function readPkcs12Certificates(buf: Buffer): Pkcs12Cert[] {
  const pfx = expectTag(tlvAt(buf, 0, "PFX"), TAG_SEQUENCE, "PFX");
  const [version, authSafeCi, macData] = children(buf, pfx);
  if (smallInt(buf, version, "PFX version") !== 3) throw new Pkcs12Error("not a PKCS#12 v3 file");

  const [typeTlv, contentWrap] = children(buf, expectTag(authSafeCi, TAG_SEQUENCE, "authSafe"));
  const type = decodeOid(buf, typeTlv);
  if (type === OID_SIGNED_DATA) throw new Pkcs12Error("public-key integrity mode (signedData) not supported");
  if (type !== OID_DATA) throw new Pkcs12Error(`unsupported authSafe type ${type ?? "?"}`);
  const content = children(buf, expectTag(contentWrap, TAG_CONTEXT_0_EXPLICIT, "authSafe content"))[0];
  if (!content) throw new Pkcs12Error("empty authSafe");
  const authSafe = octets(buf, content, "authSafe");

  // Las dos formas de "sin contraseña" que existen en la práctica. Con
  // MAC se elige por el MAC; sin él (o con uno que no conocemos) decide
  // el descifrado.
  const candidates: (string | null)[] = ["", null];
  let passwords = candidates;
  if (macData) {
    const matching = candidates.filter((p) => macMatches(buf, macData, authSafe, p) !== false);
    if (matching.length === 0) throw new Pkcs12Error("password required (empty password rejected)");
    passwords = matching;
  }

  let lastError: unknown = null;
  for (const password of passwords) {
    try {
      const { certs, keyIds } = readAuthSafe(authSafe, password);
      return certs.map((c) => ({ der: c.der, hasPrivateKey: c.keyId !== null && keyIds.has(c.keyId) }));
    } catch (err) {
      lastError = err;
    }
  }
  if (lastError instanceof Pkcs12Error && lastError.message === "decryption failed" && !macData) {
    throw new Pkcs12Error("password required (empty password rejected)");
  }
  throw lastError instanceof Pkcs12Error ? lastError : new Pkcs12Error("malformed PKCS#12");
}
