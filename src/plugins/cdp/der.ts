// src/plugins/cdp/der.ts
//
// Minimal DER reader, just enough to pull algorithm OIDs out of an X.509
// certificate. Exists because Node's crypto.X509Certificate cannot tell
// us what we need:
//
//   * `publicKey.asymmetricKeyType` only models RSA, EC, Ed25519/448 and
//     X25519/448. A post-quantum certificate (ML-DSA, SLH-DSA) reports
//     nothing at all — indistinguishable from a parse failure.
//   * `sigAlgName` is undefined on the Node versions we ship, and
//     `toString()` returns PEM (not an OpenSSL text dump), so the old
//     "sniff the textual dump" fallback could never match. Measured on
//     the pilot fleet: 2129 certificates, 0 with a signature algorithm.
//
// Reading the OID straight from the DER fixes both, and — critically —
// keeps working for algorithms that did not exist when this code shipped.
//
// SECURITY: this parses untrusted input collected from endpoints. Every
// read is bounds-checked, lengths are validated against the buffer,
// indefinite-length encodings (illegal in DER) are rejected, and both
// nesting depth and sibling count are capped. A malformed certificate
// must return null, never throw or spin.

const TAG_SEQUENCE = 0x30;
const TAG_OID = 0x06;
const TAG_CONTEXT_0 = 0xa0; // [0] EXPLICIT — the optional `version` field

const MAX_SIBLINGS = 64;
const MAX_OID_BYTES = 64;

export type Tlv = {
  tag: number;
  /** Offset of the tag byte, i.e. where this TLV begins on the wire.
   *  Needed by callers that must hash or copy the encoding itself. */
  headerStart: number;
  /** Offset of the first content byte. */
  start: number;
  /** Offset one past the last content byte. */
  end: number;
  /** Offset one past the whole TLV (i.e. where the next sibling starts). */
  next: number;
};

/** Read one TLV at `offset`, or null if it does not fit / is not DER. */
export function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset < 0 || offset + 2 > buf.length) return null;

  const tag = buf[offset];
  const lengthByte = buf[offset + 1];
  let length: number;
  let headerLen: number;

  if (lengthByte < 0x80) {
    length = lengthByte;
    headerLen = 2;
  } else if (lengthByte === 0x80) {
    // Indefinite length: valid in BER, forbidden in DER.
    return null;
  } else {
    const numBytes = lengthByte & 0x7f;
    // 4 bytes caps a length at ~4GB; anything longer is malformed for our
    // purposes and would overflow the arithmetic below.
    if (numBytes > 4 || offset + 2 + numBytes > buf.length) return null;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + buf[offset + 2 + i];
    }
    headerLen = 2 + numBytes;
  }

  const start = offset + headerLen;
  const end = start + length;
  if (end > buf.length) return null;

  return { tag, headerStart: offset, start, end, next: end };
}

/** Direct children of a constructed TLV, in order. */
export function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let offset = parent.start;

  while (offset < parent.end && out.length < MAX_SIBLINGS) {
    const tlv = readTlv(buf, offset);
    if (!tlv || tlv.next > parent.end || tlv.next <= offset) break;
    out.push(tlv);
    offset = tlv.next;
  }

  return out;
}

/** Decode an OID's content bytes into dotted-decimal form. */
export function decodeOid(buf: Buffer, tlv: Tlv | null): string | null {
  if (!tlv) return null;
  const len = tlv.end - tlv.start;
  if (tlv.tag !== TAG_OID || len === 0 || len > MAX_OID_BYTES) return null;

  const parts: number[] = [];
  const first = buf[tlv.start];
  // First byte packs the first two arcs: 40*arc1 + arc2.
  parts.push(Math.floor(first / 40), first % 40);

  let value = 0;
  // Tracked separately from `value`: a dangling continuation byte whose
  // payload bits happen to be zero (e.g. 0x80 as the last byte) leaves
  // value === 0, so testing the value alone would accept a truncated OID
  // and return a plausible-looking prefix.
  let pending = false;
  for (let i = tlv.start + 1; i < tlv.end; i++) {
    const byte = buf[i];
    // Guard against a value large enough to lose integer precision.
    if (value > Number.MAX_SAFE_INTEGER / 128) return null;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
      pending = false;
    } else {
      pending = true;
    }
  }
  // A trailing continuation bit with no terminator is malformed.
  if (pending) return null;

  return parts.join(".");
}

/**
 * The raw SubjectPublicKeyInfo TLV, exactly as it appears in the
 * certificate. Hashing this is the standard way to identify "the same
 * key" across certificates (it is what `pin-sha256` pins).
 *
 * Extracted with the DER walker rather than
 * `publicKey.export({type:"spki"})` for the same reason the OIDs are:
 * Node cannot export a key whose algorithm it does not model, so the
 * export path would silently yield nothing for exactly the post-quantum
 * certificates we most want to track.
 *
 * SPKI (not the bare key bits) on purpose: it includes the algorithm
 * identifier, so an RSA key and an EC key that happened to share bytes
 * could never collide, and for EC the named curve is part of the
 * identity.
 */
export function extractSpkiDer(der: Buffer): Buffer | null {
  if (!Buffer.isBuffer(der) || der.length < 8) return null;

  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== TAG_SEQUENCE) return null;

  const tbs = children(der, cert)[0];
  if (!tbs || tbs.tag !== TAG_SEQUENCE) return null;

  const tbsChildren = children(der, tbs);
  const base = tbsChildren[0]?.tag === TAG_CONTEXT_0 ? 1 : 0;
  const spki = tbsChildren[base + 5];
  if (!spki || spki.tag !== TAG_SEQUENCE) return null;

  // From the tag byte, not the contents: the hash must cover the whole
  // SubjectPublicKeyInfo encoding to match what every other tool means
  // by a public-key hash.
  return der.subarray(spki.headerStart, spki.end);
}

export type CertAlgorithmOids = {
  /** SubjectPublicKeyInfo.algorithm.algorithm */
  publicKeyOid: string | null;
  /** SubjectPublicKeyInfo.algorithm.parameters, when it is an OID
   *  (this is where the named curve lives for EC keys). */
  publicKeyParamOid: string | null;
  /** tbsCertificate.signature.algorithm */
  signatureOid: string | null;
};

/**
 * Pull the algorithm OIDs out of a DER-encoded certificate.
 *
 * Path walked (RFC 5280):
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
 *   TBSCertificate ::= SEQUENCE {
 *     [0] version OPTIONAL, serialNumber, signature, issuer,
 *     validity, subject, subjectPublicKeyInfo, ... }
 *
 * The signature OID is taken from INSIDE tbsCertificate rather than the
 * outer copy: both must match per RFC 5280, and the inner one is the one
 * actually covered by the signature.
 */
export function extractAlgorithmOids(der: Buffer): CertAlgorithmOids {
  const empty: CertAlgorithmOids = {
    publicKeyOid: null,
    publicKeyParamOid: null,
    signatureOid: null
  };

  if (!Buffer.isBuffer(der) || der.length < 8) return empty;

  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== TAG_SEQUENCE) return empty;

  const certChildren = children(der, cert);
  const tbs = certChildren[0];
  if (!tbs || tbs.tag !== TAG_SEQUENCE) return empty;

  const tbsChildren = children(der, tbs);
  // `version` is optional; when present it is the [0] EXPLICIT wrapper.
  const base = tbsChildren[0]?.tag === TAG_CONTEXT_0 ? 1 : 0;

  // After the optional version: serialNumber(0), signature(1), issuer(2),
  // validity(3), subject(4), subjectPublicKeyInfo(5).
  const signatureAlgId = tbsChildren[base + 1];
  const spki = tbsChildren[base + 5];

  const result: CertAlgorithmOids = { ...empty };

  if (signatureAlgId && signatureAlgId.tag === TAG_SEQUENCE) {
    const oidTlv = children(der, signatureAlgId)[0];
    if (oidTlv) result.signatureOid = decodeOid(der, oidTlv);
  }

  if (spki && spki.tag === TAG_SEQUENCE) {
    const algId = children(der, spki)[0];
    if (algId && algId.tag === TAG_SEQUENCE) {
      const algChildren = children(der, algId);
      if (algChildren[0]) result.publicKeyOid = decodeOid(der, algChildren[0]);
      // Parameters are optional and only interesting when they are an OID
      // (EC named curve). RSA carries NULL here; PQC algorithms carry
      // nothing at all.
      if (algChildren[1] && algChildren[1].tag === TAG_OID) {
        result.publicKeyParamOid = decodeOid(der, algChildren[1]);
      }
    }
  }

  return result;
}

const TAG_CONTEXT_3 = 0xa3; // [3] EXPLICIT — the `extensions` field
const TAG_OCTET_STRING = 0x04;
const TAG_IA5_STRING = 0x16;
const TAG_CONTEXT_6 = 0x86; // [6] IMPLICIT IA5String — GeneralName.uniformResourceIdentifier

/** X.509 extension OIDs we read. */
export const EXT_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
export const EXT_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";

// ── Certificados híbridos "catalyst" (ITU-T X.509 2019) ────────────
//
// Un certificado híbrido lleva la clave y la firma CLÁSICAS en los
// campos normales de X.509, y una SEGUNDA clave y firma post-cuánticas
// en tres extensiones no críticas. Así un verificador antiguo lo trata
// como un certificado corriente y lo acepta, mientras que uno moderno
// puede comprobar además la mitad PQC.
//
// ⚠️ POR QUÉ ESTO IMPORTA PARA NOSOTROS, medido el 2026-08-27: en toda
// la flota hay 10.277 certificados y los 10.277 salen clasificados como
// `quantum_broken`. Si alguno fuera híbrido, hoy lo diríamos igual —
// leemos su mitad clásica y la PQC es invisible. Sería un FALSO
// NEGATIVO en la herramienta que vendemos como inventario PQC, y el
// peor momento para descubrirlo es cuando un cliente ya tenga híbridos
// y le digamos que no tiene ninguno.
//
// Sólo se leen los OID: qué algoritmo declara la mitad alternativa.
// NO se verifica la firma alternativa, y eso es deliberado — ver el
// comentario de extractHybridOids.
export const EXT_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72";
export const EXT_ALT_SIGNATURE_ALGORITHM = "2.5.29.73";
export const EXT_ALT_SIGNATURE_VALUE = "2.5.29.74";
/** AccessDescription.accessMethod for an OCSP responder. */
const ACCESS_METHOD_OCSP = "1.3.6.1.5.5.7.48.1";

const MAX_URLS = 8;
const MAX_URL_LEN = 512;

/**
 * The contents of one extension's extnValue (the bytes INSIDE the
 * OCTET STRING wrapper), or null when the certificate has no such
 * extension.
 *
 * TBSCertificate lays out `extensions` as a [3] EXPLICIT wrapper after
 * the optional unique-id fields, so we scan the tail rather than index
 * a fixed position.
 */
export function extractExtension(der: Buffer, oid: string): Tlv | null {
  if (!Buffer.isBuffer(der) || der.length < 8) return null;

  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== TAG_SEQUENCE) return null;
  const tbs = children(der, cert)[0];
  if (!tbs || tbs.tag !== TAG_SEQUENCE) return null;

  const extensionsWrapper = children(der, tbs).find((c) => c.tag === TAG_CONTEXT_3);
  if (!extensionsWrapper) return null;

  const extensionsSeq = children(der, extensionsWrapper)[0];
  if (!extensionsSeq || extensionsSeq.tag !== TAG_SEQUENCE) return null;

  for (const ext of children(der, extensionsSeq)) {
    if (ext.tag !== TAG_SEQUENCE) continue;
    const parts = children(der, ext);
    if (decodeOid(der, parts[0]) !== oid) continue;
    // `critical` is optional, so extnValue is the last element.
    const value = parts[parts.length - 1];
    return value && value.tag === TAG_OCTET_STRING ? value : null;
  }

  return null;
}

export type HybridOids = {
  /** altSignatureAlgorithm.algorithm — el algoritmo de la firma alternativa. */
  altSignatureOid: string | null;
  /** subjectAltPublicKeyInfo.algorithm.algorithm — la clave alternativa. */
  altPublicKeyOid: string | null;
  /** Hay firma alternativa presente (aunque su OID no se pueda decodificar). */
  hasAltSignatureValue: boolean;
};

/**
 * Los OID de la mitad alternativa de un certificado híbrido catalyst.
 *
 * ⚠️ ESTO NO VERIFICA NADA, y es a propósito. Se lee QUÉ algoritmo
 * declara la mitad PQC, no si su firma es válida.
 *
 * La razón está documentada en la literatura y es incómoda: las pilas de
 * validación desplegadas tratan estas extensiones como no críticas y las
 * ignoran, así que un certificado catalyst con la firma alternativa
 * FALSIFICADA se acepta igual. BouncyCastle mismo la acepta en su ruta
 * por defecto y sólo la rechaza mediante una llamada opt-in aparte.
 *
 * Un inventario que dijera "híbrido, luego protegido" estaría afirmando
 * algo que la infraestructura del cliente no comprueba. Lo que sí es
 * cierto —y lo que reportamos— es que el certificado DECLARA una mitad
 * post-cuántica. El juicio sobre si eso protege es del servidor, con el
 * catálogo de familias, y ahí se puede matizar sin desplegar la flota.
 */
export function extractHybridOids(der: Buffer): HybridOids {
  const empty: HybridOids = {
    altSignatureOid: null,
    altPublicKeyOid: null,
    hasAltSignatureValue: false
  };
  if (!Buffer.isBuffer(der) || der.length < 8) return empty;

  const result: HybridOids = { ...empty };

  // altSignatureAlgorithm ::= AlgorithmIdentifier — el extnValue ES la
  // SEQUENCE, sin envoltorio adicional.
  const altSigAlg = extractExtension(der, EXT_ALT_SIGNATURE_ALGORITHM);
  if (altSigAlg) {
    const seq = children(der, altSigAlg)[0];
    if (seq && seq.tag === TAG_SEQUENCE) {
      const oidTlv = children(der, seq)[0];
      if (oidTlv) result.altSignatureOid = decodeOid(der, oidTlv);
    }
  }

  // subjectAltPublicKeyInfo ::= SubjectPublicKeyInfo — misma forma que el
  // SPKI normal: SEQUENCE { AlgorithmIdentifier, BIT STRING }.
  const altSpki = extractExtension(der, EXT_SUBJECT_ALT_PUBLIC_KEY_INFO);
  if (altSpki) {
    const seq = children(der, altSpki)[0];
    if (seq && seq.tag === TAG_SEQUENCE) {
      const algId = children(der, seq)[0];
      if (algId && algId.tag === TAG_SEQUENCE) {
        const oidTlv = children(der, algId)[0];
        if (oidTlv) result.altPublicKeyOid = decodeOid(der, oidTlv);
      }
    }
  }

  // La presencia del VALOR se reporta aparte de su OID: un certificado
  // con altSignatureValue pero sin altSignatureAlgorithm legible sigue
  // siendo híbrido, y decir "no hay nada" ahí sería la misma clase de
  // falso negativo que este módulo viene a cerrar.
  result.hasAltSignatureValue = extractExtension(der, EXT_ALT_SIGNATURE_VALUE) !== null;

  return result;
}

/** Every IA5String / [6] URI nested anywhere under `parent`. */
function collectUris(der: Buffer, parent: Tlv, out: string[], depth = 0): void {
  if (depth > 6 || out.length >= MAX_URLS) return;

  for (const child of children(der, parent)) {
    if (out.length >= MAX_URLS) return;
    if (child.tag === TAG_IA5_STRING || child.tag === TAG_CONTEXT_6) {
      const value = der.subarray(child.start, child.end).toString("latin1").trim();
      if (value.length > 0 && value.length <= MAX_URL_LEN && /^https?:\/\//i.test(value)) {
        if (!out.includes(value)) out.push(value);
      }
      continue;
    }
    // Constructed nodes only; a primitive we do not recognise is skipped.
    if ((child.tag & 0x20) !== 0) collectUris(der, child, out, depth + 1);
  }
}

/**
 * CRL distribution point URLs. These plus the serial number are all the
 * control plane needs to answer "was this revoked?" — no certificate
 * bytes have to leave the endpoint.
 */
export function extractCrlUrls(der: Buffer): string[] {
  const ext = extractExtension(der, EXT_CRL_DISTRIBUTION_POINTS);
  if (!ext) return [];
  // extnValue wraps a DER structure; step into the OCTET STRING first.
  const inner = readTlv(der, ext.start);
  if (!inner) return [];
  const urls: string[] = [];
  collectUris(der, inner, urls);
  return urls;
}

/**
 * OCSP responder URLs from Authority Information Access. Collected for
 * completeness and display; the control plane cannot actually query them
 * without the ISSUER's certificate (an OCSP request identifies a
 * certificate by hashes of the issuer's name and public key, neither of
 * which is derivable from the metadata we keep). See ADR-0004 (c).
 */
export function extractOcspUrls(der: Buffer): string[] {
  const ext = extractExtension(der, EXT_AUTHORITY_INFO_ACCESS);
  if (!ext) return [];
  const inner = readTlv(der, ext.start);
  if (!inner || inner.tag !== TAG_SEQUENCE) return [];

  const urls: string[] = [];
  for (const accessDescription of children(der, inner)) {
    if (accessDescription.tag !== TAG_SEQUENCE) continue;
    const parts = children(der, accessDescription);
    if (decodeOid(der, parts[0]) !== ACCESS_METHOD_OCSP) continue;
    collectUris(der, accessDescription, urls);
  }
  return urls;
}
