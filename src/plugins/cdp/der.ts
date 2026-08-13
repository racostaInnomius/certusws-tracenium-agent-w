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
