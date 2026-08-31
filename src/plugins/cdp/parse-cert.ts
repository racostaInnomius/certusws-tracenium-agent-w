// src/plugins/cdp/parse-cert.ts
//
// Shared X.509 → CdpCertItem parsing for every CDP provider. Uses
// Node's native crypto.X509Certificate (same primitive the mTLS
// renewal path relies on in src/bootstrap/cert-renewal.ts) so the
// plugin adds zero dependencies.
//
// Providers hand us PEM or DER plus the store context; everything
// extracted here is public certificate metadata. Private key material
// is never touched — `hasPrivateKey` arrives as a flag from the
// provider (Windows store attribute / macOS identity list) and is
// forwarded verbatim.

import crypto from "crypto";
import {
  extractAlgorithmOids,
  extractHybridOids,
  extractSpkiDer,
  extractCrlUrls,
  extractOcspUrls
} from "./der";
import { algorithmName, curveName } from "./algorithm-oids";
import type { CdpCertItem, CdpStoreInfo } from "../../domain/cdp-types";

/** Extract CN from an OpenSSL-style DN block ("subject=\nCN=Foo\nO=Bar"). */
function extractCN(dn: string | undefined): string | undefined {
  if (!dn) return undefined;
  const match = dn.match(/(?:^|\n|, ?)CN=([^\n,]+)/);
  return match ? match[1].trim() : undefined;
}

function normalizeDn(dn: string | undefined): string | undefined {
  if (!dn) return undefined;
  // X509Certificate renders DNs newline-separated; flatten for the wire.
  return dn.split("\n").map((part) => part.trim()).filter(Boolean).join(", ");
}

function parseSan(san: string | undefined): string[] | undefined {
  if (!san) return undefined;
  const entries = san
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  return entries.length ? entries : undefined;
}

function toIsoUtc(dateStr: string | undefined): string | undefined {
  if (!dateStr) return undefined;
  const parsed = new Date(dateStr);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function keyInfo(
  cert: crypto.X509Certificate,
  oids: { publicKeyOid: string | null; publicKeyParamOid: string | null }
): {
  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
} {
  // The OID is authoritative: it names algorithms Node cannot model at
  // all (ML-DSA, SLH-DSA), which would otherwise report as no algorithm.
  // Node still gives us the key SIZE, which the OID does not carry for
  // RSA, so the two are combined rather than one replacing the other.
  const fromOid = algorithmName(oids.publicKeyOid);

  try {
    const key = cert.publicKey;
    const type = key.asymmetricKeyType;
    const details = key.asymmetricKeyDetails;

    if (type === "rsa" || type === "rsa-pss") {
      return { keyAlgorithm: fromOid ?? "RSA", keySizeBits: details?.modulusLength };
    }
    if (type === "ec") {
      return {
        keyAlgorithm: fromOid ?? "EC",
        // namedCurve is e.g. "prime256v1" — report the bit strength too.
        keySizeBits: details?.namedCurve?.match(/(\d{3})/)
          ? Number(details.namedCurve.match(/(\d{3})/)![1])
          : undefined,
        curve: details?.namedCurve ?? curveName(oids.publicKeyParamOid)
      };
    }
    if (type === "ed25519" || type === "ed448" || type === "x25519" || type === "x448") {
      return { keyAlgorithm: fromOid ?? type.toUpperCase() };
    }
    return { keyAlgorithm: fromOid ?? (type ? type.toUpperCase() : undefined) };
  } catch {
    // Node refused the key entirely (an algorithm it cannot load).
    // The OID still names it — this is exactly the PQC case.
    return fromOid ? { keyAlgorithm: fromOid } : {};
  }
}

/**
 * Signature algorithm, from the DER.
 *
 * The previous implementation tried `sigAlgName` and then grepped
 * `cert.toString()` for "Signature Algorithm:". Neither works on the Node
 * versions we ship: the property is undefined and toString() returns PEM,
 * not an OpenSSL text dump. The result was silent — every certificate
 * reported no signature algorithm, so the `weak_sig` hygiene flag could
 * never fire and the compliance check that reads it passed on evidence
 * that did not exist. Measured on the pilot fleet: 2129 certificates, 0
 * with a signature algorithm recorded.
 */
function signatureAlgorithm(
  cert: crypto.X509Certificate,
  oids: { signatureOid: string | null }
): string | undefined {
  const fromOid = algorithmName(oids.signatureOid);
  if (fromOid) return fromOid;
  // Keep the old property path as a fallback in case a future Node
  // exposes it; harmless when undefined.
  const anyCert = cert as unknown as { sigAlgName?: string };
  return typeof anyCert.sigAlgName === "string" && anyCert.sigAlgName
    ? anyCert.sigAlgName
    : undefined;
}

export function certIdFor(fingerprint256: string, storeId: string): string {
  return crypto
    .createHash("sha256")
    .update(`${fingerprint256}:${storeId}`)
    .digest("hex");
}

export type ParseCertOptions = {
  store: CdpStoreInfo;
  hasPrivateKey?: boolean;
};

/**
 * Parse a single certificate (PEM string or DER buffer) into the CDP
 * wire item. Returns null on parse failure — providers count failures
 * but never abort the whole scan for one corrupt blob.
 */
export function parseCertToItem(
  input: string | Buffer,
  opts: ParseCertOptions
): CdpCertItem | null {
  let cert: crypto.X509Certificate;
  try {
    cert = new crypto.X509Certificate(input);
  } catch {
    return null;
  }

  const fingerprint256 = cert.fingerprint256.replace(/:/g, "").toLowerCase();
  const fingerprintSha1 = cert.fingerprint
    ? cert.fingerprint.replace(/:/g, "").toLowerCase()
    : undefined;

  const subjectDN = normalizeDn(cert.subject);
  const issuerDN = normalizeDn(cert.issuer);

  const keyUsage = cert.keyUsage && cert.keyUsage.length ? [...cert.keyUsage] : undefined;

  // `cert.raw` is the DER Node already parsed, so this costs no re-decode
  // of the input and works whether we were handed PEM or DER.
  const oids = extractAlgorithmOids(cert.raw);
  // Extensiones catalyst. En un certificado corriente los tres campos
  // salen vacíos y no viaja nada.
  const hybrid = extractHybridOids(cert.raw);

  // sha256 over the SubjectPublicKeyInfo — the standard identity for
  // "the same key", byte-identical to `openssl ... | pin-sha256`. Two
  // certificates sharing this share a key pair; two DEVICES sharing it
  // while both claiming the private key means the key was copied.
  const spki = extractSpkiDer(cert.raw);
  const publicKeyHash = spki
    ? crypto.createHash("sha256").update(spki).digest("hex")
    : undefined;

  return {
    id: certIdFor(fingerprint256, opts.store.id),
    fingerprint256,
    ...(fingerprintSha1 ? { fingerprintSha1 } : {}),
    serial: cert.serialNumber ? cert.serialNumber.toLowerCase() : undefined,

    subjectDN,
    subjectCN: extractCN(cert.subject),
    issuerDN,
    issuerCN: extractCN(cert.issuer),

    notBefore: toIsoUtc(cert.validFrom),
    notAfter: toIsoUtc(cert.validTo),

    ...keyInfo(cert, oids),
    signatureAlgorithm: signatureAlgorithm(cert, oids),
    // Raw OIDs travel too: the control plane classifies them (see
    // ADR-0004), so an algorithm this agent has never heard of can still
    // be named and judged without a fleet rollout.
    publicKeyOid: oids.publicKeyOid ?? undefined,
    signatureOid: oids.signatureOid ?? undefined,
    altSignatureOid: hybrid.altSignatureOid ?? undefined,
    altPublicKeyOid: hybrid.altPublicKeyOid ?? undefined,
    // Sólo se manda cuando es cierto: un `false` en cada uno de los
    // 10.277 certificados de la flota engorda el payload sin decir nada,
    // y el payload ya tiene tope (por eso existe `truncated`).
    hasAltSignature: hybrid.hasAltSignatureValue || undefined,
    publicKeyHash,
    // Revocation pointers. These plus the serial number let the CONTROL
    // PLANE answer "was this revoked?" without any certificate bytes
    // leaving the endpoint, and without turning every device into a CRL
    // or OCSP client. See ADR-0004 (c).
    ...(() => {
      const crlUrls = extractCrlUrls(cert.raw);
      const ocspUrls = extractOcspUrls(cert.raw);
      return {
        ...(crlUrls.length ? { crlUrls } : {}),
        ...(ocspUrls.length ? { ocspUrls } : {})
      };
    })(),

    isCA: cert.ca,
    selfSigned: subjectDN !== undefined && subjectDN === issuerDN,
    hasPrivateKey: opts.hasPrivateKey ?? false,

    keyUsage,
    san: parseSan(cert.subjectAltName),

    store: opts.store,
    source: "store"
  } as CdpCertItem;
}

/** Split a PEM bundle (possibly containing many CERTIFICATE blocks). */
export function splitPemBundle(pem: string): string[] {
  const blocks = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
  );
  return blocks ?? [];
}
