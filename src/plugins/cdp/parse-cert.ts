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

function keyInfo(cert: crypto.X509Certificate): {
  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
} {
  try {
    const key = cert.publicKey;
    const type = key.asymmetricKeyType;
    const details = key.asymmetricKeyDetails;

    if (type === "rsa" || type === "rsa-pss") {
      return { keyAlgorithm: "RSA", keySizeBits: details?.modulusLength };
    }
    if (type === "ec") {
      return {
        keyAlgorithm: "EC",
        // namedCurve is e.g. "prime256v1" — report the bit strength too.
        keySizeBits: details?.namedCurve?.match(/(\d{3})/)
          ? Number(details.namedCurve.match(/(\d{3})/)![1])
          : undefined,
        curve: details?.namedCurve
      };
    }
    if (type === "ed25519" || type === "ed448" || type === "x25519" || type === "x448") {
      return { keyAlgorithm: type.toUpperCase() };
    }
    return type ? { keyAlgorithm: type.toUpperCase() } : {};
  } catch {
    return {};
  }
}

/** Signature algorithm is not exposed by X509Certificate directly on all
 *  Node versions; fall back to sniffing the textual dump. */
function signatureAlgorithm(cert: crypto.X509Certificate): string | undefined {
  const anyCert = cert as unknown as { sigAlgName?: string; toString(): string };
  if (typeof anyCert.sigAlgName === "string" && anyCert.sigAlgName) {
    return anyCert.sigAlgName;
  }
  const match = cert.toString().match(/Signature Algorithm:\s*([^\s\n]+)/);
  return match ? match[1] : undefined;
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

    ...keyInfo(cert),
    signatureAlgorithm: signatureAlgorithm(cert),

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
