// src/plugins/cdp/algorithm-oids.ts
//
// OID → human-readable algorithm name.
//
// Deliberately NOT a classifier. The agent reports the raw OID and a
// display name; deciding whether an algorithm is quantum-broken,
// PQ-safe or hybrid happens SERVER-SIDE (see ADR-0004), for the same
// reason hygiene flags do: the judgement changes far more often than the
// fleet gets upgraded, and re-classifying must never require an agent
// rollout.
//
// An OID missing from this table is NOT an error. The raw OID still
// travels, so the control plane can name and classify it later without
// touching a single endpoint. That is the whole point of reading the OID
// instead of trusting Node's algorithm model.
//
// ⚠️ The post-quantum entries are from the NIST CSOR arc
// (2.16.840.1.101.3.4). Verify against the CSOR registry before using
// them in customer-facing material — FIPS 203/204/205 are final
// (Aug 2024) but the OID assignments for some parameter sets were still
// settling, and FN-DSA (FIPS 206) was not final at the time of writing.

export const ALGORITHM_NAMES: Record<string, string> = {
  // ── Public key algorithms — classical (broken by Shor) ───────────
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.10040.4.1": "DSA",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",

  // ── Public key algorithms — post-quantum signatures ──────────────
  "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
  "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
  "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
  "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
  "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
  "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
  "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
  "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
  "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
  "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
  "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
  "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
  "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
  "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
  "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",

  // ── Public key algorithms — post-quantum KEM (FIPS 203) ──────────
  // Rare in certificates today (KEM certs are still a draft concept),
  // but present so we can name one the day it shows up.
  "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
  "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
  "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",

  // ── Stateful hash-based signatures (RFC 8554 / RFC 8391) ─────────
  // PQ-safe, but one-time-key stateful — used for firmware/code signing.
  "1.2.840.113549.1.9.16.3.17": "HSS-LMS",
  "1.3.6.1.5.5.7.6.34": "XMSS",
  "1.3.6.1.5.5.7.6.35": "XMSS-MT",

  // ── Signature algorithms — weak digests ──────────────────────────
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.10040.4.3": "dsa-with-sha1",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.3.14.3.2.29": "sha1WithRSA",
  "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
  "1.2.840.113549.1.1.3": "md4WithRSAEncryption",

  // ── Signature algorithms — current ───────────────────────────────
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
  "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "2.16.840.1.101.3.4.3.13": "sha3-256WithRSAEncryption",
  "2.16.840.1.101.3.4.3.14": "sha3-384WithRSAEncryption",
  "2.16.840.1.101.3.4.3.15": "sha3-512WithRSAEncryption",
};

/** Named elliptic curves (SubjectPublicKeyInfo algorithm parameters). */
export const CURVE_NAMES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.3.132.0.10": "secp256k1",
  "1.2.840.10045.3.1.1": "P-192",
  "1.3.132.0.33": "P-224",
};

/**
 * Display name for an OID. Unknown OIDs come back as `oid:<dotted>` so
 * they stay visible and searchable in the UI instead of vanishing into a
 * null — the failure mode this whole module exists to fix.
 */
export function algorithmName(oid: string | null | undefined): string | undefined {
  if (!oid) return undefined;
  return ALGORITHM_NAMES[oid] ?? `oid:${oid}`;
}

export function curveName(oid: string | null | undefined): string | undefined {
  if (!oid) return undefined;
  return CURVE_NAMES[oid] ?? `oid:${oid}`;
}
