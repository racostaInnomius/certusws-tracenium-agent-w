// src/domain/cdp-types.ts
//
// CDP (Crypto Discovery Plugin) wire schema 1.0.
//
// The agent reports FACTS about X.509 certificates found in the OS
// stores — metadata only, never key material. All judgment (expiry
// status, weak-crypto flags, nonstandard-root detection) lives
// server-side so thresholds can change without a fleet rollout.
// See certusws-tracenium/docs/CDP_CRYPTO_DISCOVERY_DESIGN.md.

export type CdpCollector = {
  plugin: "cdp";
  version: string;
};

export type CdpStoreScope = "machine" | "user" | "system-roots";

export type CdpStoreInfo = {
  /** Stable store identifier, e.g. "lm/my", "keychain/system", "fs/etc-ssl-certs". */
  id: string;
  name: string;
  scope: CdpStoreScope;
};

export type CdpCertItem = {
  /** Stable per-device key: sha256(fingerprint256 + ":" + storeId). */
  id: string;
  fingerprint256: string;
  fingerprintSha1?: string;
  serial?: string;

  subjectDN?: string;
  subjectCN?: string;
  issuerDN?: string;
  issuerCN?: string;

  /** ISO-8601 UTC. */
  notBefore?: string;
  notAfter?: string;

  keyAlgorithm?: string;
  keySizeBits?: number;
  curve?: string;
  signatureAlgorithm?: string;
  /** Raw algorithm OIDs straight from the DER. Reported so the control
   *  plane can name and classify algorithms this agent predates —
   *  post-quantum in particular. See ADR-0004. */
  publicKeyOid?: string;
  signatureOid?: string;
  /** sha256 of the DER SubjectPublicKeyInfo (same value as openssl's
   *  pin-sha256, in hex). Identifies the KEY, not the certificate —
   *  the control plane uses it to spot copied private keys. */
  publicKeyHash?: string;
  /** CRL distribution point URLs from the certificate (ADR-0004 c). */
  crlUrls?: string[];
  /** OCSP responder URLs from Authority Information Access. */
  ocspUrls?: string[];
  /** Only for `source: "listener"` — what the live handshake revealed
   *  about the chain the service serves (ADR-0004 b). */
  tls?: {
    port: number;
    /** Certificates the server actually sent. 1 usually means it
     *  omitted the intermediates. */
    chainDepth: number;
    /** Does the device's own trust store accept the chain? */
    chainAuthorized: boolean;
    /** OpenSSL verify code when it does not. */
    chainError?: string;
    /** Advisory only: a proxy legitimately serves other names. */
    coversDeviceHostname?: boolean;
    /** Which process serves this certificate (ADR-0004 a). The join key
     *  the control plane uses to attribute a certificate to an owning
     *  application in the software inventory. */
    process?: { pid: number; name?: string; path?: string };
  };

  isCA?: boolean;
  selfSigned?: boolean;
  /** Metadata only — the key itself is NEVER read or transmitted. */
  hasPrivateKey?: boolean;

  keyUsage?: string[];
  extendedKeyUsage?: string[];
  san?: string[];

  store: CdpStoreInfo;
  /** Where the certificate was found:
   *   "store"      — OS certificate store
   *   "java-store" — JKS/PKCS12 keystore (JVM cacerts or app keystore)
   *   "listener"   — captured from a live local TLS handshake, i.e. what
   *                  the service actually serves (may differ from any
   *                  store). */
  source: "store" | "java-store" | "listener";
};

export type CdpDelta = {
  added: CdpCertItem[];
  removed: Array<{ id: string }>;
  updated: CdpCertItem[];
};

export type CdpCollectorError = {
  message: string;
  phase?: string;
};

export type CdpNamespace = {
  schemaVersion: "1.0";
  collector: CdpCollector;
  collectedAt: string;

  /** Internal-only scheduler flag; stripped semantics match SCP/PMP. */
  hasChanges: boolean;

  /** True when the item cap was hit and low-priority certs were dropped. */
  truncated: boolean;

  stores: CdpStoreInfo[];

  certificates: {
    count: number;
    /** Full baseline — first send or forced resync only. */
    items?: CdpCertItem[];
    /** Incremental changes vs the local SQLite baseline. */
    delta?: CdpDelta;
  };

  collectorError?: CdpCollectorError;
};
