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

  isCA?: boolean;
  selfSigned?: boolean;
  /** Metadata only — the key itself is NEVER read or transmitted. */
  hasPrivateKey?: boolean;

  keyUsage?: string[];
  extendedKeyUsage?: string[];
  san?: string[];

  store: CdpStoreInfo;
  /** "store" = OS cert store; "java-store" = JKS/PKCS12 keystore
   *  (JVM cacerts or operator-configured app keystore). */
  source: "store" | "java-store";
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
