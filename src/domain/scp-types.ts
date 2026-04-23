// src/domain/scp-types.ts
//
// SCP wire schema 2.0.
//
// Schema 2.0 flips the old contract: the agent no longer decides pass/fail
// and no longer ships a `checks[]` array or an `overall` block. It only
// reports *evidence* collected from the platform (firewall, defender,
// bitlocker, smb, shares, cipher suites, TLS protocols, patches, …) and
// the backend evaluator runs the catalog rules against that evidence.
//
// Everything that used to be "agent opinion" (score, per-check status,
// remediation prose) is now computed server-side against the Control-DB
// catalog. That means:
//   - The agent can add new evidence blocks without a server change.
//   - The catalog can change pass/fail logic without a fleet rollout.
//   - Findings keep a stable framework mapping snapshot regardless of
//     which agent version produced the evidence.
//
// Backward compatibility: the backend rejects schema < 2.0 outright
// (see certusws-tracenium/modules/grpc/controlplane.ts → validateScpPayload).

// -------- Wire-format types --------------------------------------------

export type ScpCollector = {
  plugin: "scp";
  /** Agent version that collected the evidence. Gates version-restricted
   *  catalog entries (e.g. macOS rules guarded by collector_version_min). */
  version: string;
};

/** Derived crypto evidence. The raw cipher/protocol arrays from the
 *  platform are expensive to evaluate in the server-side rule DSL, so
 *  the agent precomputes the flags the catalog references directly
 *  (`crypto.tls10Enabled`, `crypto.weakCiphers`, …). The raw arrays are
 *  kept under `ciphers` / `protocols` for diagnostics. */
export type ScpCryptoEvidence = {
  tls10Enabled?: boolean;
  tls11Enabled?: boolean;
  tls12Enabled?: boolean;
  tls13Enabled?: boolean;
  weakCiphers?: string[];
  ciphers?: unknown[];
  protocols?: unknown[];
};

export type ScpPatchesEvidence = {
  items?: unknown[];
  count?: number;
  lastScanUtc?: string;
};

/** Diagnostic block surfaced when the collector itself failed to run
 *  (e.g. PrivSvc unavailable). Carried as evidence so the UI can
 *  visualize "collector down" without inventing synthetic findings. */
export type ScpCollectorError = {
  message: string;
  phase?: string;
};

export type ScpNamespace = {
  schemaVersion: "2.0";
  collector: ScpCollector;

  /** Internal-only: scheduler flag used to decide whether to push the
   *  snapshot. The device-facts builder strips it before send. Kept on
   *  the type so the scheduler's existing hash/diff path compiles. */
  hasChanges: boolean;

  // Windows + cross-platform evidence blocks
  firewall?: unknown;
  defender?: unknown;
  bitlocker?: unknown;
  smb?: unknown;
  shares?: unknown;
  antivirus?: unknown;
  domain?: unknown;
  crypto?: ScpCryptoEvidence;
  patches?: ScpPatchesEvidence;

  // macOS-specific evidence blocks
  filevault?: unknown;
  gatekeeper?: unknown;
  sip?: unknown;
  screenLock?: unknown;
  services?: unknown;
  softwareUpdate?: unknown;
  accounts?: unknown;

  collectorError?: ScpCollectorError;
};
