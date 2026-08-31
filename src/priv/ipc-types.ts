// src/priv/ipc-types.ts

/**
 * Methods that Node can invoke on PrivSvc (request/response IPC).
 *
 * NOTE: Push notifications from PrivSvc back to Node (acks/control events)
 * use the `PrivSvcPushMethod` union below.
 */
export type PrivSvcMethod =
  | "ping"
  | "identity"
  | "software.inventory"
  | "security.compliance"
  | "patch.scan"
  | "patch.install"
  // Patch Management v2 — non-patch security remediation (TLS,
  // ciphers, SMB, firewall, etc) routed through the same PMP
  // plugin. Two methods:
  //   * `pmp.read_check_state` — read-only probe of the local
  //                              system state for a given checkId.
  //                              Used pre-install (idempotency
  //                              compute), pre-apply (state_before),
  //                              and post-apply (verification +
  //                              state_after). Returns
  //                              { state, isCompliant, supported }.
  //   * `pmp.remediate`        — apply the registry / plist /
  //                              powershell change. Privsvc dispatches
  //                              by checkId to a hardcoded whitelist
  //                              — NEVER executes catalog-supplied
  //                              scripts. Returns
  //                              { exitCode, stderrExcerpt,
  //                                durationMs, requiresReboot,
  //                                changesApplied[] }.
  | "pmp.read_check_state"
  | "pmp.remediate"
  // CDP — Crypto Discovery Plugin. Read-only enumeration of the
  // LocalMachine certificate stores via C# X509Store. Returns
  // { certificates: [{ store, rawDerBase64, hasPrivateKey }] }.
  // NEVER exports private key material — hasPrivateKey is the store
  // attribute only. Same read-only class as security.compliance.
  | "cdp.certs.read"
  // Faltaba en la union aunque el cliente ya le daba presupuesto: el
  // tipo se quedo atras cuando se anadio el metodo.
  | "cdp.certs.readUser"
  // ADR-0011 decision 10 — quitar la confianza a un ancla. DESCONFIAR,
  // no borrar: en Windows se anade a `Disallowed`, en macOS es un trust
  // setting de denegacion. Ver CdpAnchorDistrust.cs.
  | "cdp.anchor.distrust"
  | "crypto.csr.generate" // enrollment CSR generation
  | "crypto.cert.install" // install client cert (bind to existing key)
  // gRPC bridge (PrivSvc owns mTLS private key + channel)
  | "grpc.connect"
  | "grpc.facts.send"
  | "grpc.facts.chunk"
  | "grpc.heartbeat"
  | "grpc.close"
  // Software Delivery Plugin (SDP) — Phase 1. The plugin lives in
  // src/plugins/sdp/ and orchestrates these three primitives:
  //   * `sdp.detect`   — evaluate a DetectionRule (registry /
  //                      bundle_version / pkg_receipt / file /
  //                      command). Returns { matched, snapshot }.
  //                      Used both pre-install (idempotency) and
  //                      post-install (verification of silent
  //                      installer success).
  //   * `sdp.download` — fetch the package binary into a privileged
  //                      staging dir and verify sha256. Returns
  //                      { stagingPath, sha256 }.
  //   * `sdp.install`  — exec the installer (msiexec / installer / etc)
  //                      with privsvc privileges. Returns
  //                      { exitCode, stderrExcerpt, durationMs }.
  | "sdp.detect"
  | "sdp.download"
  | "sdp.install"
  //   * `sdp.verifySignature` — full Authenticode verification of a
  //     downloaded package via the OS (WinVerifyTrust): digest + chain
  //     to the Windows trust store + revocation. Returns { trusted,
  //     reason }. Gate before install when the package requires signing.
  | "sdp.verifySignature"
  // Infrastructure Gateway — vCenter credential custody. PrivSvc runs as
  // SYSTEM/root and already owns the mTLS private key, so it is the only
  // component that can open a credential envelope sealed against this
  // device's certificate, and the only one that should touch the OS
  // credential store. The control plane never sees the plaintext: the
  // admin's BROWSER seals it against the gateway's public key and the
  // backend only relays ciphertext it has no key for. See ADR-0001 (C).
  //
  //   * `credential.provision` — params { ref, envelope }. Opens the sealed
  //     envelope with the enrollment private key and writes the credential to
  //     the OS store (Windows Credential Manager / macOS Keychain / libsecret,
  //     falling back to an AES-256-GCM file at mode 0600). Returns
  //     { ok, certFingerprint } or fails with code
  //     `stale_envelope` when it was sealed against a certificate that has
  //     since rotated — deliberately distinct from a decrypt failure so the
  //     UI can tell the admin to re-enter rather than "invalid credential".
  //   * `credential.retrieve` — params { ref }. Returns { username, password }
  //     for the duration of ONE vCenter operation. Callers must not cache it.
  //   * `credential.remove`   — params { ref }. Used when a gateway is
  //     de-registered so the secret does not outlive its purpose.
  | "credential.provision"
  | "credential.retrieve"
  | "credential.remove";

export type GrpcAckParams = {
  eventId: string;
  status: number;
  message?: string;
  receivedAtUtc?: string;
};

/**
 * Methods that PrivSvc can PUSH to Node (unsolicited events).
 * Node must subscribe to these via a push sink / session.
 */
export type PrivSvcPushMethod =
  | "grpc.connected"
  | "grpc.ack"
  | "grpc.control.rotateCert"
  | "grpc.control.runJob"
  | "grpc.control.policyUpdate"
  | "grpc.control.disconnect"
  | "grpc.control.agentUpdate"
  | "grpc.control.streamClosed"
  | "grpc.disconnected"
  | "log";

export type PrivSvcRequest = {
  v: 1;
  /**
   * Correlation id (client-generated). If omitted, the IPC client may generate one.
   */
  id: string;
  method: PrivSvcMethod;
  params?: Record<string, any>;
  meta?: {
    tenantId: string;
    deviceId: string;
    traceId?: string;
  };
};

export type PrivSvcResponse =
  | { v: 1; id: string; ok: true; result: any; error: null }
  | { v: 1; id: string; ok: false; result: null; error: { code: string; message: string } };

/**
 * Push envelope format coming from PrivSvc.
 *
 * Examples:
 *  - { v:1, id:"...", method:"grpc.ack", params:{eventId,status,message,receivedAtUtc}, meta:{...} }
 */
export type PrivSvcPush =
  | {
      v: 1;
      id?: string;
      method: "grpc.ack";
      params: GrpcAckParams;
      meta?: {
        tenantId?: string;
        deviceId?: string;
        traceId?: string;
        connectionId?: string;
      };
    }
  | {
      v: 1;
      id?: string;
      method: Exclude<PrivSvcPushMethod, "grpc.ack">;
      params?: Record<string, any>;
      meta?: {
        tenantId?: string;
        deviceId?: string;
        traceId?: string;
        connectionId?: string;
      };
    };
