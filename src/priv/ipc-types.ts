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
  | "sdp.install";

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
