// src/priv/ipc-types.ts

/**
 * Methods that Node can invoke on PrivSvc (request/response IPC).
 *
 * NOTE: Push notifications from PrivSvc back to Node (acks/control events)
 * use the `PrivSvcPushMethod` union below.
 */
export type PrivSvcMethod =
  | "win.ping"
  | "win.identity"
  | "win.software.inventory"
  | "win.security.posture"
  | "win.crypto.csr.generate" // enrollment CSR generation
  | "win.crypto.cert.install" // install client cert (bind to existing key)
  // gRPC bridge (PrivSvc owns mTLS private key + channel)
  | "win.grpc.connect"
  | "win.grpc.facts.send"
  | "win.grpc.close";

/**
 * Methods that PrivSvc can PUSH to Node (unsolicited events).
 * Node must subscribe to these via a push sink / session.
 */
export type PrivSvcPushMethod =
  | "win.grpc.ack"
  | "win.grpc.control.rotateCert"
  | "win.grpc.control.runJob"
  | "win.grpc.disconnected"
  | "win.log";

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
 *  - { v:1, id:"...", method:"win.grpc.ack", params:{eventId,status,message,receivedAtUtc}, meta:{...} }
 */
export type PrivSvcPush = {
  v: 1;
  id: string;
  method: PrivSvcPushMethod;
  params?: Record<string, any>;
  meta?: {
    tenantId?: string;
    deviceId?: string;
    traceId?: string;
    connectionId?: string;
  };
};