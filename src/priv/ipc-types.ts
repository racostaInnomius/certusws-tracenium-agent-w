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
  | "security.posture"
  | "crypto.csr.generate" // enrollment CSR generation
  | "crypto.cert.install" // install client cert (bind to existing key)
  // gRPC bridge (PrivSvc owns mTLS private key + channel)
  | "grpc.connect"
  | "grpc.facts.send"
  | "grpc.facts.chunk"
  | "grpc.close";

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
  | "grpc.control.requestFacts"
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