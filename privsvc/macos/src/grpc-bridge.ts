import crypto from "crypto";
import path from "path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { loadInstalledIdentity } from "./crypto-store";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const PROTO_PATH = path.resolve(__dirname, "../proto/controlplane.proto");

type BridgeState = {
  client?: any;
  call?: grpc.ClientDuplexStream<any, any>;
  push?: PushSink;
  connected: boolean;
  connecting: boolean;
  tenantId?: string;
  deviceId?: string;
  target?: string;
  chunks: Map<string, { totalChunks: number; chunks: string[] }>;
};

const state: BridgeState = {
  connected: false,
  connecting: false,
  chunks: new Map()
};

function loadControlPlaneClient() {
  const def = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true
  });
  const pkg = grpc.loadPackageDefinition(def) as any;
  return pkg.tracenium.control.ControlPlane;
}

function normalizeTarget(value: string) {
  const target = String(value || "").trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  if (!target) throw new Error("target_required");
  return target;
}

function push(method: string, params?: Record<string, any>) {
  try {
    state.push?.({
      v: 1,
      method,
      params: params || {},
      meta: {
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        connectionId: state.target
      }
    });
  } catch (err: any) {
    logger.warn("push_failed", { method, error: err?.message || String(err) });
  }
}

function decodeBytes(value: any): string {
  if (!value) return "";
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf8");
  return String(value);
}

function handleControlMessage(msg: any) {
  if (msg.ack) {
    push("grpc.ack", {
      eventId: String(msg.ack.eventId || ""),
      status: Number(msg.ack.status ?? 0),
      message: String(msg.ack.message || ""),
      receivedAtUtc: msg.ack.receivedAtUtc || new Date().toISOString(),
      serverTimeUtc: msg.ack.serverTimeUtc || undefined
    });
    return;
  }

  if (msg.runJob) {
    push("grpc.control.runJob", {
      jobId: String(msg.runJob.jobId || ""),
      jobType: String(msg.runJob.jobType || ""),
      payloadJson: decodeBytes(msg.runJob.payloadJson),
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.rotateCert) {
    push("grpc.control.rotateCert", {
      reason: msg.rotateCert.reason || "server_request",
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.policyUpdate) {
    push("grpc.control.policyUpdate", {
      eventId: msg.policyUpdate.eventId || "",
      policyVersion: msg.policyUpdate.policyVersion || "",
      policyJson: decodeBytes(msg.policyUpdate.policyJson),
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.disconnect) {
    push("grpc.control.disconnect", {
      reason: msg.disconnect.reason || "server_request",
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.agentUpdate) {
    push("grpc.control.agentUpdate", {
      jobId: msg.agentUpdate.jobId || "",
      version: msg.agentUpdate.version || "",
      receivedAtUtc: new Date().toISOString()
    });
  }
}

function write(msg: any): Promise<void> {
  return new Promise((resolve, reject) => {
    const call = state.call;
    if (!call || state.connected !== true) {
      reject(new Error("grpc_not_connected"));
      return;
    }

    call.write(msg, (err: Error | null | undefined) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function startConnection(params: Record<string, any>, pushSink: PushSink) {
  if (state.connected || state.connecting) return;

  state.connecting = true;
  state.push = pushSink;
  state.tenantId = String(params.tenantId || "");
  state.deviceId = String(params.deviceId || "");
  state.target = normalizeTarget(params.target);

  if (!state.tenantId || !state.deviceId) {
    throw new Error("tenantId_deviceId_required");
  }

  try {
    const identity = loadInstalledIdentity();
    const creds = grpc.credentials.createSsl(
      identity.caBundle,
      identity.clientKey,
      identity.clientCert
    );

    const ControlPlane = loadControlPlaneClient();
    state.client = new ControlPlane(state.target, creds);
    const call = state.client.Connect() as grpc.ClientDuplexStream<any, any>;
    state.call = call;

    call.on("data", handleControlMessage);
    call.on("error", (err: any) => {
      state.connected = false;
      state.connecting = false;
      logger.error("grpc_stream_error", { error: err?.message || String(err) });
      push("grpc.control.streamClosed", {
        reason: err?.message || "grpc_stream_error",
        atUtc: new Date().toISOString()
      });
      push("grpc.disconnected", { manual: false });
    });
    call.on("end", () => {
      state.connected = false;
      state.connecting = false;
      push("grpc.disconnected", { manual: false });
    });

    const eventId = crypto.randomUUID().replace(/-/g, "");
    call.write({
      traceId: eventId,
      hello: {
        eventId,
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        agentVersion: String(params.agentVersion || ""),
        protocolVersion: "1",
        policyVersion: String(params.policyVersion || ""),
        capabilities: ["amp"]
      }
    });

    state.connected = true;
    push("grpc.connected", {
      ready: true,
      target: state.target,
      atUtc: new Date().toISOString()
    });
  } finally {
    state.connecting = false;
  }
}

export async function handleGrpcConnect(req: PrivSvcRequest, pushSink: PushSink): Promise<PrivSvcResponse> {
  try {
    await startConnection(req.params || {}, pushSink);
    return success(req.id, {
      connected: true,
      ready: true,
      target: state.target
    });
  } catch (err: any) {
    return fail(req.id, "grpc_connect_failed", err?.message || String(err));
  }
}

export async function handleFactsSend(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const eventId = String(req.params?.eventId || "");
    const payloadJson = String(req.params?.payloadJson || "{}");
    if (!eventId) return fail(req.id, "bad_request", "eventId required");

    await write({
      traceId: eventId,
      facts: {
        eventId,
        deviceId: state.deviceId || "",
        payloadJson: Buffer.from(payloadJson, "utf8")
      }
    });

    return success(req.id, { accepted: true, eventId });
  } catch (err: any) {
    return fail(req.id, "facts_send_failed", err?.message || String(err));
  }
}

export async function handleFactsChunk(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const eventId = String(params.eventId || "");
  const chunkIndex = Number(params.chunkIndex);
  const totalChunks = Number(params.totalChunks);
  const payloadChunk = String(params.payloadChunk || "");

  if (!eventId || !Number.isInteger(chunkIndex) || !Number.isInteger(totalChunks) || totalChunks <= 0) {
    return fail(req.id, "bad_request", "invalid chunk parameters");
  }

  const current = state.chunks.get(eventId) || {
    totalChunks,
    chunks: new Array<string>(totalChunks).fill("")
  };

  current.chunks[chunkIndex] = payloadChunk;
  state.chunks.set(eventId, current);

  if (current.chunks.every((chunk) => chunk.length > 0)) {
    state.chunks.delete(eventId);
    return handleFactsSend({
      ...req,
      params: {
        eventId,
        payloadJson: current.chunks.join("")
      }
    });
  }

  return success(req.id, {
    accepted: true,
    eventId,
    chunkIndex,
    totalChunks
  });
}

export async function handleAck(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const eventId = String(req.params?.eventId || "");
    if (!eventId) return fail(req.id, "bad_request", "eventId required");

    await write({
      traceId: eventId,
      ack: {
        eventId,
        status: Number(req.params?.status ?? 0),
        message: String(req.params?.message || ""),
        receivedAtUtc: req.params?.receivedAtUtc || new Date().toISOString()
      }
    });

    return success(req.id, { accepted: true, eventId });
  } catch (err: any) {
    return fail(req.id, "ack_send_failed", err?.message || String(err));
  }
}

export async function handleClose(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    state.connected = false;
    state.connecting = false;
    state.call?.end();
    state.call = undefined;
    state.client = undefined;
    push("grpc.disconnected", { manual: true });
    return success(req.id, { closed: true });
  } catch (err: any) {
    return fail(req.id, "grpc_close_failed", err?.message || String(err));
  }
}
