import os from "os";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { handleGenerateCsr, handleInstallCert } from "./crypto-store";
import {
  handleAck,
  handleClose,
  handleFactsChunk,
  handleFactsSend,
  handleGrpcConnect
} from "./grpc-bridge";
import { handleSecurityPosture } from "./security-posture";
import { logger } from "./logger";

function isRoot() {
  return typeof process.getuid === "function" ? process.getuid() === 0 : false;
}

function requiresRoot(method: string) {
  return method.startsWith("crypto.") || method.startsWith("grpc.");
}

export async function routeRequest(req: PrivSvcRequest, push: PushSink): Promise<PrivSvcResponse> {
  if (req.v !== 1) return fail(req.id, "bad_version", "Unsupported protocol version");
  if (!req.id) return fail("unknown", "bad_request", "Missing id");
  if (!req.method) return fail(req.id, "bad_request", "Missing method");

  logger.info("ipc_request", {
    method: req.method,
    id: req.id,
    tenantId: req.meta?.tenantId,
    deviceId: req.meta?.deviceId
  });

  if (requiresRoot(req.method) && !isRoot()) {
    return fail(req.id, "forbidden", "root required");
  }

  switch (req.method) {
    case "ping":
      return success(req.id, {
        service: "TraceniumPrivSvc",
        platform: "macos",
        version: process.env.TRACENIUM_PRIVSVC_VERSION || "1.0.0",
        utc: new Date().toISOString()
      });

    case "identity":
      return success(req.id, {
        uid: typeof process.getuid === "function" ? process.getuid() : null,
        gid: typeof process.getgid === "function" ? process.getgid() : null,
        user: os.userInfo().username,
        isRoot: isRoot(),
        utc: new Date().toISOString()
      });

    case "crypto.csr.generate":
      return handleGenerateCsr(req);

    case "crypto.cert.install":
      return handleInstallCert(req);

    case "grpc.connect":
      return handleGrpcConnect(req, push);

    case "grpc.facts.send":
      return handleFactsSend(req);

    case "grpc.facts.chunk":
      return handleFactsChunk(req);

    case "grpc.ack":
      return handleAck(req);

    case "grpc.close":
      return handleClose(req);

    case "software.inventory":
      return fail(req.id, "not_supported", "software.inventory is collected by Agent Core on macOS");

    case "security.posture":
      return handleSecurityPosture(req);

    default:
      return fail(req.id, "not_supported", `Unsupported method: ${req.method}`);
  }
}
