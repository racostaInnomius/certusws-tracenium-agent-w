import os from "os";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { handleGenerateCsr, handleInstallCert, handleRenewCert } from "./crypto-store";
import {
  handleAck,
  handleClose,
  handleFactsChunk,
  handleFactsSend,
  handleGrpcConnect,
  handleHeartbeat
} from "./grpc-bridge";
import { handlePatchInstall, handlePatchScan } from "./patch-management";
import { handlePmpReadCheckState, handlePmpRemediate } from "./pmp-remediation";
import { handleSecurityPosture } from "./security-posture";
import { handleSdpDetect, handleSdpDownload, handleSdpInstall } from "./sdp";
import { logger } from "./logger";

function isRoot() {
  return typeof process.getuid === "function" ? process.getuid() === 0 : false;
}

function requiresRoot(method: string) {
  // sdp.detect could be argued as non-root (some rules — file_exists,
  // command_exit — don't need root), but consistency wins: every SDP
  // primitive runs in privsvc and we don't want a partial-privilege
  // attack surface where an unprivileged caller can probe the
  // detection runner with arbitrary commands. Same gate as crypto/grpc.
  //
  // pmp.* covers Phase 1 Patch Management v2 remediation primitives
  // (read_check_state + remediate). Both run privileged work (registry
  // reads on Windows, defaults/launchctl on macOS, etc.) and the
  // unprivileged surface is intentionally zero.
  return method.startsWith("crypto.")
      || method.startsWith("grpc.")
      || method.startsWith("sdp.")
      || method.startsWith("pmp.")
      || method === "patch.install";
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

    case "crypto.cert.renew":
      return handleRenewCert(req);

    case "grpc.connect":
      return handleGrpcConnect(req, push);

    case "grpc.facts.send":
      return handleFactsSend(req);

    case "grpc.facts.chunk":
      return handleFactsChunk(req);

    case "grpc.ack":
      return handleAck(req);

    case "grpc.heartbeat":
      return handleHeartbeat(req);

    case "grpc.close":
      return handleClose(req);

    case "software.inventory":
      return fail(req.id, "not_supported", "software.inventory is collected by Agent Core on macOS");

    case "security.compliance":
    case "security.posture":
      return handleSecurityPosture(req);

    case "patch.scan":
      return handlePatchScan(req);

    case "patch.install":
      return handlePatchInstall(req);

    // SDP — Phase 1-E. See privsvc/macos/src/sdp.ts.
    case "sdp.detect":
      return handleSdpDetect(req);

    case "sdp.download":
      return handleSdpDownload(req);

    case "sdp.install":
      return handleSdpInstall(req);

    // PMv2 — non-patch security remediation. See privsvc/macos/src/
    // pmp-remediation.ts. Phase 1 covers Windows-only checkIds —
    // these handlers return `unsupported_check` for everything until
    // Phase 2 lands macOS-applicable handlers (FileVault, Gatekeeper,
    // screen lock, SIP).
    case "pmp.read_check_state":
      return handlePmpReadCheckState(req);

    case "pmp.remediate":
      return handlePmpRemediate(req);

    default:
      return fail(req.id, "not_supported", `Unsupported method: ${req.method}`);
  }
}
