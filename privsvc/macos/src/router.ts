import os from "os";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { handleGenerateCsr, handleInstallCert, handleRenewCert } from "./crypto-store";
import {
  handleCredentialProvision,
  handleCredentialRetrieve,
  handleCredentialRemove,
} from "./credential-store";
import {
  handleAck,
  handleClose,
  handleFactsChunk,
  handleFactsSend,
  handleGrpcConnect,
  handleHeartbeat,
  handleCatalogRequest,
  handleSelfInstallRequest,
  handleRemoteSessionAnswer,
  handleRemoteSessionIce,
  handleRemoteSessionClose,
  handleRemoteSessionError,
  handleRemoteSessionTranscript,
  handleRemoteFileTransferAudit,
  handleRemoteScreenAudit
} from "./grpc-bridge";
import { handlePatchInstall, handlePatchScan } from "./patch-management";
import { handlePmpReadCheckState, handlePmpRemediate } from "./pmp-remediation";
import { handleSecurityPosture } from "./security-posture";
import { handleMdmEnrollmentState, handleMdmObserveSettings } from "./mdm-state";
import { handleScreenCapture } from "./screen-capture";
import { handleInputInject } from "./input-injection";
import {
  handleSdpDetect,
  handleSdpDownload,
  handleSdpInstall,
  handleSdpUninstall,
  handleSdpVerifySignature,
} from "./sdp";
import { handleDpPrefetch, handleDpStatus } from "./dp";
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
      // mdm.* es solo lectura, pero lee /Library/Managed Preferences y
      // consulta `profiles`. Se exige root por consistencia: el repo
      // evita a propósito una superficie de privilegio parcial.
      || method.startsWith("mdm.")
      || method === "patch.install"
      // RCP M3.S1 — screen.capture spawns the capture helper into the
      // console user's GUI session via `launchctl asuser` + `sudo`,
      // both of which require root.
      || method === "screen.capture";
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

    // Infrastructure Gateway credential custody (ADR-0001). PrivSvc holds the
    // enrollment private key, so it is the only component that can open a
    // credential sealed against this device's certificate.
    case "credential.provision":
      return handleCredentialProvision(req);

    case "credential.retrieve":
      return handleCredentialRetrieve(req);

    case "credential.remove":
      return handleCredentialRemove(req);

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

    case "grpc.catalog.request":
      return handleCatalogRequest(req);

    case "grpc.selfInstall.request":
      return handleSelfInstallRequest(req);

    // RCP M1.S1 — agent-side outbound signaling. The Node.js RCP
    // plugin sends these when the WebRTC peer generates an answer /
    // discovers a candidate / closes / errors. Mirror of Windows
    // Router.cs:109-118.
    case "grpc.send.remoteSessionAnswer":
      return handleRemoteSessionAnswer(req);

    case "grpc.send.remoteSessionIce":
      return handleRemoteSessionIce(req);

    case "grpc.send.remoteSessionClose":
      return handleRemoteSessionClose(req);

    case "grpc.send.remoteSessionError":
      return handleRemoteSessionError(req);

    // RCP M1.S3 — shell transcript chunks (agent → server).
    case "grpc.send.remoteSessionTranscript":
      return handleRemoteSessionTranscript(req);

    // RCP M2.S1 — file transfer audit (agent → server).
    case "grpc.send.remoteFileTransferAudit":
      return handleRemoteFileTransferAudit(req);

    // RCP M3.S1 — screen share audit (agent → server).
    case "grpc.send.remoteScreenAudit":
      return handleRemoteScreenAudit(req);

    // RCP M3.S1 — screen capture (Node.js → PrivSvc → Swift helper).
    // PrivSvc owns spawning the capture helper into the user's GUI
    // session; result is a base64 JPEG. Mirror of Windows Router.cs:121.
    // RCP — control remoto. Va por el helper, que es quien vive en la sesión
    // gráfica y quien tiene (o pide) el permiso de Accesibilidad.
    case "input.inject":
      return handleInputInject(req);

    case "screen.capture":
      return handleScreenCapture(req);

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

    // Uninstall by identity (app bundle rm / pkg receipt forget) — no download.
    case "sdp.uninstall":
      return handleSdpUninstall(req);

    // Signature gate (fail-closed) — pkgutil --check-signature / codesign.
    case "sdp.verifySignature":
      return handleSdpVerifySignature(req);

    // Distribution Phase B — DP role: warm the LAN cache + serve peers.
    case "sdp.dp.prefetch":
      return handleDpPrefetch(req);
    case "sdp.dp.status":
      return handleDpStatus(req);

    // PMv2 — non-patch security remediation. See privsvc/macos/src/
    // pmp-remediation.ts. Phase 1 covers Windows-only checkIds —
    // these handlers return `unsupported_check` for everything until
    // Phase 2 lands macOS-applicable handlers (FileVault, Gatekeeper,
    // screen lock, SIP).
    case "pmp.read_check_state":
      return handlePmpReadCheckState(req);

    // MDM — SOLO LECTURA. No hay handler de escritura a propósito: la
    // entrega la hará el perfil MDM, y una escritura del agente sería
    // redundante y conflictiva (ADR-0002).
    case "mdm.enrollment_state":
      return handleMdmEnrollmentState(req);

    case "mdm.observe_settings":
      return handleMdmObserveSettings(req);

    case "pmp.remediate":
      return handlePmpRemediate(req);

    default:
      return fail(req.id, "not_supported", `Unsupported method: ${req.method}`);
  }
}
