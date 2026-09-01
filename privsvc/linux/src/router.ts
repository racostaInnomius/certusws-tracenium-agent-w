// privsvc/linux/src/router.ts
//
// Method dispatch for the Linux privsvc IPC. Subsequent phases extend
// this switch as handlers land:
//
//   Phase 2 — grpc.* (grpc-bridge.ts) + crypto.* (crypto-store.ts)  [DONE]
//   Phase 5 — security.compliance / security.posture   (security-posture.ts)
//   Phase 6 — patch.scan                                (patch-management.ts)
//   Phase 7 — patch.install                             (patch-management.ts)
//   Phase 8 — pmp.read_check_state / pmp.remediate     (pmp-remediation.ts)
//   Phase 9 — sdp.detect / sdp.download / sdp.install   (sdp.ts)
//
// Every privileged method is gated by `requiresRoot()` — the kernel
// already enforces this via the socket's 0660 root:tracenium mode
// (only the agent user, who is also `tracenium`, can connect), so
// this is defense in depth, not the primary boundary.
import os from "os";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";
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
  handleRemoteScreenAudit,
} from "./grpc-bridge";
import { handleSecurityPosture } from "./security-posture";
import { handleScreenCapture } from "./screen-capture";
import { handleIndicatorShow, handleIndicatorHide } from "./remote-indicator";
import { handleConsentRequest } from "./consent-dialog";
import { handlePatchScan, handlePatchInstall } from "./patch-management";
import { handlePmpReadCheckState, handlePmpRemediate } from "./pmp-remediation";
import {
  handleSdpDetect,
  handleSdpDownload,
  handleSdpInstall,
  handleSdpUninstall,
  handleSdpVerifySignature,
} from "./sdp";
import { handleDpPrefetch, handleDpStatus } from "./dp";
import { handleAgentInstall } from "./agent-install";
import * as rcpPty from "./rcp-pty";
import {
  handleCdpCsrGenerate,
  handleCdpKeyDestroy,
  handleCdpKeyList
} from "./cdp-keys";
import { handleCdpCertInstall } from "./cdp-cert-install";

function isRoot() {
  return typeof process.getuid === "function" ? process.getuid() === 0 : false;
}

function requiresRoot(method: string) {
  // Phase 1 has no privileged methods yet; the gate is preinstalled
  // so we don't forget to apply it when handlers get wired in. Keep
  // this prefix list in lockstep with the macOS router.ts.
  return (
    method.startsWith("crypto.") ||
    method.startsWith("grpc.") ||
    method.startsWith("sdp.") ||
    method.startsWith("pmp.") ||
    // cdp.* faltaba en las dos plataformas. Aqui la lista dice
    // literalmente "keep this prefix list in lockstep with the macOS
    // router.ts", y no lo estaba.
    method.startsWith("cdp.") ||
    method === "patch.install" ||
    method === "agent.install" ||
    // RCP M3.S1 — screen.capture spawns the capture helper as the
    // session user (runuser/su), which requires root.
    method === "screen.capture" ||
    // RCP — abre un pty como root. Es la operacion mas privilegiada que
    // expone este broker, asi que el gate es obligatorio.
    method.startsWith("rcp.pty.")
  );
}

export async function routeRequest(req: PrivSvcRequest, push: PushSink): Promise<PrivSvcResponse> {
  if (req.v !== 1) return fail(req.id, "bad_version", "Unsupported protocol version");
  if (!req.id) return fail("unknown", "bad_request", "Missing id");
  if (!req.method) return fail(req.id, "bad_request", "Missing method");

  logger.info("ipc_request", {
    method: req.method,
    id: req.id,
    tenantId: req.meta?.tenantId,
    deviceId: req.meta?.deviceId,
  });

  if (requiresRoot(req.method) && !isRoot()) {
    return fail(req.id, "forbidden", "root required");
  }

  switch (req.method) {
    case "ping":
      return success(req.id, {
        service: "TraceniumPrivSvc",
        platform: "linux",
        version: process.env.TRACENIUM_PRIVSVC_VERSION || "1.0.0",
        utc: new Date().toISOString(),
      });

    case "identity":
      return success(req.id, {
        uid: typeof process.getuid === "function" ? process.getuid() : null,
        gid: typeof process.getgid === "function" ? process.getgid() : null,
        user: os.userInfo().username,
        isRoot: isRoot(),
        utc: new Date().toISOString(),
      });

    // ── Crypto / cert lifecycle (Phase 2) ─────────────────────────
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

    // ADR-0011 fase 2 — emision para certificados AJENOS al agente.
    //
    // Metodos NUEVOS, no `crypto.csr.generate`: ese escribe a rutas
    // fijas y reutilizarlo sobrescribiria la clave de enrolamiento del
    // agente (correccion medida de ADR-0004).
    case "cdp.csr.generate":
      return handleCdpCsrGenerate(req);

    case "cdp.key.destroy":
      return handleCdpKeyDestroy(req);

    case "cdp.key.list":
      return handleCdpKeyList(req);

    // ADR-0011 fase 3. Aqui los guards de la fase 1 dejan de estar sin
    // cablear: allowlist de rutas + cadena validada contra el trust
    // store LOCAL.
    case "cdp.cert.install":
      return handleCdpCertInstall(req);

    case "crypto.cert.renew":
      return handleRenewCert(req);

    // ── gRPC bridge (Phase 2) ─────────────────────────────────────
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

    // RCP M3.S1 — screen capture (Node.js → PrivSvc → C helper).
    // PrivSvc owns spawning the capture helper as the session user
    // with DISPLAY/XAUTHORITY; result is a base64 JPEG. Mirror of
    // Windows Router.cs:121.
    // RCP — shell remoto con privilegios en Linux. Devuelve la ruta de un
    // socket dedicado; los bytes del pty NO pasan por este IPC (ver
    // rcp-pty.ts para el porque).
    case "rcp.pty.open":
      return rcpPty.handleOpen(req);

    case "rcp.pty.close":
      return rcpPty.handleClose(req);

    case "screen.capture":
      return handleScreenCapture(req);

    // ADR-0012 — indicador de sesión de control remoto. Linux no tiene
    // bandeja donde ponerlo, así que PrivSvc lo lanza dentro de la sesión
    // gráfica y lo mantiene vivo mientras dure. `show` no vuelve hasta
    // saber si la ventana está en pantalla: si no lo está, el agente
    // rechaza la sesión en vez de compartir pantalla en silencio.
    case "rcp.indicator.show":
      return handleIndicatorShow(req);

    case "rcp.indicator.hide":
      return handleIndicatorHide(req);

    // ADR-0012 — las dos puertas de consentimiento (ver / controlar).
    // Bloquea hasta que la persona decide o vence el plazo.
    case "rcp.consent.request":
      return handleConsentRequest(req);

    // ── SCP — security posture (Phase 5) ──────────────────────────
    // Both method names route to the same handler. Schema 2.0 uses
    // `security.compliance` from agent-side; legacy macOS callers
    // still use `security.posture`. Accept both for cross-platform
    // alignment with the macOS router.
    case "security.compliance":
    case "security.posture":
      return handleSecurityPosture(req);

    // ── PMP scan (Phase 6) ────────────────────────────────────────
    // Read-only enumeration of available updates via apt/dnf/zypper.
    case "patch.scan":
      return handlePatchScan(req);

    // ── PMP install (Phase 7) ─────────────────────────────────────
    // Dispatch by family: debian → apt-get install --only-upgrade;
    // rhel → dnf upgrade --advisory=...; suse → stub (Phase 10).
    // Lock detection on debian (`fuser`) before invoking apt-get;
    // dnf has built-in waiter, no pre-probe needed.
    case "patch.install":
      return handlePatchInstall(req);

    // ── PMP v2 — non-patch security remediation (Phase 8) ─────────
    // Per-checkId handlers for sshd hardening + firewall enable.
    // SSH config edits use the drop-in approach (write to
    // /etc/ssh/sshd_config.d/99-tracenium-hardening.conf and
    // validate via `sshd -t` before atomic rename). Operator's
    // /etc/ssh/sshd_config is never touched.
    case "pmp.read_check_state":
      return handlePmpReadCheckState(req);
    case "pmp.remediate":
      return handlePmpRemediate(req);

    // ── SDP — Software Delivery (Phase 9) ─────────────────────────
    // Three handlers: detect (rule evaluation), download (curl +
    // sha256 verify into root-owned staging), install (apt-get for
    // .deb / dnf for .rpm). Format ↔ distro family is enforced in
    // handleSdpInstall — a deb on RHEL bounces with format_unsupported.
    case "sdp.detect":
      return handleSdpDetect(req);
    case "sdp.download":
      return handleSdpDownload(req);
    case "sdp.install":
      return handleSdpInstall(req);
    // Uninstall by package name (apt-get/dnf remove) — no download, identity
    // from the dpkg_installed/rpm_installed detection rule.
    case "sdp.uninstall":
      return handleSdpUninstall(req);
    // Signature gate (fail-closed) — rpm -K / dpkg-sig --verify.
    case "sdp.verifySignature":
      return handleSdpVerifySignature(req);

    // Distribution Phase B — DP role: warm the LAN cache + serve peers.
    case "sdp.dp.prefetch":
      return handleDpPrefetch(req);
    case "sdp.dp.status":
      return handleDpStatus(req);

    // ── Agent self-upgrade ────────────────────────────────────────
    // Installs the .deb/.rpm the agent has downloaded into
    // /var/lib/tracenium/updates/. Must go through privsvc (root)
    // because dpkg/rpm need root — the agent itself runs as the
    // unprivileged `tracenium` user. Dispatched as a detached
    // systemd-run --scope so the install survives our own restart
    // when the upgrade's postinstall does `systemctl try-restart
    // tracenium-privsvc tracenium-agent`.
    case "agent.install":
      return handleAgentInstall(req);

    // ── AMP — software inventory ──────────────────────────────────
    // On macOS this method bounces with `not_supported` because amp
    // is collected by the agent core (running as root via launchd).
    // On Linux the agent runs as user `tracenium` (non-root), so
    // privileged inventory bits (dmidecode, /sys/class/dmi/id reads
    // that need root in some VM configs) DO need to come through
    // privsvc. Phase 3 wires the actual handler — for now bounce so
    // the agent gets a clear contract violation rather than a hang.
    case "software.inventory":
      return fail(req.id, "not_implemented", "software.inventory will land in Phase 3");

    default:
      // Phase 1: every other method should bounce. The agent's plugin
      // code is OS-aware enough to skip Linux-unsupported calls, so
      // this branch should mostly fire from manual debugging or from
      // a method added in a future phase whose handler hasn't been
      // wired in router yet.
      return fail(req.id, "not_supported", `Unsupported method: ${req.method}`);
  }
}
