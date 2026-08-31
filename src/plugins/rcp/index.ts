// src/plugins/rcp/index.ts
//
// RCP (Remote Control Plugin) — M3.S1.
//
// Responsibilities owned by this module:
//
//   - Advertise capability strings on Hello when policy enables them:
//       rcp.shell  — policy.features.remoteShell  (M1)
//       rcp.file   — policy.features.remoteFile   (M2.S1)
//       rcp.screen — policy.features.remoteScreen (M3.S1)
//   - Handle inbound RemoteSession* control messages from the
//     backend by delegating to the SessionManager.
//   - Send outbound signaling (Answer / Ice / Close / Error) via the
//     gRPC client write surface.
//
// See RCP_DESIGN_DECISIONS_v2.md for the architecture overview.

import type { AgentContext } from "../../core/agent-context";
import { SessionManager } from "./session-manager";
import { createLinuxConsentPrompter } from "./consent-prompter-linux";
import { createTrayConsentPrompter } from "./consent-prompter-tray";

let manager: SessionManager | null = null;
let nativeBroken = false;
let nativeBrokenReason: string | null = null;

/**
 * Returns true if the WebRTC native runtime is known to be broken on this
 * host (load failed, construct-probe failed, etc.). The Hello path uses this
 * to gate `rcp.*` capability advertisement: if the runtime is broken, we
 * don't advertise — the operator gets a "device does not advertise rcp.shell"
 * tooltip instead of clicking a button that would never respond.
 */
export function isRcpNativeBroken(): boolean {
  return nativeBroken;
}

export function rcpNativeBrokenReason(): string | null {
  return nativeBrokenReason;
}

/**
 * Eager probe of the WebRTC native runtime during agent bootstrap.
 *
 * Background: `node-datachannel` is a C++ binding. On hosts where the .node
 * loads but the underlying libdatachannel/OpenSSL/libjuice combo is broken
 * (wrong arch, missing system libs, ABI mismatch with the embedded Node, an
 * IPv6 socket call that hard-faults on a stripped-down Windows install,
 * etc.) the FIRST attempt to instantiate `PeerConnection` crashes the V8
 * runtime. Node disappears with no JS-level handler firing — no log, no
 * wedge dump, no stack trace. We've spent months chasing "the AgentCore
 * stops running" because the failure happens lazily on the first operator
 * click rather than at boot.
 *
 * This probe moves the failure UP to boot. We try to construct + dispose a
 * throwaway PeerConnection right after `initRcp`. If it works, we're fine
 * — RCP is healthy and the operator's first session works on the first try.
 * If it crashes the runtime, you see it the moment the agent starts, in the
 * Event Viewer as a faulting module — not silently mid-call.
 *
 * If the probe throws a normal JS error (not a native crash), we log + mark
 * the runtime broken so subsequent capability advertisements are accurate.
 *
 * Idempotent and safe to call repeatedly.
 */
export function probeRcpNative(ctx: AgentContext): void {
  if (nativeBroken) return; // already known bad
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const ndc = require("node-datachannel");
    const probe = new ndc.PeerConnection("rcp-probe", { iceServers: [] });
    try {
      probe.close?.();
    } catch {
      /* ignore — disposed regardless */
    }
    ctx.logger?.info?.("[rcp] native runtime probe OK");
  } catch (err: any) {
    nativeBroken = true;
    nativeBrokenReason = err?.message || String(err);
    ctx.logger?.error?.("[rcp] native runtime probe FAILED — RCP disabled", {
      name: err?.name,
      code: err?.code,
      message: err?.message,
      stack: err?.stack
    });
  }
}

/**
 * Initialize the RCP plugin. Called from the gRPC stream handler at
 * bootstrap, after the agent context is wired but before the first
 * control message arrives. The plugin is a passive listener — it
 * only acts when the backend sends RemoteSession* messages.
 *
 * Idempotent: returns the existing instance on repeat init (the
 * stream handler may re-init on reconnect).
 */
export function initRcp(ctx: AgentContext): SessionManager {
  if (manager) return manager;
  manager = new SessionManager(ctx);
  registerConsentPrompter(ctx);
  ctx.logger?.info?.("[rcp] initialized");
  return manager;
}

/**
 * Registra el prompter nativo de esta plataforma (ADR-0012).
 *
 * Sin esto, `ctx.consentPrompter` queda vacío, el agente NO anuncia
 * `rcp.consent` y toda sesión que requiera consentimiento se deniega. Eso es
 * lo correcto como valor por defecto —fallar cerrado— y es inservible como
 * estado final: la función existe pero nadie puede usarla.
 *
 * ⚠️ No se pisa un prompter ya registrado. Los tests inyectan el suyo, y una
 * llamada a initRcp() después lo sustituiría por el real, que en el runner
 * intentaría hablar con un PrivSvc que no existe.
 */
function registerConsentPrompter(ctx: AgentContext): void {
  if (ctx.consentPrompter) return;
  try {
    if (process.platform === "linux") {
      ctx.consentPrompter = createLinuxConsentPrompter(ctx);
      ctx.logger?.info?.("[rcp] consent prompter: linux/x11");
      return;
    }
    if (process.platform === "win32" || process.platform === "darwin") {
      // Ambas tienen ya algo corriendo en la sesión del usuario (bandeja .NET
      // / app de estado Swift), así que el aviso viaja por el canal de
      // ficheros que esas dos ya usan. Ver consent-prompter-tray.ts.
      ctx.consentPrompter = createTrayConsentPrompter(ctx);
      ctx.logger?.info?.("[rcp] consent prompter: tray", { platform: process.platform });
      return;
    }

    ctx.logger?.info?.("[rcp] sin prompter nativo para esta plataforma", {
      platform: process.platform
    });
  } catch (err: any) {
    ctx.logger?.warn?.("[rcp] no se pudo registrar el prompter de consentimiento", {
      err: err?.message || String(err)
    });
  }
}

/**
 * Returns true if the agent should advertise `rcp.shell` on Hello.
 * Called from `grpc-client.ts` when computing the capabilities array.
 * Reading the policy at advertisement time (not init) means a policy
 * push that flips the flag picks up on the next reconnect.
 */
export function rcpShellAdvertised(ctx: AgentContext): boolean {
  if (nativeBroken) return false; // probe found the runtime broken; advertising would lie
  try {
    return Boolean(ctx.policyRuntime.isFeatureEnabled("remoteShell"));
  } catch {
    return false;
  }
}

/**
 * Returns true if the agent should advertise `rcp.file` on Hello.
 * Gated on policy.features.remoteFile (M2.S1).
 */
export function rcpFileAdvertised(ctx: AgentContext): boolean {
  if (nativeBroken) return false;
  try {
    return Boolean(ctx.policyRuntime.isFeatureEnabled("remoteFile"));
  } catch {
    return false;
  }
}

/**
 * Returns true if the agent should advertise `rcp.screen` on Hello.
 * Gated on policy.features.remoteScreen (M3.S1).
 */
export function rcpScreenAdvertised(ctx: AgentContext): boolean {
  if (nativeBroken) return false;
  try {
    return Boolean(ctx.policyRuntime.isFeatureEnabled("remoteScreen"));
  } catch {
    return false;
  }
}

/**
 * Returns true if the agent should advertise `rcp.consent` on Hello — i.e. it
 * can actually prompt the interactive user for approval. Gated on a functional
 * consent prompter being registered on the context: if none is wired, we must
 * NOT advertise, so the backend fail-closes any consent-required session rather
 * than opening one the user never approved. See consent-prompt.ts.
 */
export function rcpConsentAdvertised(ctx: AgentContext): boolean {
  if (nativeBroken) return false;
  try {
    return Boolean(ctx.consentPrompter?.available?.());
  } catch {
    return false;
  }
}

/**
 * Inbound message dispatch. The gRPC stream handler calls this for
 * each remoteSession* control message; we route to the manager.
 *
 * Lazy-init the manager so a misconfigured deploy that never gets
 * a RemoteSessionOffer doesn't even allocate the WebRTC machinery.
 */
export async function handleRemoteSessionMessage(
  ctx: AgentContext,
  type:
    | "offer"
    | "ice"
    | "close"
    | "error",
  params: any
): Promise<void> {
  const sid = String(params?.sessionId || "").slice(-8);
  // `ice` llega 10-20+ veces por sesión (un mensaje por candidato) y es
  // puro ruido en el caso feliz; offer/close/error son eventos de ciclo
  // de vida, raros y valiosos. Se separan de nivel para bajar volumen
  // sin perder la traza de establecimiento de sesión — que es justo
  // donde este log sirve como chokepoint de fallos silenciosos.
  const traceDispatch = type === "ice" ? ctx.logger?.debug : ctx.logger?.info;
  traceDispatch?.("[rcp] dispatch entered", { type, sid });
  if (!manager) initRcp(ctx);
  if (!manager) {
    ctx.logger?.error?.("[rcp] dispatch aborted: manager init returned null", {
      type,
      sid
    });
    return;
  }
  try {
    switch (type) {
      case "offer":
        await manager.onOffer(params);
        break;
      case "ice":
        await manager.onIce(params);
        break;
      case "close":
        await manager.onClose(params);
        break;
      case "error":
        await manager.onError(params);
        break;
    }
    traceDispatch?.("[rcp] dispatch handler returned", { type, sid });
  } catch (err: any) {
    // Verbose by design: this is the chokepoint where any silent failure in the
    // session-manager / peer-session / node-datachannel chain surfaces. Without
    // the stack we just see the dispatcher swallow the error and the operator
    // sees "Signaling WebSocket error" with no clue why. Worth the extra log
    // bytes on a code path that fires per-session, not per-message.
    ctx.logger?.error?.("[rcp] dispatch handler threw", {
      type,
      sid,
      message: err?.message || String(err),
      name: err?.name,
      code: err?.code,
      stack: err?.stack
    });
    throw err;
  }
}

export { SessionManager };
