// src/plugins/rcp/index.ts
//
// RCP (Remote Control Plugin) — M1.S1 skeleton.
//
// Responsibilities owned by this module:
//
//   - Advertise capability strings on Hello when policy enables them
//     (`rcp.shell` when `policy.features.remoteShell === true`).
//   - Handle inbound RemoteSession* control messages from the
//     backend by delegating to the SessionManager.
//   - Send outbound signaling (Answer / Ice / Close / Error) via the
//     gRPC client write surface.
//
// What this module does NOT do (yet):
//
//   - Spawn PTYs. Sprint 2 hooks the PTY into the DataChannel.
//   - Persist transcripts. Sprint 3.
//   - Enforce session caps. Backend already caps at the start of a
//     session; the agent trusts those checks.
//
// See RCP_DESIGN_DECISIONS_v2.md for the architecture overview.

import type { AgentContext } from "../../core/agent-context";
import { SessionManager } from "./session-manager";

let manager: SessionManager | null = null;

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
  ctx.logger?.info?.("[rcp] initialized");
  return manager;
}

/**
 * Returns true if the agent should advertise `rcp.shell` on Hello.
 * Called from `grpc-client.ts` when computing the capabilities
 * array. Reading the policy at advertisement time (not init) means
 * a policy push that flips the flag picks up on the next reconnect.
 */
export function rcpShellAdvertised(ctx: AgentContext): boolean {
  try {
    return Boolean(ctx.policyRuntime.isFeatureEnabled("remoteShell"));
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
  if (!manager) initRcp(ctx);
  if (!manager) return;
  switch (type) {
    case "offer":
      return manager.onOffer(params);
    case "ice":
      return manager.onIce(params);
    case "close":
      return manager.onClose(params);
    case "error":
      return manager.onError(params);
  }
}

export { SessionManager };
