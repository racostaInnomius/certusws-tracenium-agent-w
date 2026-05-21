// src/plugins/rcp/session-manager.ts
//
// RCP M1.S1 — orchestrates concurrent WebRTC peer connections, one
// per active session. The manager:
//
//   - Allocates a PeerSession on RemoteSessionOffer
//   - Routes inbound ICE to the matching PeerSession
//   - Tears down on RemoteSessionClose / RemoteSessionError
//   - Limits the number of concurrent peers (defense in depth — the
//     backend also enforces session caps before sending the offer)
//
// The actual WebRTC handshake lives in `peer-session.ts`; this
// module owns the lifecycle map.

import type { AgentContext } from "../../core/agent-context";
import { PeerSession } from "./peer-session";

// M1.S1: hardcoded ceiling. The backend already caps sessions per
// device at 3 + per operator at 10. This 8 is a "if the backend
// invariant breaks, this agent process still doesn't run out of
// resources" safety net.
const MAX_CONCURRENT_LOCAL_PEERS = 8;

export class SessionManager {
  private readonly sessions = new Map<string, PeerSession>();

  constructor(private readonly ctx: AgentContext) {}

  /**
   * Called when the backend sends RemoteSessionOffer. Allocates a
   * peer + generates an answer. Send paths in PeerSession push the
   * answer + ICE candidates back via grpc-stream's write.
   *
   * Policy check: if `policy.features.remoteShell` is not enabled
   * for this capability, we reject before allocating the peer. The
   * backend SHOULD have caught this (capability isn't advertised on
   * Hello unless the flag is on) but enforce here as defense.
   */
  async onOffer(params: any): Promise<void> {
    const sessionId = String(params?.sessionId || "").trim();
    const sdp = String(params?.sdp || "");
    const capability = String(params?.capability || "");
    const timeoutSeconds = Number(params?.sessionTimeoutSeconds || 0) || 4 * 60 * 60;

    if (!sessionId || !sdp || !capability) {
      this.ctx.logger?.warn?.("[rcp] offer missing required fields", {
        sessionId,
        hasSdp: Boolean(sdp),
        capability
      });
      return;
    }

    if (this.sessions.has(sessionId)) {
      // Duplicate offer for the same sessionId — could be a
      // signaling retry. Resend the answer if we already have a
      // PeerSession; otherwise log and ignore.
      this.ctx.logger?.warn?.("[rcp] duplicate offer for existing session", {
        sessionId
      });
      return;
    }

    if (this.sessions.size >= MAX_CONCURRENT_LOCAL_PEERS) {
      this.ctx.logger?.warn?.("[rcp] rejecting offer: local cap reached", {
        sessionId,
        active: this.sessions.size
      });
      this.sendError(sessionId, "AGENT_AT_CAPACITY", "agent at concurrent-session cap");
      return;
    }

    // Capability gate — re-checks the policy flag for `rcp.shell`.
    // M2/M3 widen this to file/screen.
    if (capability === "rcp.shell") {
      const enabled = Boolean(
        this.ctx.policyRuntime?.isFeatureEnabled?.("remoteShell")
      );
      if (!enabled) {
        this.ctx.logger?.warn?.("[rcp] offer rejected: remoteShell disabled", {
          sessionId
        });
        this.sendError(sessionId, "POLICY_DISABLED", "remoteShell policy is off");
        return;
      }
    } else {
      // file / screen not yet supported by the agent.
      this.sendError(
        sessionId,
        "CAPABILITY_NOT_AVAILABLE",
        `capability ${capability} not implemented in this agent version`
      );
      return;
    }

    const peer = new PeerSession({
      sessionId,
      capability,
      ctx: this.ctx,
      sendAnswer: (s) => this.sendAnswer(sessionId, s),
      sendIce: (cand, mid, mline) =>
        this.sendIce(sessionId, cand, mid, mline),
      onTeardown: (reason) => {
        this.sessions.delete(sessionId);
        this.sendClose(sessionId, reason);
      },
      sessionTimeoutSeconds: timeoutSeconds
    });
    this.sessions.set(sessionId, peer);

    try {
      await peer.acceptOffer(sdp);
    } catch (err: any) {
      this.ctx.logger?.error?.("[rcp] acceptOffer failed", {
        sessionId,
        err: err?.message || String(err)
      });
      this.sessions.delete(sessionId);
      this.sendError(sessionId, "SDP_PARSE_ERROR", err?.message || String(err));
    }
  }

  onIce(params: any): void {
    const sessionId = String(params?.sessionId || "").trim();
    const peer = this.sessions.get(sessionId);
    if (!peer) {
      // ICE arriving for a session we never saw (or already
      // closed). Common during the close-race; log at debug, not
      // warn.
      this.ctx.logger?.debug?.("[rcp] ice for unknown session", { sessionId });
      return;
    }
    peer.addRemoteIce({
      candidate: String(params?.candidate || ""),
      sdpMid: String(params?.sdpMid || ""),
      sdpMLineIndex: Number(params?.sdpMLineIndex || 0)
    });
  }

  async onClose(params: any): Promise<void> {
    const sessionId = String(params?.sessionId || "").trim();
    const reason = String(params?.reason || "remote_closed");
    const peer = this.sessions.get(sessionId);
    if (!peer) return;
    this.sessions.delete(sessionId);
    await peer.dispose(reason);
  }

  async onError(params: any): Promise<void> {
    const sessionId = String(params?.sessionId || "").trim();
    const code = String(params?.code || "remote_error");
    this.ctx.logger?.warn?.("[rcp] backend reported error", {
      sessionId,
      code,
      message: params?.message
    });
    const peer = this.sessions.get(sessionId);
    if (peer) {
      this.sessions.delete(sessionId);
      await peer.dispose(`remote_error:${code}`);
    }
  }

  // ── Outbound write helpers ─────────────────────────────────────
  //
  // These call into the agent's gRPC write surface. The actual
  // wire-up of `ctx.sendControl` lives in grpc-stream.ts — see
  // RCP-related additions in that file's data-handler.

  private sendAnswer(sessionId: string, sdp: string): void {
    this.ctx.sendControl?.({
      remoteSessionAnswer: { sessionId, sdp }
    });
  }

  private sendIce(
    sessionId: string,
    candidate: string,
    sdpMid: string,
    sdpMLineIndex: number
  ): void {
    this.ctx.sendControl?.({
      remoteSessionIce: { sessionId, candidate, sdpMid, sdpMLineIndex }
    });
  }

  private sendClose(sessionId: string, reason: string): void {
    this.ctx.sendControl?.({
      remoteSessionClose: { sessionId, reason }
    });
  }

  private sendError(sessionId: string, code: string, message: string): void {
    this.ctx.sendControl?.({
      remoteSessionError: { sessionId, code, message }
    });
  }
}
