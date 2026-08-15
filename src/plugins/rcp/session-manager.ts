// src/plugins/rcp/session-manager.ts
//
// RCP M3.S1 — orchestrates concurrent WebRTC peer connections, one
// per active session. The manager:
//
//   - Allocates a PeerSession on RemoteSessionOffer
//   - Routes inbound ICE to the matching PeerSession
//   - Tears down on RemoteSessionClose / RemoteSessionError
//   - Limits the number of concurrent peers (defense in depth — the
//     backend also enforces session caps before sending the offer)
//   - Sends audit gRPC messages for file transfer (M2.S1) and screen
//     share (M3.S1) sessions via ctx.sendControl
//
// The actual WebRTC handshake lives in `peer-session.ts`; this
// module owns the lifecycle map.

import type { AgentContext } from "../../core/agent-context";
import { PeerSession } from "./peer-session";
import {
  failClosedConsentPrompter,
  consentCloseReason,
  type ConsentDecision,
} from "./consent-prompt";

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
    // iceServersJson — added 2026-06-10. Backend forwards the same
    // Cloudflare-minted TURN creds it gave the browser, so the agent
    // can emit relay candidates too. JSON-stringified RTCIceServer[].
    // Empty/absent on legacy backends (before the proto field existed),
    // in which case we fall back to no iceServers and behave like
    // before (host-only candidates, ICE works only on the same LAN).
    const iceServersJson = String(params?.iceServersJson || "").trim();
    let iceServers: any[] = [];
    if (iceServersJson) {
      try {
        const parsed = JSON.parse(iceServersJson);
        if (Array.isArray(parsed)) iceServers = parsed;
      } catch (err: any) {
        this.ctx.logger?.warn?.("[rcp] failed to parse iceServersJson; falling back to empty", {
          sid: sessionId.slice(-8),
          err: err?.message || String(err),
          firstChars: iceServersJson.slice(0, 80)
        });
      }
    }
    this.ctx.logger?.info?.("[rcp] onOffer entered", {
      sid: sessionId.slice(-8),
      capability,
      sdpLen: sdp.length,
      activeSessions: this.sessions.size,
      iceServersCount: iceServers.length
    });

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

    // Capability gate — re-checks the policy flag for each capability.
    // The backend SHOULD have already verified this (capability must be
    // advertised in Hello), but we enforce here as defense in depth.
    type CapabilityPolicyMap = Record<string, "remoteShell" | "remoteFile" | "remoteScreen">;
    const CAPABILITY_POLICY: CapabilityPolicyMap = {
      "rcp.shell":  "remoteShell",
      "rcp.file":   "remoteFile",
      "rcp.screen": "remoteScreen"
    };
    const policyFeature = CAPABILITY_POLICY[capability];
    if (!policyFeature) {
      this.sendError(sessionId, "CAPABILITY_UNKNOWN", `unknown capability: ${capability}`);
      return;
    }
    const enabled = Boolean(this.ctx.policyRuntime?.isFeatureEnabled?.(policyFeature));
    if (!enabled) {
      this.ctx.logger?.warn?.("[rcp] offer rejected: capability policy disabled", {
        sessionId,
        capability
      });
      this.sendError(sessionId, "POLICY_DISABLED", `${capability} policy is off`);
      return;
    }

    // User-attended approval gate. When policy requires end-user consent, prompt
    // the interactive user BEFORE allocating the peer / opening the capability.
    // A deny or timeout tears the session down with the conventional close
    // reason the backend audits (consent_denied / consent_timeout). The prompter
    // is injected on ctx; absent one, the fail-closed default denies — the
    // backend should have already blocked this via the rcp.consent capability
    // gate, but we enforce here too (defense in depth).
    const requireConsent = Boolean(
      this.ctx.policyRuntime?.isFeatureEnabled?.("remoteRequireConsent")
    );
    if (requireConsent) {
      const prompter = this.ctx.consentPrompter ?? failClosedConsentPrompter;
      let decision: ConsentDecision;
      try {
        decision = await prompter.request({
          sessionId,
          capability,
          operator: params?.operatorUserId ? String(params.operatorUserId) : null,
          timeoutSeconds,
        });
      } catch (err: any) {
        // A prompter that throws must not fail OPEN — treat as denied.
        this.ctx.logger?.error?.("[rcp] consent prompt threw; denying", {
          sid: sessionId.slice(-8),
          err: err?.message || String(err),
        });
        decision = "denied";
      }
      if (decision !== "approved") {
        this.ctx.logger?.info?.("[rcp] session declined by consent gate", {
          sid: sessionId.slice(-8),
          capability,
          decision,
        });
        this.sendClose(sessionId, consentCloseReason(decision) ?? "consent_denied");
        return;
      }
      this.ctx.logger?.info?.("[rcp] consent granted", {
        sid: sessionId.slice(-8),
        capability,
      });
    }

    // Construct the PeerSession. This instantiates the native node-datachannel
    // RtcPeerConnection, which has historically been the silent-crash hotspot
    // (missing prebuild for the host arch, deadlock during ICE init, etc.).
    // Bracketing logs let us locate the exact step the next time it fails.
    this.ctx.logger?.info?.("[rcp] constructing PeerSession", {
      sid: sessionId.slice(-8)
    });
    const peer = new PeerSession({
      sessionId,
      capability,
      ctx: this.ctx,
      iceServers,
      sendAnswer: (s) => this.sendAnswer(sessionId, s),
      sendIce: (cand, mid, mline) =>
        this.sendIce(sessionId, cand, mid, mline),
      sendTranscript: (chunk) => this.sendTranscript(sessionId, chunk),
      sendFileTransferAudit: (audit) =>
        this.sendFileTransferAudit(sessionId, audit),
      sendScreenAudit: (audit) =>
        this.sendScreenAudit(sessionId, audit),
      onTeardown: (reason) => {
        this.sessions.delete(sessionId);
        this.sendClose(sessionId, reason);
      },
      sessionTimeoutSeconds: timeoutSeconds
    });
    this.ctx.logger?.info?.("[rcp] PeerSession constructed", {
      sid: sessionId.slice(-8)
    });
    this.sessions.set(sessionId, peer);

    try {
      this.ctx.logger?.info?.("[rcp] acceptOffer starting", {
        sid: sessionId.slice(-8)
      });
      await peer.acceptOffer(sdp);
      this.ctx.logger?.info?.("[rcp] acceptOffer completed", {
        sid: sessionId.slice(-8)
      });
    } catch (err: any) {
      this.ctx.logger?.error?.("[rcp] acceptOffer failed", {
        sessionId,
        err: err?.message || String(err),
        stack: err?.stack
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
    // Verbose by intent — when "acceptOffer starting" was the last line in the
    // log and nothing else followed, we needed to know whether (a) libdatachannel
    // hung in setLocal/setRemoteDescription (we'd never get here), (b) the
    // answer was generated but the IPC to PrivSvc failed silently (we'd see
    // THIS log but no remoteSessionAnswer in the bus). Without distinguishing
    // the two, the diagnosis loops back to "node-datachannel broke" when the
    // real issue might be the grpc-client↔PrivSvc reconnect storm.
    this.ctx.logger?.info?.("[rcp] sendAnswer dispatching", {
      sid: sessionId.slice(-8),
      sdpLen: sdp.length
    });
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
    // Candidate dispatch was the one step in the whole RCP handshake with no
    // trace at all. When a session dies with `ice_failed` and the browser
    // reports zero remote candidates, there was no way to tell "the agent
    // never gathered any" apart from "it gathered them and they were lost on
    // the way" — which are completely different bugs in different repos.
    //
    // One line per candidate is fine: a handshake produces a handful, not a
    // stream, and they only flow during the first seconds of a session.
    // `typ` is the useful part (host / srflx / relay), so we extract it
    // instead of logging the whole candidate line.
    const typ = /(?:^| )typ (\w+)/.exec(candidate || "")?.[1] ?? "unknown";
    this.ctx.logger?.info?.("[rcp] sendIce dispatching", {
      sid: sessionId.slice(-8),
      typ,
      sdpMid,
      // libdatachannel emits candidates prefixed with "a=", while the browser
      // side expects the bare "candidate:..." attribute. Recorded so a
      // format mismatch is visible in the log rather than inferred.
      hasAPrefix: String(candidate || "").startsWith("a="),
      len: String(candidate || "").length
    });
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

  private sendTranscript(
    sessionId: string,
    chunk: {
      stream: "stdout";
      tsDeltaSeconds: number;
      data: string;
      bytesCount: number;
    }
  ): void {
    this.ctx.sendControl?.({
      remoteSessionTranscript: {
        sessionId,
        stream: chunk.stream,
        tsDeltaSeconds: chunk.tsDeltaSeconds,
        data: chunk.data,
        bytesCount: chunk.bytesCount
      }
    });
  }

  // M2.S1 — fire-and-forget audit for file transfer lifecycle events.
  // Called by FileSession at "started" and at terminal status
  // ("completed" | "failed" | "cancelled").
  private sendFileTransferAudit(
    sessionId: string,
    audit: {
      transferId: string;
      direction: string;
      remotePath: string;
      filename: string;
      sizeBytes: number;
      transferredBytes: number;
      status: string;
      errorMessage: string;
    }
  ): void {
    this.ctx.sendControl?.({
      remoteFileTransferAudit: {
        sessionId,
        transferId: audit.transferId,
        direction: audit.direction,
        remotePath: audit.remotePath,
        filename: audit.filename,
        sizeBytes: audit.sizeBytes,
        transferredBytes: audit.transferredBytes,
        status: audit.status,
        errorMessage: audit.errorMessage
      }
    });
  }

  // M3.S1 — fire-and-forget audit for screen share lifecycle events.
  // Called by ScreenSession at "started" and "stopped" / "error".
  private sendScreenAudit(
    sessionId: string,
    audit: {
      event: string;
      width: number;
      height: number;
      fps: number;
      errorMessage: string;
    }
  ): void {
    this.ctx.sendControl?.({
      remoteScreenAudit: {
        sessionId,
        event: audit.event,
        width: audit.width,
        height: audit.height,
        fps: audit.fps,
        errorMessage: audit.errorMessage
      }
    });
  }
}
