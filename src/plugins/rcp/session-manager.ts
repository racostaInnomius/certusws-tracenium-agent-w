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
  SESSION_CONSENT_TIMEOUT_S,
  type ConsentDecision,
} from "./consent-prompt";

// M1.S1: hardcoded ceiling. The backend already caps sessions per
// device at 3 + per operator at 10. This 8 is a "if the backend
// invariant breaks, this agent process still doesn't run out of
// resources" safety net.
const MAX_CONCURRENT_LOCAL_PEERS = 8;

// Candidates that arrive before their session exists are held here, keyed by
// sessionId, until onOffer creates the peer. See onIce for why.
//
// Bounds are deliberate: this map is fed directly by inbound network messages,
// so an unbounded version is a memory-growth primitive for anyone who can
// reach the signaling path. A real gathering emits well under a dozen
// candidates; anything past the cap is a bug or an attack, not a session.
const PENDING_ICE_MAX_SESSIONS = 16;
const PENDING_ICE_MAX_PER_SESSION = 32;
// A session whose offer never turns up is dead weight. 60s is far longer than
// the offer/answer round trip (sub-second in practice) and matches the
// backend's own signal-bus TTL.
const PENDING_ICE_TTL_MS = 60_000;

type PendingIce = {
  candidate: string;
  sdpMid: string;
  sdpMLineIndex: number;
};

/** `a=ice-ufrag:` from an SDP. Identifies an ICE generation: a new value
 *  means the far side restarted ICE rather than resending its offer. */
function extractIceUfrag(sdp: string): string | null {
  const m = /^a=ice-ufrag:(\S+)/m.exec(String(sdp || ""));
  return m ? m[1] : null;
}

export class SessionManager {
  private readonly sessions = new Map<string, PeerSession>();

  /**
   * Sesiones cuya persona YA dio su consentimiento.
   *
   * ⚠️ Existe por el reinicio de ICE. Cuando el Wi-Fi de un portátil salta de
   * punto de acceso, el navegador manda una oferta nueva; para `rcp.screen`
   * el peer se reconstruye desde cero y el resto de `onOffer` se ejecuta otra
   * vez — incluida la puerta del consentimiento. Es decir: a la persona le
   * volvía a saltar el diálogo a mitad de sesión, sin que nada hubiera
   * cambiado salvo su router.
   *
   * Volver a preguntar ahí no es "más seguro", es peor: enseña que el
   * diálogo aparece solo y se acepta sin leer, que es exactamente cómo se
   * anula un consentimiento. La sesión es LA MISMA —mismo id, mismo
   * operador, el indicador nunca se apagó—, así que la decisión sigue valiendo.
   *
   * Se limpia con la sesión: nunca sobrevive a un cierre.
   */
  private readonly consentGranted = new Set<string>();
  private readonly pendingIce = new Map<
    string,
    { at: number; items: PendingIce[] }
  >();
  // ice-ufrag of the offer each live session was built from. A second offer
  // carrying the SAME ufrag is a signaling retransmit; a DIFFERENT one is an
  // ICE restart, which this WebRTC stack cannot apply — see onOffer.
  private readonly sessionUfrag = new Map<string, string>();

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
    // Quién abrió la sesión, para el indicador del endpoint (ADR-0012).
    // Vacío en backends anteriores a este campo: el indicador degrada a "un
    // operador" en vez de inventarse un nombre.
    const operator = String(params?.operator || "").trim();

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
      // A second offer for a live session is one of two very different
      // things, and the old code ignored both — which left the browser
      // waiting for an answer that never came until its retries ran out
      // ("WebRTC connection lost — retries exhausted").
      const incomingUfrag = extractIceUfrag(sdp);
      const knownUfrag = this.sessionUfrag.get(sessionId);
      const peer = this.sessions.get(sessionId)!;

      if (incomingUfrag && knownUfrag && incomingUfrag === knownUfrag) {
        // Same ICE credentials ⇒ a plain retransmit of the offer we already
        // answered (bus redelivery, or the browser resending). Re-applying is
        // safe: libdatachannel accepts an identical remote description and
        // emits a fresh answer, which is exactly what the browser is waiting
        // for. Verified against node-datachannel before relying on it.
        this.ctx.logger?.info?.("[rcp] offer retransmit — re-answering", {
          sid: sessionId.slice(-8)
        });
        peer.acceptOffer(sdp).catch((err: any) => {
          this.ctx.logger?.warn?.("[rcp] re-answer failed", {
            sid: sessionId.slice(-8),
            err: err?.message || String(err)
          });
        });
        return;
      }

      // Different ice-ufrag ⇒ the browser attempted an ICE RESTART
      // (createOffer({iceRestart:true}) in iceRestart.js), because the
      // network path broke: Wi-Fi roam, NAT mapping aged out, TURN
      // allocation expired.
      //
      // libdatachannel cannot apply new ICE credentials to an existing
      // PeerConnection — it rejects the remote description with "Invalid ICE
      // settings from remote SDP" (verified against node-datachannel). So
      // renegotiating in place is not on the table with this stack.
      //
      // The only way to recover is to throw the peer away and rebuild from
      // the new offer. That works, but it drops the DataChannel — and with
      // it whatever the capability was carrying. Whether that is a good
      // trade depends entirely on WHAT is being carried, so we decide per
      // capability rather than applying one rule to different situations:
      //
      //   rcp.screen — stateless. The stream is a sequence of frames with no
      //     accumulated state; rebuilding costs the operator a brief freeze
      //     and the next keyframe repaints. Recovering silently is strictly
      //     better than dying.
      //
      //   rcp.shell / rcp.file — stateful. A rebuilt channel means a fresh
      //     PTY (losing the working directory, environment, and any
      //     half-typed command) or an aborted transfer. Silently handing the
      //     operator a clean prompt that LOOKS like their old session is
      //     worse than an honest failure, because they may not notice.
      const rebuildable = capability === "rcp.screen";
      this.ctx.logger?.warn?.("[rcp] ICE restart requested", {
        sid: sessionId.slice(-8),
        capability,
        knownUfrag,
        incomingUfrag,
        action: rebuildable ? "rebuilding peer" : "closing session"
      });

      this.sessions.delete(sessionId);
      this.sessionUfrag.delete(sessionId);
      if (!rebuildable) this.pendingIce.delete(sessionId);

      // Await the teardown: the old native PeerConnection still holds its
      // sockets and DataChannel, and building the replacement on top of a
      // half-closed one is how the native layer gets wedged.
      try {
        await peer.dispose(
          rebuildable ? "ice_restart_rebuild" : "ice_restart_unsupported"
        );
      } catch (err: any) {
        this.ctx.logger?.warn?.("[rcp] dispose during ICE restart failed", {
          sid: sessionId.slice(-8),
          err: err?.message || String(err)
        });
      }

      if (!rebuildable) {
        this.sendClose(sessionId, "ice_restart_unsupported");
        return;
      }
      // Fall through: with the session removed, the rest of onOffer builds a
      // fresh peer from this offer exactly as it would for a new session.
      this.ctx.logger?.info?.("[rcp] rebuilding peer for ICE restart", {
        sid: sessionId.slice(-8)
      });
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
    // Una reconstrucción por reinicio de ICE NO vuelve a preguntar: es la
    // misma sesión y la persona ya decidió. Ver `consentGranted`.
    if (requireConsent && this.consentGranted.has(sessionId)) {
      this.ctx.logger?.info?.("[rcp] consentimiento ya concedido en esta sesión; no se repregunta", {
        sid: sessionId.slice(-8)
      });
    } else if (requireConsent) {
      const prompter = this.ctx.consentPrompter ?? failClosedConsentPrompter;
      let decision: ConsentDecision;
      try {
        decision = await prompter.request({
          sessionId,
          capability,
          operator: params?.operatorUserId ? String(params.operatorUserId) : null,
          // ⚠️ NOT `timeoutSeconds`. That is the session's 4-hour hard cap,
          // and passing it here told the dialog to wait four hours for a
          // person to answer "may this stranger see your screen?". Two
          // different questions had been given the same number because both
          // read as "a timeout on this session".
          timeoutSeconds: SESSION_CONSENT_TIMEOUT_S,
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
      this.consentGranted.add(sessionId);
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
      operator,
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
      sendRecordingReady: (r) => this.sendRecordingReady(r),
      onTeardown: (reason) => {
        this.sessions.delete(sessionId);
        this.consentGranted.delete(sessionId);
        this.sendClose(sessionId, reason);
      },
      sessionTimeoutSeconds: timeoutSeconds
    });
    this.ctx.logger?.info?.("[rcp] PeerSession constructed", {
      sid: sessionId.slice(-8)
    });
    this.sessions.set(sessionId, peer);
    const ufrag = extractIceUfrag(sdp);
    if (ufrag) this.sessionUfrag.set(sessionId, ufrag);

    try {
      this.ctx.logger?.info?.("[rcp] acceptOffer starting", {
        sid: sessionId.slice(-8)
      });
      await peer.acceptOffer(sdp);
      this.ctx.logger?.info?.("[rcp] acceptOffer completed", {
        sid: sessionId.slice(-8)
      });
      // Now that the remote description is in place, hand over anything the
      // browser trickled while we were still setting the session up.
      this.drainEarlyIce(sessionId, peer);
    } catch (err: any) {
      this.ctx.logger?.error?.("[rcp] acceptOffer failed", {
        sessionId,
        err: err?.message || String(err),
        stack: err?.stack
      });
      this.sessions.delete(sessionId);
      this.pendingIce.delete(sessionId);
      this.sessionUfrag.delete(sessionId);
      this.sendError(sessionId, "SDP_PARSE_ERROR", err?.message || String(err));
    }
  }

  onIce(params: any): void {
    const sessionId = String(params?.sessionId || "").trim();
    if (!sessionId) return;
    const ice: PendingIce = {
      candidate: String(params?.candidate || ""),
      sdpMid: String(params?.sdpMid || ""),
      sdpMLineIndex: Number(params?.sdpMLineIndex || 0)
    };

    const peer = this.sessions.get(sessionId);
    if (peer) {
      peer.addRemoteIce(ice);
      return;
    }

    // No peer yet. This is NOT necessarily a late candidate for a closed
    // session — the browser starts trickling the moment it calls
    // setLocalDescription, so its first candidates routinely overtake the
    // offer on the way here. Dropping them (which is what this did) made
    // connectivity depend on which message won the race: the same device,
    // network and ICE servers would connect on one attempt and fail with
    // `ice_failed` on the next. That non-determinism is also what made the
    // whole RCP investigation so slow — every measurement was a coin flip.
    //
    // So buffer, and let onOffer drain once the peer exists.
    this.rememberEarlyIce(sessionId, ice);
  }

  /** Hold a candidate that arrived ahead of its offer. Bounded + TTL'd. */
  private rememberEarlyIce(sessionId: string, ice: PendingIce): void {
    this.sweepPendingIce();

    let entry = this.pendingIce.get(sessionId);
    if (!entry) {
      if (this.pendingIce.size >= PENDING_ICE_MAX_SESSIONS) {
        this.ctx.logger?.warn?.("[rcp] early-ice buffer full, dropping", {
          sid: sessionId.slice(-8),
          buffered: this.pendingIce.size
        });
        return;
      }
      entry = { at: Date.now(), items: [] };
      this.pendingIce.set(sessionId, entry);
    }
    if (entry.items.length >= PENDING_ICE_MAX_PER_SESSION) {
      this.ctx.logger?.warn?.("[rcp] early-ice cap reached for session", {
        sid: sessionId.slice(-8)
      });
      return;
    }
    entry.items.push(ice);
    this.ctx.logger?.debug?.("[rcp] buffered early ice", {
      sid: sessionId.slice(-8),
      pending: entry.items.length
    });
  }

  /**
   * Feed the buffered candidates to a freshly-created peer.
   *
   * MUST run after acceptOffer: libdatachannel wants the remote description
   * set before it will accept remote candidates, so draining any earlier
   * would throw them away a second time — with the buffer masking the bug.
   */
  private drainEarlyIce(sessionId: string, peer: PeerSession): void {
    const entry = this.pendingIce.get(sessionId);
    if (!entry) return;
    this.pendingIce.delete(sessionId);
    this.ctx.logger?.info?.("[rcp] draining early ice", {
      sid: sessionId.slice(-8),
      count: entry.items.length
    });
    for (const ice of entry.items) peer.addRemoteIce(ice);
  }

  /** Drop buffers whose offer never arrived. */
  private sweepPendingIce(): void {
    if (this.pendingIce.size === 0) return;
    const cutoff = Date.now() - PENDING_ICE_TTL_MS;
    for (const [sid, entry] of this.pendingIce) {
      if (entry.at < cutoff) this.pendingIce.delete(sid);
    }
  }

  async onClose(params: any): Promise<void> {
    const sessionId = String(params?.sessionId || "").trim();
    this.pendingIce.delete(sessionId);
    const reason = String(params?.reason || "remote_closed");
    const peer = this.sessions.get(sessionId);
    if (!peer) return;
    this.sessions.delete(sessionId);
    this.consentGranted.delete(sessionId);
    await peer.dispose(reason);
  }

  async onError(params: any): Promise<void> {
    const sessionId = String(params?.sessionId || "").trim();
    const code = String(params?.code || "remote_error");
    this.pendingIce.delete(sessionId);
    this.ctx.logger?.warn?.("[rcp] backend reported error", {
      sessionId,
      code,
      message: params?.message
    });
    const peer = this.sessions.get(sessionId);
    if (peer) {
      this.sessions.delete(sessionId);
      this.consentGranted.delete(sessionId);
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

  /**
   * Entrega la clave de una grabación al control plane (ADR-0012).
   *
   * ⚠️ Este mensaje es lo único que separa una grabación de auditoría de un
   * fichero indescifrable. La clave no se persiste en el endpoint, así que si
   * esto no sale, ese vídeo no lo lee nadie nunca — ni nosotros ni el cliente
   * que lo necesite para un incidente.
   *
   * Va por el canal de control, que es el mismo mTLS ya autenticado por el que
   * viaja todo lo demás. El VÍDEO no va por aquí: sube al blob del tenant,
   * aparte, para que quien obtenga el almacenamiento no obtenga también la
   * clave.
   */
  private sendRecordingReady(r: {
    sessionId: string;
    keyBase64: string;
    bytes: number;
    frames: number;
    width: number;
    height: number;
    durationMs: number;
    truncated: boolean;
    stopReason: string;
    sha256: string;
  }): void {
    this.ctx.sendControl?.({ remoteRecordingReady: r });
  }
}
