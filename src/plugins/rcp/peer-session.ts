// src/plugins/rcp/peer-session.ts
//
// RCP M1 — one WebRTC peer connection wrapping `node-datachannel`.
//
// Lifecycle:
//   - constructor: builds PeerConnection with empty config (ICE
//     servers are inferred from the offer's SDP in M1.S1; M2 wires
//     the agent-side TURN config from policy when we need it).
//   - acceptOffer: sets remote description, generates answer,
//     sends via sendAnswer callback.
//   - addRemoteIce: forwards browser-side candidates to the peer.
//   - dispose: closes the connection and any open DataChannel.
//
// Sprint 1 wired a placeholder echo handler on the DataChannel.
// Sprint 2 replaced it with a real PTY (see pty-session.ts) —
// inbound messages are forwarded as stdin to a spawned shell,
// PTY stdout/stderr come back through the channel.

import type { AgentContext } from "../../core/agent-context";
import { PtySession } from "./pty-session";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const nodeDatachannel = require("node-datachannel");

type PeerSessionArgs = {
  sessionId: string;
  capability: string;
  ctx: AgentContext;
  sendAnswer: (sdp: string) => void;
  sendIce: (candidate: string, sdpMid: string, sdpMLineIndex: number) => void;
  onTeardown: (reason: string) => void;
  sessionTimeoutSeconds: number;
};

export class PeerSession {
  private peer: any;
  // DataChannel established by the OFFERER (browser). We don't
  // create one locally; we wait for `onDataChannel`.
  private dataChannel: any | null = null;
  // PTY allocated when the DataChannel opens (Sprint 2). null
  // until then. We don't spawn the shell at offer time because the
  // browser may abandon mid-handshake — spawning on data-channel
  // open guarantees we only run a shell for a peer that actually
  // connected.
  private pty: PtySession | null = null;
  private hardTimer: NodeJS.Timeout | null = null;
  private disposed = false;

  constructor(private readonly args: PeerSessionArgs) {
    const { ctx, sessionId } = args;

    // M1.S1 — empty iceServers. The browser's offer contains the
    // TURN candidates negotiated client-side; the agent only needs
    // host + reflexive candidates of its own. If a corporate
    // network forces relay-only paths from the agent side, M3 adds
    // an agent-side TURN config.
    this.peer = new nodeDatachannel.PeerConnection(`rcp-${sessionId}`, {
      iceServers: []
    });

    this.peer.onLocalDescription((sdp: string, type: string) => {
      if (this.disposed) return;
      // We only emit our LOCAL "answer" type. Initial offers from
      // browser are the REMOTE description (handled in acceptOffer).
      if (type === "answer") {
        args.sendAnswer(sdp);
      }
    });

    this.peer.onLocalCandidate((candidate: string, sdpMid: string) => {
      if (this.disposed) return;
      // libdatachannel's API exposes sdpMid as a string. mlineIndex
      // isn't directly exposed; we send 0 — modern SDP with a
      // single m= line for data channels matches this. M3 (screen
      // / video tracks) revisits.
      args.sendIce(candidate, sdpMid, 0);
    });

    this.peer.onStateChange((state: string) => {
      ctx.logger?.info?.("[rcp] peer state", { sessionId, state });
      if (state === "failed" || state === "closed") {
        // Schedule teardown — race against an explicit close from
        // either side, so set a flag rather than dispose
        // immediately.
        setImmediate(() => {
          if (this.disposed) return;
          args.onTeardown(state === "failed" ? "ice_failed" : "peer_closed");
        });
      }
    });

    this.peer.onDataChannel((dc: any) => {
      this.dataChannel = dc;
      ctx.logger?.info?.("[rcp] data channel open", {
        sessionId,
        label: dc.getLabel?.()
      });

      // Sprint 2 — allocate the PTY now (not at offer time). If
      // spawning fails (rare: missing shell, OS handle exhaustion)
      // we surface RemoteSessionError + tear down.
      try {
        this.pty = new PtySession({
          sessionId,
          ctx,
          send: (text) => {
            // Defensive: dataChannel might have closed between an
            // onData event and the time we serialize.
            if (this.disposed) return;
            try {
              dc.sendMessage(text);
            } catch (err: any) {
              ctx.logger?.warn?.("[rcp] data channel send failed", {
                sessionId,
                err: err?.message
              });
            }
          },
          onExit: (code, reason) => {
            // Shell terminated. We tear down the peer (which
            // triggers args.onTeardown → SessionManager removes us
            // and sends RemoteSessionClose to backend).
            ctx.logger?.info?.("[rcp] shell exit, scheduling teardown", {
              sessionId,
              code,
              reason
            });
            setImmediate(() => {
              if (this.disposed) return;
              args.onTeardown(reason);
            });
          }
        });
      } catch (err: any) {
        ctx.logger?.error?.("[rcp] PTY spawn failed at channel open", {
          sessionId,
          err: err?.message || String(err)
        });
        setImmediate(() => args.onTeardown("pty_spawn_failed"));
        return;
      }

      dc.onMessage((msg: any) => {
        if (this.disposed || !this.pty) return;
        const text =
          typeof msg === "string"
            ? msg
            : msg && typeof msg === "object" && "toString" in msg
            ? msg.toString()
            : String(msg);
        this.pty.handleMessage(text);
      });

      dc.onClosed(() => {
        ctx.logger?.info?.("[rcp] data channel closed", { sessionId });
        // Browser closed the channel — kill the shell.
        this.pty?.dispose("data_channel_closed");
        this.pty = null;
      });
    });

    // Hard cap timer — even if the operator forgets to close, the
    // session can't outlive this. Triggers a clean teardown that
    // updates the audit row to 'closed'.
    this.hardTimer = setTimeout(() => {
      if (this.disposed) return;
      args.onTeardown("hard_cap_timeout");
    }, args.sessionTimeoutSeconds * 1000);
    // Don't keep the process alive just for this timer.
    (this.hardTimer as any).unref?.();
  }

  async acceptOffer(remoteSdp: string): Promise<void> {
    // `setRemoteDescription(sdp, type)` — node-datachannel uses the
    // raw SDP + type "offer". Once set, calling `setLocalDescription`
    // with type "answer" triggers the onLocalDescription callback
    // with the generated answer.
    this.peer.setRemoteDescription(remoteSdp, "offer");
    this.peer.setLocalDescription("answer");
  }

  addRemoteIce(ice: {
    candidate: string;
    sdpMid: string;
    sdpMLineIndex: number;
  }): void {
    if (this.disposed) return;
    try {
      this.peer.addRemoteCandidate(ice.candidate, ice.sdpMid);
    } catch (err: any) {
      this.args.ctx.logger?.warn?.("[rcp] addRemoteCandidate failed", {
        sessionId: this.args.sessionId,
        err: err?.message
      });
    }
  }

  async dispose(reason: string): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    if (this.hardTimer) {
      clearTimeout(this.hardTimer);
      this.hardTimer = null;
    }
    // Kill the shell BEFORE tearing down the channel — gives the
    // PTY's exit handler a moment to fire and queue its final
    // 'exit' message, even if the data channel races ahead.
    try {
      this.pty?.dispose(reason);
    } catch {
      /* ignore */
    }
    this.pty = null;
    try {
      this.dataChannel?.close?.();
    } catch {
      /* ignore */
    }
    try {
      this.peer?.close?.();
    } catch {
      /* ignore */
    }
    this.args.ctx.logger?.info?.("[rcp] session disposed", {
      sessionId: this.args.sessionId,
      reason
    });
  }
}
