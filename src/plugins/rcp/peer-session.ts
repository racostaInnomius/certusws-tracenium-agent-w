// src/plugins/rcp/peer-session.ts
//
// RCP M3.S1 — one WebRTC peer connection wrapping `node-datachannel`.
//
// Lifecycle:
//   - constructor: builds PeerConnection with empty config.
//   - acceptOffer: sets remote description, generates answer.
//   - addRemoteIce: forwards browser-side candidates to the peer.
//   - dispose: closes the connection and any open DataChannel.
//
// onDataChannel routes to the session type by capability:
//   rcp.shell  → PtySession + TranscriptBuffer  (M1.S2 / M1.S3)
//   rcp.file   → FileSession                    (M2.S1)
//   rcp.screen → ScreenSession                  (M3.S1)

import type { AgentContext } from "../../core/agent-context";
import { PtySession } from "./pty-session";
import { TranscriptBuffer } from "./transcript-buffer";
import { FileSession } from "./file-session";
import type { FileTransferAuditPayload } from "./file-session";
import { ScreenSession } from "./screen-session";
import type { ScreenAuditPayload } from "./screen-session";

// Native module load. This is the historical hotspot for "AgentCore goes
// silent" — `node-datachannel` is a C++ binding around libdatachannel +
// libjuice + OpenSSL, and on some platforms (notably Windows ARM64 ports
// without prebuilt binaries) the .node file loads but crashes the V8
// runtime on first real use (constructing PeerConnection, parsing SDP,
// etc.). When that happens Node dies instantly with no chance to flush
// stdout, write a wedge dump, or run any handler — the process simply
// disappears and WinSW restart-storms until rate-limited to Stopped.
//
// The require itself is bracketed in a try so a load-time failure logs
// clearly instead of taking down the importer chain silently. Runtime
// crashes from inside libdatachannel can still happen later; those need
// to be diagnosed via Event Viewer "Faulting module: node_datachannel.node"
// — see the README troubleshooting section.
//
// eslint-disable-next-line @typescript-eslint/no-var-requires
let nodeDatachannel: any;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  nodeDatachannel = require("node-datachannel");
} catch (err: any) {
  console.error(
    "[FATAL] node-datachannel require() failed — RCP will be non-functional",
    {
      name: err?.name,
      code: err?.code,
      message: err?.message,
      stack: err?.stack
    }
  );
  // Rethrow so the importer knows. session-manager will surface this on
  // the first offer via the dispatcher's catch (now wired with verbose
  // logging from this sprint).
  throw err;
}

type PeerSessionArgs = {
  sessionId: string;
  capability: string;
  ctx: AgentContext;
  sendAnswer: (sdp: string) => void;
  sendIce: (candidate: string, sdpMid: string, sdpMLineIndex: number) => void;
  // M1.S3 — transcript chunk uploader (rcp.shell only).
  sendTranscript: (chunk: {
    stream: "stdout";
    tsDeltaSeconds: number;
    data: string;
    bytesCount: number;
  }) => void;
  // M2.S1 — file transfer audit uploader (rcp.file only).
  sendFileTransferAudit: (audit: FileTransferAuditPayload) => void;
  // M3.S1 — screen share audit uploader (rcp.screen only).
  sendScreenAudit: (audit: ScreenAuditPayload) => void;
  onTeardown: (reason: string) => void;
  sessionTimeoutSeconds: number;
};

export class PeerSession {
  private peer: any;
  // DataChannel established by the OFFERER (browser). We don't
  // create one locally; we wait for `onDataChannel`.
  private dataChannel: any | null = null;
  // rcp.shell — PTY + transcript buffer (M1.S2 / M1.S3)
  private pty: PtySession | null = null;
  private transcript: TranscriptBuffer | null = null;
  // rcp.file — file browser / transfer session (M2.S1)
  private fileSession: FileSession | null = null;
  // rcp.screen — screen capture + streaming session (M3.S1)
  private screenSession: ScreenSession | null = null;
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
      const cap = args.capability;
      ctx.logger?.info?.("[rcp] data channel open", {
        sessionId,
        capability: cap,
        label: dc.getLabel?.()
      });

      // ── rcp.shell — PTY + transcript (M1.S2 / M1.S3) ────────────
      if (cap === "rcp.shell") {
        const sessionStartedAtMs = Date.now();
        this.transcript = new TranscriptBuffer(sessionStartedAtMs, (chunk) => {
          if (this.disposed) return;
          try {
            args.sendTranscript(chunk);
          } catch (err: any) {
            ctx.logger?.warn?.("[rcp] transcript flush failed", {
              sessionId,
              err: err?.message
            });
          }
        });

        try {
          this.pty = new PtySession({
            sessionId,
            ctx,
            send: (text) => {
              if (this.disposed) return;
              try {
                dc.sendMessage(text);
              } catch (err: any) {
                ctx.logger?.warn?.("[rcp] data channel send failed", {
                  sessionId,
                  err: err?.message
                });
              }
              // Tee PTY output into transcript buffer.
              try {
                const parsed = JSON.parse(text);
                if (
                  parsed?.type === "stdout" &&
                  typeof parsed.data === "string"
                ) {
                  this.transcript?.append(parsed.data);
                }
              } catch {
                /* not a recognized JSON envelope — skip */
              }
            },
            onExit: (code, reason) => {
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
          ctx.logger?.info?.("[rcp] shell data channel closed", { sessionId });
          this.pty?.dispose("data_channel_closed");
          this.pty = null;
        });
        return;
      }

      // ── rcp.file — file browser / transfer (M2.S1) ───────────────
      if (cap === "rcp.file") {
        this.fileSession = new FileSession(dc, {
          sessionId,
          ctx,
          sendFileTransferAudit: args.sendFileTransferAudit,
          onTeardown: (reason) => {
            this.fileSession = null;
            if (!this.disposed) args.onTeardown(reason);
          }
        });
        return;
      }

      // ── rcp.screen — screen capture + streaming (M3.S1) ──────────
      if (cap === "rcp.screen") {
        this.screenSession = new ScreenSession(dc, {
          sessionId,
          ctx,
          sendScreenAudit: args.sendScreenAudit,
          onTeardown: (reason) => {
            this.screenSession = null;
            if (!this.disposed) args.onTeardown(reason);
          }
        });
        return;
      }

      // Unknown capability — shouldn't reach here (gated in session-manager)
      ctx.logger?.warn?.("[rcp] unhandled capability on data channel open", {
        sessionId,
        capability: cap
      });
      setImmediate(() => args.onTeardown("unknown_capability"));
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
    // rcp.shell — kill the PTY first, then flush transcript.
    try {
      this.pty?.dispose(reason);
    } catch {
      /* ignore */
    }
    this.pty = null;
    try {
      this.transcript?.dispose();
    } catch {
      /* ignore */
    }
    this.transcript = null;
    // rcp.file — clean up uploads / temp files.
    try {
      this.fileSession?.dispose(reason);
    } catch {
      /* ignore */
    }
    this.fileSession = null;
    // rcp.screen — stop the capture loop.
    try {
      this.screenSession?.dispose(reason);
    } catch {
      /* ignore */
    }
    this.screenSession = null;
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
