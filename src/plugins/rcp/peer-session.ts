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
import { createPtySession, type RcpShellSession } from "./pty-session";
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
  /** Operador que abrió la sesión. Vacío en backends antiguos. */
  operator?: string;
  // ICE servers (STUN + TURN) for the agent's own peer connection,
  // extracted from the offer's iceServersJson field. Without them
  // the agent only emits `host` candidates from its NIC, which is
  // unreachable from the operator's browser whenever the agent is
  // behind any NAT. Defaults to [] for backward compat (the legacy
  // STUN-public-only behaviour).
  iceServers: any[];
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
  private pty: RcpShellSession | null = null;
  private transcript: TranscriptBuffer | null = null;
  // rcp.file — file browser / transfer session (M2.S1)
  private fileSession: FileSession | null = null;
  // rcp.screen — screen capture + streaming session (M3.S1)
  private screenSession: ScreenSession | null = null;
  private hardTimer: NodeJS.Timeout | null = null;
  private disposed = false;

  constructor(private readonly args: PeerSessionArgs) {
    const { ctx, sessionId } = args;

    // ICE servers are the SAME Cloudflare-minted creds the browser got
    // back from POST /sessions — backend embeds them in the offer via
    // iceServersJson, session-manager parses them, we receive them here.
    // Both peers MUST have iceServers: each discovers its own candidates
    // independently (the offer's `a=candidate` lines are the BROWSER's
    // candidates, not the agent's). Without these the agent only emits
    // host candidates from its local NIC; if that NIC is on a NAT (any
    // VM, any corp desktop, any cloud workload), ICE gathering yields
    // unreachable addresses and connectivity check fails ~15s in.
    //
    // Format conversion — IMPORTANT:
    // The backend hands us the standard WebRTC RTCIceServer shape:
    //   { urls: ["turn:host:port?transport=udp", ...], username, credential }
    // That's what the browser eats. But `node-datachannel` does NOT accept
    // that shape — it throws "IceServer config error (hostname OR/AND port
    // is not suitable)" the moment you pass it (confirmed empirically on
    // W11-JPR-Lab01 2026-06-10 16:24). Its native API expects:
    //   { hostname: string, port: number, username?, password?, relayType? }
    // OR pre-flattened `turn:user:pass@host:port` URL strings. We go with
    // the object form because Cloudflare's tokens contain characters that
    // would need URL-encoding inside the userinfo portion and that's a
    // footgun for the next reader.
    //
    // We flatten each WebRTC entry's urls[] into one libdatachannel object
    // per URL — that's what libdatachannel expects (one record per network
    // path it should consider). Unparseable URLs are dropped + logged so
    // we never silently degrade to host-only candidates again.
    const rawIceServers = Array.isArray(args.iceServers) ? args.iceServers : [];
    const peerIceServers: any[] = [];
    const droppedUrls: string[] = [];
    for (const s of rawIceServers) {
      const urls: string[] = Array.isArray(s?.urls)
        ? s.urls.filter((u: any) => typeof u === "string")
        : (typeof s?.urls === "string" ? [s.urls] : []);
      const username: string | undefined = typeof s?.username === "string" ? s.username : undefined;
      const credential: string | undefined = typeof s?.credential === "string" ? s.credential : undefined;
      for (const url of urls) {
        // Accept: stun:host:port, turn:host:port[?transport=udp|tcp],
        //         turns:host:port[?transport=tcp]
        const m = /^(stun|turn|turns):([^:?\s]+):(\d+)(?:\?(.*))?$/.exec(url);
        if (!m) {
          droppedUrls.push(url);
          continue;
        }
        const scheme = m[1];
        const hostname = m[2];
        const port = Number(m[3]);
        const query = m[4] || "";
        const entry: any = { hostname, port };
        if (scheme === "turn" || scheme === "turns") {
          if (username) entry.username = username;
          if (credential) entry.password = credential;
          // relayType — node-datachannel enum 'TurnUdp' | 'TurnTcp' | 'TurnTls'
          if (scheme === "turns") {
            entry.relayType = "TurnTls";
          } else {
            const transport = /transport=tcp/i.test(query) ? "TurnTcp" : "TurnUdp";
            entry.relayType = transport;
          }
        }
        peerIceServers.push(entry);
      }
    }
    ctx.logger?.info?.("[rcp] PeerConnection ice config", {
      sid: sessionId.slice(-8),
      rawCount: rawIceServers.length,
      flattenedCount: peerIceServers.length,
      droppedCount: droppedUrls.length,
      // Don't log creds or hostnames in prod logs once stabilised; ok for now
      // because we're still validating the path end-to-end.
      sample: peerIceServers.slice(0, 3).map((e: any) => ({
        hostname: e.hostname,
        port: e.port,
        relayType: e.relayType,
        hasUser: Boolean(e.username),
        hasPass: Boolean(e.password)
      })),
      droppedSample: droppedUrls.slice(0, 3)
    });
    this.peer = new nodeDatachannel.PeerConnection(`rcp-${sessionId}`, {
      iceServers: peerIceServers
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
          this.pty = createPtySession({
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
          const cause = String(err?.message || err || "").trim();
          ctx.logger?.error?.("[rcp] PTY spawn failed at channel open", {
            sessionId,
            shell: process.env.SHELL || null,
            platform: process.platform,
            arch: process.arch,
            err: cause
          });
          // Carry the underlying cause in the close reason, not just the
          // opaque bucket name. The reason reaches the operator's panel and
          // `remote_sessions.close_reason`, so a support engineer can tell
          // "posix_spawnp failed" (node-pty's spawn-helper is missing or not
          // executable for this arch) apart from a missing shell or a bad
          // cwd — without shell access to the endpoint's log. Bounded so a
          // long native error can't bloat the audit column.
          const reason = cause
            ? `pty_spawn_failed: ${cause.slice(0, 120)}`
            : "pty_spawn_failed";
          setImmediate(() => args.onTeardown(reason));
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
          operator: args.operator,
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
    // `setRemoteDescription(sdp, type)` registers the browser's offer.
    //
    // libdatachannel auto-generates the answer the moment setRemoteDescription
    // returns with type="offer" — it fires the onLocalDescription callback
    // we registered in the constructor with the answer SDP. There is NO
    // explicit `setLocalDescription("answer")` call needed; the README of
    // node-datachannel actually shows this pattern (no setLocalDescription
    // at all, just setRemoteDescription on the answerer side).
    //
    // The previous version of this function called
    // `peer.setLocalDescription("answer")` explicitly. Empirically that
    // call hangs forever inside the native code on Windows ARM64 (probably
    // a DTLS init bug in the embedded libdatachannel for that platform) —
    // the entire event loop blocks, no JS error fires, the operator just
    // sees the agent go silent after "setRemoteDescription after". We
    // captured this in TraceniumAgentCore_20260610.out.log lines 414-416:
    // every log up through `setRemoteDescription after` arrives, then
    // nothing. Removing the redundant explicit call sidesteps the bug
    // AND matches the upstream-documented API.
    const sid = this.args.sessionId.slice(-8);
    this.args.ctx.logger?.info?.("[rcp] setRemoteDescription before", {
      sid, sdpLen: remoteSdp.length
    });
    this.peer.setRemoteDescription(remoteSdp, "offer");
    this.args.ctx.logger?.info?.("[rcp] setRemoteDescription after — answer will be emitted via onLocalDescription", { sid });
    // No explicit setLocalDescription — the constructor's onLocalDescription
    // callback fires asynchronously as soon as libdatachannel has the
    // answer prepared. That callback ships the SDP via sendAnswer().
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
