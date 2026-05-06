import crypto from "crypto";
import path from "path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { loadInstalledIdentity } from "./crypto-store";
import type { PrivSvcRequest, PrivSvcResponse, PushSink } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const PROTO_PATH = path.resolve(__dirname, "../proto/controlplane.proto");

// gRPC channel keepalive — forces the runtime to detect dead TCP
// connections (e.g. Wi-Fi dropped and reconnected) by pinging the server
// regardless of outbound traffic. Without these, the channel can stay in
// a "zombie" state for hours with no way to tell the link is dead.
//
// Note: in production we've seen cases where the @grpc/grpc-js HTTP/2
// keepalive doesn't fire reliably after sleep/wake or ungraceful
// backend restarts (SIGKILL, OOM). The application-level watchdog
// below — see WATCHDOG_INTERVAL_MS / DEAD_STREAM_THRESHOLD_MS — is
// the safety net for those cases. Same approach the Windows
// (Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs) bridge uses, with
// matching numbers (15s tick, 150s threshold).
const CHANNEL_OPTIONS: grpc.ChannelOptions = {
  "grpc.keepalive_time_ms": 30_000,            // send a ping every 30s
  "grpc.keepalive_timeout_ms": 10_000,         // fail if no pong in 10s
  "grpc.keepalive_permit_without_calls": 1,    // ping even with no RPCs
  "grpc.http2.max_pings_without_data": 0,      // unlimited idle pings
  "grpc.http2.min_time_between_pings_ms": 30_000,
  "grpc.http2.min_ping_interval_without_data_ms": 30_000
};

// Application-level dead-stream watchdog. Polls every WATCHDOG_INTERVAL_MS
// the wall-clock gap between "now" and the most recent server activity;
// if that gap crosses DEAD_STREAM_THRESHOLD_MS the bridge declares the
// stream zombie, emits a `grpc.control.deadStream` push so the agent can
// log the event with full timing, and tears down → reconnect.
//
// Threshold rationale (mirror of Windows' settings):
//   * Server sends `ping` every 90s (controlplane.ts HEARTBEAT_INTERVAL_MS).
//   * 150s = 1× ping + ~60s grace for jitter/network blips. A genuinely
//     idle but healthy stream still shows activity well under that.
//   * 15s tick keeps detection latency bounded — worst case
//     ~150 + 15 = 165s.
const WATCHDOG_INTERVAL_MS = 15_000;
const DEAD_STREAM_THRESHOLD_MS = 150_000;

// ── Self-restart circuit breaker ──────────────────────────────────────
//
// Last-resort safety net for the case where every other recovery path
// has failed: the watchdog tore the bridge down, the agent-core asked
// us to reconnect, but the reconnect attempts have been failing back
// to back for too long. Without this, the privsvc just spins forever
// emitting `grpc.connect_failed` while the agent assumes someone else
// will fix it — none of the higher layers will, because launchd thinks
// the daemon is healthy (the process is running fine) and the agent
// has no authority to restart privsvc.
//
// Mechanics:
//   * `lastSuccessfulConnectAtMs` is stamped on every successful
//     `state.connected = true` (i.e. once HELLO has been written and
//     the bridge believes the stream is live).
//   * A `setInterval` checks every BREAKER_TICK_MS whether we've gone
//     longer than BREAKER_THRESHOLD_MS WITHOUT being connected. If so,
//     `process.exit(1)`. launchd's KeepAlive=true relaunches us
//     immediately, which gets us a fresh process, fresh gRPC client,
//     fresh TLS handshake — the nuclear option that always works.
//
// Why 5 minutes:
//   * A healthy reconnect cycle takes <30s end-to-end (DNS, TLS, HELLO).
//   * Sleep/wake reconnects we've measured top out at ~90s (network
//     stack settling).
//   * 5 min is long enough that no normal operation trips it, short
//     enough that an operator opening a zombie laptop sees the device
//     come back inside coffee-break time.
//   * NEVER trip during initial boot before any agent has ever talked
//     to us — see `everConnected` guard below. We don't want a daemon
//     that's been freshly installed (and is correctly waiting for the
//     agent to call `grpc.connect`) to suicide every 5 minutes.
const BREAKER_TICK_MS = 30_000;
const BREAKER_THRESHOLD_MS = 5 * 60 * 1000;

type BridgeState = {
  client?: any;
  call?: grpc.ClientDuplexStream<any, any>;
  push?: PushSink;
  connected: boolean;
  connecting: boolean;
  tenantId?: string;
  deviceId?: string;
  target?: string;
  chunks: Map<string, {
    totalChunks: number;
    chunks: string[];
    createdAt: number;
    // Namespace metadata from the first chunk is preserved across
    // reassembly so the final Facts frame has the same `namespace` /
    // `namespaces` fields it would if the payload had fit in one
    // message. agent-core sends these in every chunk request but we
    // only store them on first arrival; the backend validator wants
    // them in the single reassembled `facts` frame.
    namespace: string;
    namespaces: string[];
  }>;
  channelWatchGen: number;
  // Dead-stream watchdog state. Set on connection start, updated on
  // every recv/send, used by watchdogTick() to detect zombies.
  connectedAtMs?: number;
  lastReceiveAtMs?: number;
  lastSendAtMs?: number;
  watchdogTimer?: NodeJS.Timeout | null;
  // Self-restart circuit breaker state. `lastSuccessfulConnectAtMs`
  // stamps the wall-clock of the most recent HELLO that brought us to
  // `connected=true`. `lastDisconnectedAtMs` stamps the moment we
  // most recently transitioned from connected → disconnected; the
  // breaker measures time-since-disconnect (NOT time-since-last-
  // connect — Patch I fix). `everConnected` flips once and stays —
  // used to suppress the breaker on first-boot when no agent has
  // ever asked us to connect yet.
  lastSuccessfulConnectAtMs?: number;
  lastDisconnectedAtMs?: number;
  everConnected: boolean;
  breakerTimer?: NodeJS.Timeout | null;
};

const state: BridgeState = {
  connected: false,
  connecting: false,
  chunks: new Map(),
  channelWatchGen: 0,
  watchdogTimer: null,
  everConnected: false,
  breakerTimer: null
};

// Self-restart circuit breaker — armed at module load. We arm it
// unconditionally (not from startConnection) because a daemon that
// has been up >5 min in the "never even connected once" state is
// already worth investigating; but we GATE the actual exit() on
// `everConnected`, so a fresh install or a daemon that's correctly
// idling waiting for agent-core to come up doesn't suicide.
//
// .unref() so the timer doesn't keep the daemon alive on shutdown.
function tripBreaker(reason: string, details: Record<string, any>) {
  logger.error("grpc_bridge_circuit_breaker_tripped", { reason, ...details });
  try {
    state.push?.({
      v: 1,
      method: "grpc.control.daemonExit",
      params: { reason, ...details },
      meta: {
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        connectionId: state.target
      }
    });
  } catch {}
  // Slightly longer flush window than the 100ms we had before. With
  // stdout still occasionally block-buffered we want the launchd
  // FD inheritance + the IPC pipe BOTH to drain before we exit.
  setTimeout(() => process.exit(1), 250).unref?.();
}

function tickBreaker() {
  if (!state.everConnected) return; // first-boot safety: see comment above

  // ── Case 1: classically disconnected too long ────────────────────
  // Agent has been trying to reconnect (with backoff) and not getting
  // through. We trip if the gap since the disconnect itself exceeds
  // the threshold.
  //
  // Patch I (May 2026 incident, follow-up to Patch E): we used to
  // measure `now - lastSuccessfulConnectAtMs`, which is the wall-
  // clock since the last HELLO succeeded. That's wrong: a healthy
  // 30-minute connection that just dropped a moment ago would show
  // `idleMs=30min` and trip the breaker INSTANTLY, before the
  // agent's exponential-backoff reconnect even gets a chance to
  // retry. The metric we actually care about is "how long have we
  // been DISCONNECTED" — which is `now - lastDisconnectedAtMs`.
  // `lastDisconnectedAtMs` is stamped by teardownBridge() at the
  // moment connected flips true → false, so on a brand-new drop
  // it's ~0ms and we (correctly) leave the agent's reconnect loop
  // alone. Only if the agent stays unable to reconnect for the full
  // BREAKER_THRESHOLD_MS do we relaunch the daemon.
  if (!state.connected) {
    const lastDisc = state.lastDisconnectedAtMs ?? 0;
    if (lastDisc === 0) return; // never disconnected: nothing to measure
    const idleMs = Date.now() - lastDisc;
    if (idleMs < BREAKER_THRESHOLD_MS) return;
    tripBreaker("disconnected_too_long", {
      idleMs,
      thresholdMs: BREAKER_THRESHOLD_MS,
      lastDisconnectedAtUtc: new Date(lastDisc).toISOString(),
      lastSuccessfulConnectAtUtc: state.lastSuccessfulConnectAtMs
        ? new Date(state.lastSuccessfulConnectAtMs).toISOString()
        : null,
    });
    return;
  }

  // ── Case 2: ZOMBIE — connected=true but no recv activity ────────
  // Patch E (post real-world incident, May 2026): a TCP that goes
  // half-open after the backend SIGKILLs / network partition can leave
  // `state.connected === true` indefinitely on this side. The bridge
  // watchdog (DEAD_STREAM_THRESHOLD_MS = 150s) was supposed to catch
  // this, but in practice it MISSED the case (suspected stdout block-
  // buffering hiding the teardown log + a still-not-fully-explained
  // condition where lastReceiveAtMs/lastSendAtMs stayed fresh). The
  // breaker is the last line of defence: if we go BREAKER_THRESHOLD_MS
  // without hearing ONE thing back from the server (server pings
  // every 90s, so `lastReceiveAtMs` should normally never be more
  // than ~95s old on a healthy stream), tear the daemon down so
  // launchd hands us a fresh process with a fresh socket.
  //
  // We DELIBERATELY use lastReceiveAtMs only — not lastSendAtMs —
  // because the agent could be sending heartbeats into a dead TCP
  // forever (kernel buffer accepts, server never reads), keeping
  // lastSendAtMs deceptively fresh. The only real liveness signal
  // is "the server actually said something to us recently".
  const lastRecv = state.lastReceiveAtMs ?? state.connectedAtMs ?? 0;
  if (lastRecv === 0) return;
  const silentMs = Date.now() - lastRecv;
  if (silentMs < BREAKER_THRESHOLD_MS) return;

  tripBreaker("connected_but_silent", {
    silentMs,
    thresholdMs: BREAKER_THRESHOLD_MS,
    lastReceiveAtUtc: new Date(lastRecv).toISOString(),
    note: "TCP half-open suspected — bridge watchdog should have caught this earlier",
  });
}

const breakerInterval = setInterval(tickBreaker, BREAKER_TICK_MS);
breakerInterval.unref?.();
state.breakerTimer = breakerInterval;

// Incomplete chunked FACTS uploads are kept in `state.chunks` until the final
// piece arrives. If the agent dies or the network drops between chunks, the
// Map would leak forever. A stale entry 5 minutes old is almost certainly
// abandoned (the agent's outbox will resend with a fresh eventId on retry).
const CHUNK_TTL_MS = 5 * 60 * 1000;
const CHUNK_SWEEP_INTERVAL_MS = 60 * 1000;

// Hard caps on chunked payload reassembly. Without these, a misbehaving
// (or compromised) agent-core caller could claim `totalChunks=10_000_000`
// and force us to allocate a 10M-slot array before any sweep runs.
//
// Real inventory payloads currently hit ~200KB, chunked at 48KB each, so
// 32 chunks × 64KB = 2 MB ceiling is generous headroom without being
// abusable. Anything above this is a bug or an attack.
const MAX_CHUNKS_PER_MESSAGE = 64;
const MAX_CHUNK_BYTES = 64 * 1024;

// Cap on decoded control-plane payloads (runJob.payloadJson,
// policyUpdate.policyJson). If the server is compromised it could push an
// arbitrarily large policy blob that we'd buffer in memory + serialize to
// IPC + re-buffer agent-side. 256 KB is plenty for any realistic policy.
const MAX_CONTROL_PAYLOAD_BYTES = 256 * 1024;

function sweepStaleChunks() {
  const now = Date.now();
  for (const [eventId, entry] of state.chunks) {
    if (now - entry.createdAt > CHUNK_TTL_MS) {
      state.chunks.delete(eventId);
      logger.warn("chunk_expired", {
        eventId,
        ageMs: now - entry.createdAt,
        chunksReceived: entry.chunks.filter((c) => c.length > 0).length,
        totalChunks: entry.totalChunks
      });
    }
  }
}

const chunkSweeper = setInterval(sweepStaleChunks, CHUNK_SWEEP_INTERVAL_MS);
chunkSweeper.unref();

// ── Dead-stream watchdog (paridad con Windows GrpcBridge.cs) ─────────
//
// The Windows bridge has had this since day one and it's been catching
// zombies in production. Mirroring the same shape here so macOS doesn't
// rely solely on @grpc/grpc-js HTTP/2 keepalive (which has known
// reliability issues post sleep/wake or ungraceful backend SIGKILL).
//
// Lifecycle:
//   * startWatchdog() — armed at the end of startConnection() once the
//     stream is live. setInterval, unref'd so it doesn't keep the
//     daemon alive on shutdown.
//   * watchdogTick() — fires every WATCHDOG_INTERVAL_MS, computes the
//     gap since the last meaningful event (recv / send / connectedAt),
//     and if it exceeds DEAD_STREAM_THRESHOLD_MS:
//       1. Pushes `grpc.control.deadStream` so the agent logs full
//          timing context BEFORE the disconnect — operator can grep
//          this in the agent log to confirm the zombie path triggered.
//       2. Calls teardownBridge("dead_stream_watchdog") which already
//          handles the cancel/cleanup/grpc.disconnected push.
//       3. Returns. The agent's normal reconnect loop takes over.
//   * stopWatchdog() — invoked from teardownBridge to make absolutely
//     sure we don't leak the timer across reconnect cycles.
function stopWatchdog() {
  if (state.watchdogTimer) {
    try { clearInterval(state.watchdogTimer); } catch {}
    state.watchdogTimer = null;
  }
}

function startWatchdog() {
  // Belt-and-suspenders: clear any existing timer before arming a new
  // one. teardownBridge already calls stopWatchdog, but a future code
  // path that calls startWatchdog twice in a row shouldn't leak.
  stopWatchdog();

  state.watchdogTimer = setInterval(() => {
    if (!state.connected || !state.call) return;

    const now = Date.now();
    const lastActivity = Math.max(
      state.lastReceiveAtMs ?? 0,
      state.lastSendAtMs ?? 0,
      state.connectedAtMs ?? 0
    );

    if (lastActivity === 0) return; // not yet established
    const silentMs = now - lastActivity;
    if (silentMs <= DEAD_STREAM_THRESHOLD_MS) return;

    const details = {
      silentMs,
      thresholdMs: DEAD_STREAM_THRESHOLD_MS,
      connectedAtUtc: state.connectedAtMs
        ? new Date(state.connectedAtMs).toISOString()
        : null,
      lastReceiveUtc: state.lastReceiveAtMs
        ? new Date(state.lastReceiveAtMs).toISOString()
        : null,
      lastSendUtc: state.lastSendAtMs
        ? new Date(state.lastSendAtMs).toISOString()
        : null
    };

    logger.warn("grpc_bridge_dead_stream_detected", details);

    // Match the Windows wire shape — agent already understands this
    // method (handled in grpc-client.ts as a soft failure signal).
    try {
      state.push?.({
        v: 1,
        method: "grpc.control.deadStream",
        params: details,
        meta: {
          tenantId: state.tenantId,
          deviceId: state.deviceId,
          connectionId: state.target
        }
      });
    } catch {}

    teardownBridge("dead_stream_watchdog", details);
  }, WATCHDOG_INTERVAL_MS);

  // Don't keep the privsvc process alive on shutdown just for the
  // watchdog tick.
  state.watchdogTimer.unref?.();
}

// Collapse all "tear down the current channel/stream" paths into one helper
// so every transport-level failure ends the same way: no stale client/call
// references, no stuck flags, and a single `grpc.disconnected` push so the
// agent can trigger its reconnect loop.
function teardownBridge(reason: string, details?: Record<string, any>) {
  const wasConnected = state.connected || state.connecting;
  state.connected = false;
  state.connecting = false;

  // Patch I — stamp the disconnect moment for the breaker. We only
  // stamp on the FIRST teardown after a connect (i.e. when wasConnected
  // was true); otherwise back-to-back teardowns from the same dropped
  // session would push the timestamp forward and mask a real "stuck
  // disconnected" state.
  if (wasConnected) {
    state.lastDisconnectedAtMs = Date.now();
  }

  // Bump the watch generation so any older watcher callback that fires
  // after this point is ignored.
  state.channelWatchGen += 1;

  // Stop the watchdog before tearing call/client. Otherwise it could
  // tick once between us setting connected=false and clearing the
  // timer, and (because we still have the stale lastActivity stamps)
  // emit a spurious "dead_stream_watchdog" alongside whatever real
  // reason actually triggered teardown.
  stopWatchdog();
  state.connectedAtMs = undefined;
  state.lastReceiveAtMs = undefined;
  state.lastSendAtMs = undefined;

  const call = state.call;
  state.call = undefined;
  if (call) {
    // Remove the original error/end/close handlers first so they don't
    // re-enter teardownBridge when we cancel the stream below. THEN
    // attach a no-op error listener, otherwise `cancel()` emits an
    // 'error' event with code 1 CANCELLED that becomes an
    // "Unhandled 'error' event" and tears the entire daemon down.
    try { call.removeAllListeners("error"); } catch {}
    try { call.removeAllListeners("end"); } catch {}
    try { call.removeAllListeners("close"); } catch {}
    try { call.removeAllListeners("data"); } catch {}
    try { call.on("error", () => {}); } catch {}
    try { (call as any).cancel?.(); } catch {}
    try { call.end(); } catch {}
  }

  const client = state.client;
  state.client = undefined;
  if (client) {
    try { client.close?.(); } catch {}
  }

  if (wasConnected) {
    logger.warn("grpc_bridge_teardown", { reason, ...(details || {}) });
    try {
      state.push?.({
        v: 1,
        method: "grpc.disconnected",
        params: { manual: reason === "manual_close", reason, atUtc: new Date().toISOString() },
        meta: {
          tenantId: state.tenantId,
          deviceId: state.deviceId,
          connectionId: state.target
        }
      });
    } catch {}
  }
}

function loadControlPlaneClient() {
  const def = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true
  });
  const pkg = grpc.loadPackageDefinition(def) as any;
  return pkg.tracenium.control.ControlPlane;
}

function normalizeTarget(value: string) {
  const target = String(value || "").trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  if (!target) throw new Error("target_required");
  return target;
}

function push(method: string, params?: Record<string, any>) {
  try {
    state.push?.({
      v: 1,
      method,
      params: params || {},
      meta: {
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        connectionId: state.target
      }
    });
  } catch (err: any) {
    logger.warn("push_failed", { method, error: err?.message || String(err) });
  }
}

function decodeBytes(value: any): string {
  if (!value) return "";
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf8");
  return String(value);
}

/**
 * Classify a gRPC client error into a safe, stable tag suitable for
 * IPC and logs.
 *
 * Raw `err.message` strings from @grpc/grpc-js regularly include peer
 * details that we don't want flowing across the IPC boundary or into
 * logs that may be shipped off-host:
 *
 *   "14 UNAVAILABLE: Connection refused. Host: grpc.tracenium.com:50051"
 *   "16 UNAUTHENTICATED: TLS handshake failed: unable to verify the
 *    first certificate"
 *   "14 UNAVAILABLE: read ECONNRESET from 203.0.113.42:50051"
 *
 * Hostnames, peer IPs, and TLS details give an attacker who's scraping
 * logs information about the backend topology. The status code + a
 * short category is enough for the agent to react (reconnect vs. fatal)
 * without leaking anything.
 */
function classifyGrpcError(err: any): { code: number | null; tag: string } {
  const code = typeof err?.code === "number" ? err.code : null;

  // Map of grpc.status codes to stable tags. Not exhaustive — anything
  // unknown collapses to "error".
  const byCode: Record<number, string> = {
    1: "cancelled",
    2: "unknown",
    3: "invalid_argument",
    4: "deadline_exceeded",
    5: "not_found",
    6: "already_exists",
    7: "permission_denied",
    8: "resource_exhausted",
    9: "failed_precondition",
    10: "aborted",
    11: "out_of_range",
    12: "unimplemented",
    13: "internal",
    14: "unavailable",
    15: "data_loss",
    16: "unauthenticated"
  };

  const tag = code != null && byCode[code] ? byCode[code] : "error";
  return { code, tag };
}

/**
 * Decode a control-plane bytes field and enforce MAX_CONTROL_PAYLOAD_BYTES.
 *
 * The gRPC server is the trust boundary; a compromised server could push a
 * multi-MB `policyJson` or `runJob.payloadJson` that we'd then buffer in
 * memory, serialise over IPC, and re-buffer on agent-core. This function
 * hard-caps the decoded size and emits a warn so an operator can notice.
 * We return the truncated string (rather than throwing) because the
 * agent-core parse step will reject invalid JSON, which is a clearer
 * failure mode than tearing down the whole gRPC stream.
 */
function decodeBoundedBytes(value: any, fieldName: string): string {
  const decoded = decodeBytes(value);
  if (decoded.length > MAX_CONTROL_PAYLOAD_BYTES) {
    logger.warn("control_payload_truncated", {
      field: fieldName,
      bytes: decoded.length,
      cap: MAX_CONTROL_PAYLOAD_BYTES
    });
    return decoded.slice(0, MAX_CONTROL_PAYLOAD_BYTES);
  }
  return decoded;
}

function handleControlMessage(msg: any) {
  // Liveness signal for the watchdog: any message from the server,
  // including `ping` (which intentionally has no specific handler
  // below), counts as activity. Stamp BEFORE the per-method dispatch
  // so a future new message type doesn't accidentally bypass us.
  state.lastReceiveAtMs = Date.now();

  if (msg.ack) {
    push("grpc.ack", {
      eventId: String(msg.ack.eventId || ""),
      status: Number(msg.ack.status ?? 0),
      message: String(msg.ack.message || ""),
      receivedAtUtc: msg.ack.receivedAtUtc || new Date().toISOString(),
      serverTimeUtc: msg.ack.serverTimeUtc || undefined
    });
    return;
  }

  if (msg.runJob) {
    push("grpc.control.runJob", {
      jobId: String(msg.runJob.jobId || ""),
      jobType: String(msg.runJob.jobType || ""),
      payloadJson: decodeBoundedBytes(msg.runJob.payloadJson, "runJob.payloadJson"),
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.rotateCert) {
    push("grpc.control.rotateCert", {
      reason: msg.rotateCert.reason || "server_request",
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.policyUpdate) {
    push("grpc.control.policyUpdate", {
      eventId: msg.policyUpdate.eventId || "",
      policyVersion: msg.policyUpdate.policyVersion || "",
      policyJson: decodeBoundedBytes(msg.policyUpdate.policyJson, "policyUpdate.policyJson"),
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.disconnect) {
    push("grpc.control.disconnect", {
      reason: msg.disconnect.reason || "server_request",
      receivedAtUtc: new Date().toISOString()
    });
    return;
  }

  if (msg.agentUpdate) {
    push("grpc.control.agentUpdate", {
      jobId: msg.agentUpdate.jobId || "",
      version: msg.agentUpdate.version || "",
      receivedAtUtc: new Date().toISOString()
    });
  }
}

function write(msg: any): Promise<void> {
  return new Promise((resolve, reject) => {
    const call = state.call;
    if (!call || state.connected !== true) {
      reject(new Error("grpc_not_connected"));
      return;
    }

    call.write(msg, (err: Error | null | undefined) => {
      if (err) reject(err);
      else {
        // Liveness signal for the watchdog. Heartbeats and FACTS
        // routes both go through here, so this is enough to mark
        // "the agent thinks the stream is alive enough to write".
        state.lastSendAtMs = Date.now();
        resolve();
      }
    });
  });
}

function watchChannelState(client: any, generation: number) {
  const channel: grpc.Channel | undefined = client?.getChannel?.();
  if (!channel) return;

  const check = () => {
    // If our generation is stale (a teardown happened), stop watching.
    if (state.channelWatchGen !== generation) return;

    let current: grpc.connectivityState;
    try {
      current = channel.getConnectivityState(false);
    } catch {
      return;
    }

    // TRANSIENT_FAILURE means the gRPC runtime tried to keep the
    // connection alive (via keepalive pings) and failed — this is the
    // signal we want to act on when the network drops.
    if (
      current === grpc.connectivityState.TRANSIENT_FAILURE ||
      current === grpc.connectivityState.SHUTDOWN
    ) {
      teardownBridge("channel_transient_failure", { state: current });
      return;
    }

    // Re-arm the watch for the next state change. Deadline 5 min from now —
    // the callback fires immediately on state change OR when the deadline
    // elapses (which means we simply re-arm).
    const deadline = new Date(Date.now() + 5 * 60 * 1000);
    try {
      channel.watchConnectivityState(current, deadline, (err) => {
        if (state.channelWatchGen !== generation) return;
        if (err) {
          // Deadline passed with no state change — keep watching.
          check();
          return;
        }
        check();
      });
    } catch {
      // Channel closed. Leave teardown to the error/end handlers.
    }
  };

  check();
}

async function startConnection(params: Record<string, any>, pushSink: PushSink) {
  if (state.connected || state.connecting) return;

  // Defensive cleanup: if an earlier teardown left any reference behind
  // (shouldn't, but cheap insurance), make sure we start fresh.
  if (state.call || state.client) {
    teardownBridge("pre_connect_cleanup");
  }

  state.connecting = true;
  state.push = pushSink;
  state.tenantId = String(params.tenantId || "");
  state.deviceId = String(params.deviceId || "");
  state.target = normalizeTarget(params.target);

  if (!state.tenantId || !state.deviceId) {
    state.connecting = false;
    throw new Error("tenantId_deviceId_required");
  }

  try {
    const identity = loadInstalledIdentity();
    const creds = grpc.credentials.createSsl(
      identity.caBundle,
      identity.clientKey,
      identity.clientCert
    );

    const ControlPlane = loadControlPlaneClient();
    state.client = new ControlPlane(state.target, creds, CHANNEL_OPTIONS);
    const call = state.client.Connect() as grpc.ClientDuplexStream<any, any>;
    state.call = call;

    // Bump generation so any previous watcher callback that might still
    // fire is ignored by watchChannelState.
    state.channelWatchGen += 1;
    const generation = state.channelWatchGen;

    call.on("data", handleControlMessage);
    call.on("error", (err: any) => {
      const classified = classifyGrpcError(err);
      // Keep the full message in the privsvc's own log (stays on this
      // host, root-owned, never leaves). DO NOT put it in the push
      // payload — that crosses the IPC boundary to agent-core, and from
      // there potentially into telemetry shippers.
      logger.error("grpc_stream_error", {
        code: classified.code,
        tag: classified.tag,
        error: err?.message || String(err)
      });
      push("grpc.control.streamClosed", {
        reason: classified.tag,
        code: classified.code,
        atUtc: new Date().toISOString()
      });
      teardownBridge("stream_error", {
        code: classified.code,
        tag: classified.tag
      });
    });
    call.on("end", () => {
      teardownBridge("stream_end");
    });
    call.on("close", () => {
      teardownBridge("stream_close");
    });

    const eventId = crypto.randomUUID().replace(/-/g, "");
    call.write({
      traceId: eventId,
      hello: {
        eventId,
        tenantId: state.tenantId,
        deviceId: state.deviceId,
        agentVersion: String(params.agentVersion || ""),
        protocolVersion: "1",
        policyVersion: String(params.policyVersion || ""),
        capabilities: ["amp"]
      }
    });

    state.connected = true;
    state.connectedAtMs = Date.now();
    // Seed both stamps to "now" so the watchdog has a reasonable
    // baseline before the first server ping or our first heartbeat.
    state.lastReceiveAtMs = state.connectedAtMs;
    state.lastSendAtMs = state.connectedAtMs;
    // Stamp the circuit breaker's "we have been alive at least once"
    // baseline. From here on, going >BREAKER_THRESHOLD_MS without
    // returning to this code path will trip the breaker.
    state.lastSuccessfulConnectAtMs = state.connectedAtMs;
    state.everConnected = true;
    // Patch I — once we're freshly connected, clear the disconnect
    // stamp. The breaker should only measure time-since-CURRENT-
    // disconnect, not time-since-some-drop-an-hour-ago that we long
    // since recovered from.
    state.lastDisconnectedAtMs = undefined;
    push("grpc.connected", {
      ready: true,
      target: state.target,
      atUtc: new Date().toISOString()
    });

    // Start watching the channel state so network drops surface quickly.
    watchChannelState(state.client, generation);

    // Application-level dead-stream watchdog. Last line of defence in
    // case the @grpc/grpc-js HTTP/2 keepalive doesn't fire after
    // sleep/wake or an ungraceful backend SIGKILL — we've seen Macs
    // sit zombie for hours otherwise. Mirrors what the Windows
    // bridge does.
    startWatchdog();
  } finally {
    state.connecting = false;
  }
}

export async function handleGrpcConnect(req: PrivSvcRequest, pushSink: PushSink): Promise<PrivSvcResponse> {
  try {
    await startConnection(req.params || {}, pushSink);
    return success(req.id, {
      connected: true,
      ready: true,
      target: state.target
    });
  } catch (err: any) {
    // Keep the raw message local (privsvc log is root-owned on this
    // host). Respond to the agent with a classified tag only, so peer
    // / SNI / TLS details don't cross the IPC boundary and later end
    // up in whatever the agent's logger ships to.
    const classified = classifyGrpcError(err);
    logger.error("grpc_connect_failed", {
      code: classified.code,
      tag: classified.tag,
      error: err?.message || String(err)
    });
    return fail(req.id, "grpc_connect_failed", classified.tag);
  }
}

export async function handleFactsSend(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const eventId = String(req.params?.eventId || "");
    const payloadJson = String(req.params?.payloadJson || "{}");
    if (!eventId) return fail(req.id, "bad_request", "eventId required");

    // --- Regression fix (macOS contract parity with Windows) ---
    //
    // The Facts proto has four relevant fields:
    //   string eventId = 1;
    //   bytes  payloadJson = 2;
    //   string deviceId = 3;
    //   string namespace = 4;
    //   repeated string namespaces = 5;
    //
    // The backend's validator (controlplane.ts `validateFactsEnvelope`)
    // REQUIRES `facts.namespaces` to be a non-empty string[] that also
    // matches the keys inside payloadJson.namespaces. If we don't set
    // it, gRPC-js serialises `namespaces` as `[]` (the default for
    // `repeated string`), the backend runs `normalizeWireNamespaces([])`
    // → `[]`, and rejects with:
    //
    //   status: 2, message: "missing facts.namespaces"
    //
    // Windows PrivSvc (IpcGrpcHandlers.cs → GrpcBridge.SendFacts) does
    // forward these fields. macOS did not, so every FACTS_SNAPSHOT from
    // a Mac was silently rejected post-ACK. agent-core does mark these
    // as FAILED in the outbox, which means new snapshots never land on
    // the backend and the device's row stays frozen at whatever version
    // last succeeded (typically before we shipped the macOS PrivSvc).
    const factNamespace = String(req.params?.namespace || "");
    const rawNamespaces = req.params?.namespaces;
    const factNamespaces = Array.isArray(rawNamespaces)
      ? rawNamespaces.filter((ns: unknown) => typeof ns === "string" && ns.length > 0) as string[]
      : [];

    await write({
      traceId: eventId,
      facts: {
        eventId,
        deviceId: state.deviceId || "",
        namespace: factNamespace,
        namespaces: factNamespaces,
        payloadJson: Buffer.from(payloadJson, "utf8")
      }
    });

    return success(req.id, { accepted: true, eventId });
  } catch (err: any) {
    return fail(req.id, "facts_send_failed", err?.message || String(err));
  }
}

export async function handleFactsChunk(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const params = req.params || {};
  const eventId = String(params.eventId || "");
  const chunkIndex = Number(params.chunkIndex);
  const totalChunks = Number(params.totalChunks);
  const payloadChunk = String(params.payloadChunk || "");

  if (!eventId || !Number.isInteger(chunkIndex) || !Number.isInteger(totalChunks) || totalChunks <= 0) {
    return fail(req.id, "bad_request", "invalid chunk parameters");
  }

  // Reject absurd totalChunks BEFORE allocating the array. Without this a
  // buggy caller could request a 10M-slot allocation that fills memory
  // before the sweeper gets a chance to GC it.
  if (totalChunks > MAX_CHUNKS_PER_MESSAGE) {
    logger.warn("chunks_rejected_too_many", { eventId, totalChunks, cap: MAX_CHUNKS_PER_MESSAGE });
    return fail(req.id, "bad_request", `totalChunks ${totalChunks} exceeds cap ${MAX_CHUNKS_PER_MESSAGE}`);
  }

  if (chunkIndex < 0 || chunkIndex >= totalChunks) {
    return fail(req.id, "bad_request", `chunkIndex ${chunkIndex} out of range`);
  }

  if (payloadChunk.length > MAX_CHUNK_BYTES) {
    logger.warn("chunk_rejected_too_large", { eventId, chunkIndex, bytes: payloadChunk.length, cap: MAX_CHUNK_BYTES });
    return fail(req.id, "bad_request", `chunk size ${payloadChunk.length} exceeds cap ${MAX_CHUNK_BYTES}`);
  }

  // Capture namespace metadata from this chunk so the reassembled
  // Facts frame carries them forward (see BridgeState.chunks comment).
  const incomingNamespace = String(params.namespace || "");
  const incomingNamespacesRaw = params.namespaces;
  const incomingNamespaces = Array.isArray(incomingNamespacesRaw)
    ? incomingNamespacesRaw.filter((ns: unknown) => typeof ns === "string" && ns.length > 0) as string[]
    : [];

  const current = state.chunks.get(eventId) || {
    totalChunks,
    chunks: new Array<string>(totalChunks).fill(""),
    createdAt: Date.now(),
    namespace: incomingNamespace,
    namespaces: incomingNamespaces
  };

  // Guard against a caller re-opening the same eventId with a different
  // totalChunks — that would silently corrupt the reassembly buffer.
  if (current.totalChunks !== totalChunks) {
    logger.warn("chunk_totals_mismatch", {
      eventId,
      existing: current.totalChunks,
      incoming: totalChunks
    });
    return fail(req.id, "bad_request", "totalChunks changed mid-stream");
  }

  // Late chunks may arrive with fresh namespace values — trust the
  // most recent non-empty pair (agent-core emits identical values in
  // every chunk, so this only matters if the first chunk was somehow
  // missing the metadata).
  if (incomingNamespace && !current.namespace) current.namespace = incomingNamespace;
  if (incomingNamespaces.length > 0 && current.namespaces.length === 0) {
    current.namespaces = incomingNamespaces;
  }

  current.chunks[chunkIndex] = payloadChunk;
  state.chunks.set(eventId, current);

  if (current.chunks.every((chunk) => chunk.length > 0)) {
    state.chunks.delete(eventId);
    return handleFactsSend({
      ...req,
      params: {
        eventId,
        payloadJson: current.chunks.join(""),
        namespace: current.namespace,
        namespaces: current.namespaces
      }
    });
  }

  return success(req.id, {
    accepted: true,
    eventId,
    chunkIndex,
    totalChunks
  });
}

export async function handleHeartbeat(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const deviceId = String(req.params?.deviceId || state.deviceId || "");
    if (!deviceId) return fail(req.id, "bad_request", "deviceId required");

    const traceId = crypto.randomUUID().replace(/-/g, "");
    await write({
      traceId,
      heartbeat: {
        deviceId,
        uptimeSeconds: Number(req.params?.uptimeSeconds ?? 0),
        agentVersion: String(req.params?.agentVersion || ""),
        policyVersion: String(req.params?.policyVersion || "")
      }
    });

    return success(req.id, { accepted: true, traceId });
  } catch (err: any) {
    return fail(req.id, "heartbeat_send_failed", err?.message || String(err));
  }
}

export async function handleAck(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const eventId = String(req.params?.eventId || "");
    if (!eventId) return fail(req.id, "bad_request", "eventId required");

    await write({
      traceId: eventId,
      ack: {
        eventId,
        status: Number(req.params?.status ?? 0),
        message: String(req.params?.message || ""),
        receivedAtUtc: req.params?.receivedAtUtc || new Date().toISOString()
      }
    });

    return success(req.id, { accepted: true, eventId });
  } catch (err: any) {
    return fail(req.id, "ack_send_failed", err?.message || String(err));
  }
}

export async function handleClose(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    teardownBridge("manual_close");
    return success(req.id, { closed: true });
  } catch (err: any) {
    return fail(req.id, "grpc_close_failed", err?.message || String(err));
  }
}
