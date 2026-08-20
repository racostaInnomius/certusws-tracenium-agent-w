// src/transport/grpc-client.ts
import { EventEmitter } from "events";
import { AgentContext } from "../core/agent-context";
import { logger } from "../bootstrap/logger";
import { outbox } from "../queue/sqlite-outbox";

function normalizeTarget(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

// IPC sizing vs the PrivSvc named-pipe limit.
//
// PrivSvc rejects any IPC *line* longer than 64 KB (NamedPipeServer.cs:
// `if (line.Length > 64 * 1024)`) and — critically — historically CLOSED
// the pipe on that path. The line it measures is the FULL serialized
// request: `{v,id,method,params:{...,payloadJson:"<escaped>"},meta}`, i.e.
// JSON wrapper + the payload AFTER JSON-escaping. JSON-escaping inflates a
// JSON payload (every `"` and `\` doubles, non-ASCII expands), so a RAW
// 62 KB payload serializes to a >64 KB line.
//
// The old values compared the RAW payload size (62 KB) against a 64 KB
// threshold → "fits" → whole-send → PrivSvc saw a >64 KB line → rejected
// + closed the pipe → the next chunk write hit `read EPIPE`. This was the
// deterministic W11 poison-pill (outbox event 266, ~62 KB) that flapped
// the connection ~10× on 2026-07-01. Events already ABOVE 64 KB were fine
// because they went straight to chunks and never attempted the whole-send.
//
// Fix: size BOTH thresholds so that raw + escaping + wrapper stays safely
// under 64 KB even in the worst realistic escaping case (~1.4×). 32 KB raw
// → ~45 KB on the wire, comfortable margin. Events >32 KB now chunk (the
// proven-good path); each 32 KB chunk also stays well under the limit.
const MAX_FACTS_IPC_BYTES = 32 * 1024;

const FACTS_CHUNK_SIZE = 32 * 1024; // 32KB: raw+escaping+wrapper stays < 64KB pipe limit

function chunkString(str: string, size: number): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < str.length; i += size) {
    chunks.push(str.slice(i, i + size));
  }
  return chunks;
}

type StreamLike = EventEmitter & {
  write: (msg: any) => void;
  end: () => void;
};

type GrpcBridgeClient = {
  Connect: () => StreamLike;
  isConnected: () => boolean;
  // Explicit teardown. Idempotent. Tears down the local stream,
  // notifies privsvc to close its side, and drops the per-AgentContext
  // singleton so the next createGrpcClient() builds fresh state.
  // Callers (notably grpc-stream's reconnect supervisor) use this when
  // they've decided the client is unrecoverable — without it, the only
  // way to invalidate the cached instance was from inside grpc-client
  // itself, which meant a "stuck reconnect" loop could keep getting
  // back the same dead client (337 attempts deep, in the observed
  // production zombie).
  close: () => void;
};

function attachPrivPushHandler(ctx: AgentContext, onPush: (msg: any) => void) {
  const priv: any = ctx.priv as any;

  // CRITICAL: always update the "current" callback target before any
  // skip-if-attached short-circuit. This fixes a stale-closure bug that
  // silently dropped every reconnect-after-bridge-recovery payload.
  //
  // The bug (W11-JPR-Lab01 logs 2026-06-10 13:31–14:02 captured it
  // perfectly): every `createGrpcClient()` call builds a NEW
  // `stream = new EventEmitter()` instance. The `onPush` callback passed
  // in here captures that fresh stream via closure. The earlier version
  // of this function — "if (priv.__pushHandlerAttached) skip" — never
  // updated the registration on subsequent calls, so PrivSvc kept
  // delivering pushes to the very first callback, which fired
  // `stream.emit("data", ...)` on the very first (now orphan) stream.
  // Meanwhile `startGrpcStream` had registered its `stream.on("data")`
  // listener on the new stream → emit and listen on different objects
  // → every remoteSessionOffer / policyUpdate / runJob / agentUpdate
  // arrived at PrivSvc, was logged as "[grpc-client] push message", and
  // then evaporated. From the operator's perspective: "the agent is
  // online but RCP / job push / policy push silently does nothing."
  //
  // Fix: route every push through `priv.__currentPushCallback`. The first
  // attach installs a tiny dispatcher into PrivSvc that just calls
  // whatever is in `__currentPushCallback` at the moment of the push.
  // Subsequent reconnects just rewrite that slot — no double-subscribe,
  // no stale stream.
  priv.__currentPushCallback = onPush;

  if (priv.__pushHandlerAttached) {
    // Dispatcher is already wired to PrivSvc; the slot rewrite above is
    // all we need. Quiet log so we don't spam noisy reconnect WARNs.
    ctx.logger?.debug?.("[grpc-client] push handler dispatcher already wired — slot updated");
    return;
  }
  priv.__pushHandlerAttached = true;

  ctx.logger?.info?.("[grpc-client] attaching PrivSvc push handler", {
    hasOnPush: typeof priv.onPush === "function",
    hasOn: typeof priv.on === "function"
  });

  // The tiny dispatcher — installed ONCE into PrivSvc, lives forever, and
  // forwards to whatever `__currentPushCallback` points at right now. The
  // `try/catch` is paranoid: a downstream bug in `onPush` (the consumer)
  // must NOT break the chain for everyone else. We log and continue.
  const dispatcher = (msg: any) => {
    const cb = priv.__currentPushCallback;
    if (!cb) return;
    try {
      cb(msg);
    } catch (err: any) {
      ctx.logger?.error?.("[grpc-client] push dispatcher: callback threw", {
        err: err?.message || String(err)
      });
    }
  };

  let attached = false;
  if (typeof priv.onPush === "function") {
    ctx.logger?.info?.("[grpc-client] subscribing via priv.onPush()");
    priv.onPush(dispatcher);
    attached = true;
  } else if (typeof priv.on === "function") {
    ctx.logger?.info?.("[grpc-client] subscribing via priv.on('push')");
    priv.on("push", dispatcher);
    attached = true;
  }

  if (!attached) {
    ctx.logger?.warn(
      "[grpc-client] PrivSvcClient has no push subscription method"
    );
  }
}

export function createGrpcClient(ctx: AgentContext): GrpcBridgeClient {
  // Singleton per AgentContext. The cache is invalidated whenever the
  // stream is torn down (stream.end / grpc.disconnected push / client.close)
  // so a reconnect after a half-open TCP / privsvc-restart / sleep-wake
  // event gets a fresh client with clean state instead of resurrecting a
  // corpse whose `connected` flag and `lastServerActivityMs` lie about
  // liveness. The "reusing existing grpc client instance" warning used
  // to print on EVERY caller after the first connect, including healthy
  // ones — masking the actual leak (calls that returned a dead client
  // after a stream death). Now it only prints inside the same generation
  // of a healthy stream, which is the only legitimate reuse case.
  if ((ctx as any).__grpcClientInstance) {
    ctx.logger?.debug?.("[grpc-client] reusing existing grpc client instance");
    return (ctx as any).__grpcClientInstance;
  }

  const target = normalizeTarget(ctx.config.grpcEndpoint);
  ctx.logger?.info(`[grpc-client] Using PrivSvc gRPC bridge → ${target}`);

  const stream = new EventEmitter() as StreamLike;
  let connectedEmitted = false;

  let connected = false;
  let connectPromise: Promise<void> | null = null;
  let ended = false;
  let localClose = false;

  // Node's EventEmitter throws SYNCHRONOUSLY when you emit 'error' with
  // zero listeners attached — it's the one event name with that special
  // case. grpc-stream.ts's stop() calls stream.removeAllListeners() as
  // part of a normal, already-handled disconnect; if a heartbeat IPC
  // call that was in flight at that exact moment resolves as a failure
  // a tick later, the plain `stream.emit("error", ...)` below used to
  // throw with nothing left to catch it — three call sites deep (the
  // heartbeat failure branch re-emits from its own catch, which the
  // outer writeChain catch then re-emits again), landing as a genuine
  // unhandled promise rejection that killed the whole agent process.
  // Confirmed in the field 2026-08-13: a device stuck in a ~5s
  // reconnect loop crashed on almost every cycle via this exact path,
  // compounding the outage instead of just reconnecting cleanly.
  // Route every post-teardown error emission through this guard instead
  // of calling stream.emit("error", ...) directly.
  const safeEmitError = (err: Error) => {
    if (stream.listenerCount("error") === 0) {
      ctx.logger?.debug?.("[grpc-client] dropping error emit — no listener attached (stream already torn down)", {
        error: err?.message || String(err)
      });
      return;
    }
    stream.emit("error", err);
  };
  // Fires if PrivSvc accepts a `grpc.connect` but never sends the
  // `grpc.connected` READY push (e.g. it restarts mid-handshake). See
  // armConnectReadyTimeout for the full rationale.
  let connectReadyTimer: NodeJS.Timeout | null = null;

  // serialize IPC writes to PrivSvc to avoid concurrent pipe writes
  let writeChain: Promise<void> = Promise.resolve();

  // track in-flight events to avoid duplicate sends before ACK
  const inFlightEvents = new Set<string>();

  // ── Server activity tracker (P0 fix for stream-zombie bug) ───────
  //
  // Stamps the wall-clock timestamp of the most recent message we
  // received from the server, ANY message — server pings, ACKs,
  // policy updates, jobs, the lot. The grpc-stream watchdog reads
  // this via `stream.getLastServerActivityMs()` and declares the
  // stream zombie if it goes longer than ~270s without any update,
  // which forces a reconnect.
  //
  // Why we set this in attachPrivPushHandler instead of inside each
  // method branch: the activity signal is "I heard from the server",
  // and that's true for every push regardless of what payload it
  // carries. Updating in one central place means a future new
  // message type doesn't accidentally bypass the watchdog.
  //
  // Initialized to "now" so a freshly-created stream isn't seen as
  // zombie before the first server ping arrives.
  let lastServerActivityMs = Date.now();
  (stream as any).getLastServerActivityMs = () => lastServerActivityMs;

  // Counterpart to `lastServerActivityMs`, tracking OUTBOUND traffic.
  // Stamped whenever a `priv.call("grpc.heartbeat")` or
  // `priv.call("grpc.facts.send")` returns ok:true — that means the
  // bridge accepted our IPC AND wrote the bytes onto the live gRPC
  // stream without erroring. If the wire were zombie, the bridge's
  // `_call.RequestStream.WriteAsync` would throw and the IPC would
  // return ok:false (handled below by `emit("error")` → reconnect).
  //
  // The reason this exists: the server doesn't ACK heartbeats by
  // design (looked at bridge logs 2026-05-19 — confirmed). On idle
  // devices that aren't generating FACTS, NOTHING comes back from
  // the server for minutes at a stretch. The previous armWatchdog
  // in grpc-stream.ts relied solely on `lastServerActivityMs` to
  // detect zombies, so it false-positived every SILENCE_THRESHOLD_MS
  // and forced a useless reconnect cycle. We now require BOTH stale-
  // receive AND stale-send to declare a stream zombie — catching the
  // genuine cases (kernel surface write errors via HTTP/2 keepalive
  // → ok:false → lastClientSendOkMs stops updating) while leaving
  // healthy-but-idle streams alone.
  //
  // Initialized to "now" for the same reason as lastServerActivityMs:
  // a fresh stream shouldn't be flagged as send-silent before its
  // first heartbeat tick.
  let lastClientSendOkMs = Date.now();
  (stream as any).getLastClientSendOkMs = () => lastClientSendOkMs;

  // Mirror of grpc-stream.ts SILENCE_THRESHOLD_MS. Kept here as a
  // local constant (not imported) to avoid a circular dep — grpc-stream
  // already imports from this file. If the threshold changes there,
  // change it here too. The important invariant is: this MUST be ≥ the
  // watchdog threshold, otherwise `isConnected()` would start lying
  // "false" before the watchdog fires its reconnect, which would make
  // heartbeats stop short of triggering any recovery.
  const SILENCE_THRESHOLD_MS = 270_000;

  // Wipe the per-ctx singleton so the next createGrpcClient() builds a
  // fresh instance instead of returning this dead one. We guard with an
  // identity check (=== client) because in theory a faster reconnect on
  // another code path could have already swapped in a newer instance,
  // and we don't want to clobber that. Idempotent — safe to call from
  // multiple disconnect paths.
  const invalidateCachedClient = (reason: string) => {
    if (connectReadyTimer) { clearTimeout(connectReadyTimer); connectReadyTimer = null; }
    if ((ctx as any).__grpcClientInstance === client) {
      delete (ctx as any).__grpcClientInstance;
      ctx.logger?.info?.("[grpc-client] cached instance invalidated", { reason });
    }
  };

  const clearConnectReadyTimeout = () => {
    if (connectReadyTimer) { clearTimeout(connectReadyTimer); connectReadyTimer = null; }
  };

  // After PrivSvc ACCEPTS a `grpc.connect` but before it confirms READY,
  // the client waits for the async `grpc.connected` push. If that push
  // never arrives — the exact macOS incident 2026-07-01: the backend went
  // DB/DNS-silent → PrivSvc's own circuit breaker restarted it mid-
  // reconnect → the pending connect was lost — the client used to wait
  // FOREVER. No heartbeat/watchdog is armed until READY, and grpc-stream's
  // reconnect loop already thinks the connect "succeeded", so nothing ever
  // recovers: the process stays alive but `connected:false` and OFFLINE
  // (that host sat zombie for 5 days). This timeout closes the gap: if
  // READY doesn't land in time, tear the client down and surface an error
  // so grpc-stream builds a fresh client and retries with backoff.
  const CONNECT_READY_TIMEOUT_MS = 30_000;
  const armConnectReadyTimeout = () => {
    clearConnectReadyTimeout();
    connectReadyTimer = setTimeout(() => {
      connectReadyTimer = null;
      if (connected || ended) return; // READY arrived, or already torn down
      ctx.logger?.warn?.("[grpc-client] connect READY not confirmed within timeout — forcing reconnect", {
        timeoutMs: CONNECT_READY_TIMEOUT_MS
      });
      try { ctx.trayStatus.markGrpcDisconnected(); } catch {}
      invalidateCachedClient("connect_ready_timeout");
      try { stream.emit("error", new Error("connect_ready_timeout")); } catch {}
    }, CONNECT_READY_TIMEOUT_MS);
    (connectReadyTimer as any)?.unref?.();
  };

  // Push from PrivSvc → re-emit as "data"
  attachPrivPushHandler(ctx, (pushMsg: any) => {
    try {
      const method = pushMsg?.method;
      if (!method) return;

      // Mark activity for ANY recognized push from the server. This
      // is the canonical liveness signal for the watchdog.
      lastServerActivityMs = Date.now();

      const params = pushMsg?.params ?? {};
      // El `method` a INFO (barato y suficiente para seguir el flujo);
      // los params completos a DEBUG. Este era EL mayor generador de
      // volumen de log en endpoints: cada oferta SDP completa y cada
      // candidato ICE de cada sesión RCP se escribían enteros. Con
      // debug apagado (default) esto pasa de kilobytes por evento a una
      // línea. Para diagnosticar, crear `debug.flag` en el data dir.
      ctx.logger?.info("[grpc-client] push message", { method });
      ctx.logger?.debug?.("[grpc-client] push params", { method, params });

      // Server ping (sent every ~90s by controlplane.ts). We don't
      // need to do anything with it — the activity stamp above is
      // already updated. The explicit early-return keeps it from
      // falling through to the unmatched-method passthrough log
      // (which would spam at the new 90s cadence).
      if (method === "grpc.ping" || method === "grpc.control.ping") {
        ctx.logger?.debug?.("[grpc-client] server ping received");
        return;
      }

      if (method === "grpc.ack") {
        ctx.logger?.info?.("[grpc-client] ACK push received", {
          rawEventId: params?.eventId,
          status: params?.status,
          message: params?.message
        });

        const normalized = {
          ...params,
          eventId: String(params?.eventId ?? "").trim()
        };

        // clear in-flight tracking
        try {
          if (normalized.eventId) {
            inFlightEvents.delete(normalized.eventId);
          }
        } catch {}

        // Remote ACK is the delivery boundary. IPC acceptance only means PrivSvc queued
        // the message locally; the outbox must remain retryable until backend ACK.
        try {
          const eventId = normalized.eventId;
          if (eventId) {
            const parts = eventId.split(":");
            const outboxId = Number(parts[parts.length - 1]);

            if (!isNaN(outboxId)) {
              const status = Number(normalized.status ?? 0);
              const message = String(normalized.message || "");

              if (status === 0) {
                outbox.markSent(outboxId);
                ctx.logger?.info?.("[grpc-client] ACK → markSent", { eventId, outboxId });
              } else if (status === 1) {
                outbox.markFailed(outboxId, message || "ACK requested retry");
                ctx.logger?.warn?.("[grpc-client] ACK → retry", { eventId, outboxId, status });
              } else {
                outbox.markRejected(outboxId, message || `ACK rejected with status ${status}`);
                ctx.logger?.warn?.("[grpc-client] ACK → rejected", { eventId, outboxId, status });
              }
            }
          }
        } catch (err: any) {
          ctx.logger?.error?.("[grpc-client] ACK handling failed", err?.message || err);
        }

        stream.emit("data", { ack: normalized });
        return;
      }

      if (method === "grpc.connected") {
        clearConnectReadyTimeout();
        if (connectedEmitted) return;
        connectedEmitted = true;

        connected = true;
        ctx.logger?.info("[grpc-client] PrivSvc confirmed gRPC connected (READY)");
        try {
          ctx.trayStatus.markGrpcConnected();
        } catch {}
        stream.emit("data", { connected: true });
        return;
      }

      if (method === "grpc.control.runJob") {
        stream.emit("data", { runJob: params });
        return;
      }

      if (method === "grpc.control.rotateCert") {
        stream.emit("data", { rotateCert: params });
        return;
      }

      if (method === "grpc.control.policyUpdate") {
        stream.emit("data", { policyUpdate: params });
        return;
      }

      if (method === "grpc.control.disconnect") {
        stream.emit("data", { disconnect: params });
        return;
      }

      if (method === "grpc.control.agentUpdate") {
        stream.emit("data", { agentUpdate: params });
        return;
      }

      // RCP M1.S1 — signaling messages from backend. PrivSvc maps
      // the proto oneof variants to these four methods. The agent
      // dispatches them to the RCP SessionManager via the
      // stream's data event (see grpc-stream.ts handler).
      if (method === "grpc.control.remoteSessionOffer") {
        stream.emit("data", { remoteSessionOffer: params });
        return;
      }
      if (method === "grpc.control.remoteSessionIce") {
        stream.emit("data", { remoteSessionIce: params });
        return;
      }
      if (method === "grpc.control.remoteSessionClose") {
        stream.emit("data", { remoteSessionClose: params });
        return;
      }
      if (method === "grpc.control.remoteSessionError") {
        stream.emit("data", { remoteSessionError: params });
        return;
      }

      if (method === "grpc.control.streamClosed" || method === "grpc.disconnected") {
        ctx.logger?.warn("[grpc-client] gRPC bridge reported disconnect");
        connected = false;
        connectPromise = null;
        ended = false;
        try {
          ctx.trayStatus.markGrpcDisconnected();
        } catch {}

        // Invalidate the singleton so the next createGrpcClient() in
        // the reconnect path builds a fresh instance. Without this,
        // grpc-stream's reconnect loop kept getting back the same
        // dead client (with stale `connected`/`lastServerActivityMs`
        // state) and the reconnect attempts piled up to 337 in the
        // wild before the operator manually restarted the agent.
        invalidateCachedClient("remote_disconnect");

        // Remote disconnect: notify listeners, but do NOT mark this stream as locally ended
        // and do NOT send grpc.close back to PrivSvc.
        stream.emit("end");
        return;
      }

      // debug passthrough si quieres
      // stream.emit("data", { debug: { method, params } });
    } catch (e: any) {
      ctx.logger?.error("[grpc-client] push handler error:", e?.message || e);
    }
  });

  async function ensureConnected() {
    if (ended && localClose) throw new Error("stream ended");
    if (connected) return;

    if (connectPromise) {
      await connectPromise;
      return;
    }

    connectPromise = (async () => {
      try {
        const tenantId = String(ctx.enrollment.tenantId || "");
        const deviceId = String(ctx.enrollment.deviceId || "");
        const agentVersion = String(ctx.config.agentVersion || "");
        // RCP M1.S1 — `rcp.shell` is advertised as a LEAF capability
        // when policy.features.remoteShell is true. Not part of
        // `plugins.enabled` because RCP isn't a job-style plugin;
        // it's a session-style listener. Adding here so backend
        // (remote-control.service.startSession) can check
        // capabilities.includes('rcp.shell').
        const baseCaps = [
          ...(ctx.enrollment.bootstrap.capabilities || []),
          ...ctx.policyRuntime.getEnabledPlugins()
        ];
        try {
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const { rcpShellAdvertised, rcpFileAdvertised, rcpScreenAdvertised, rcpConsentAdvertised } = require("../plugins/rcp");
          // M1 — rcp.shell: policy.features.remoteShell
          if (rcpShellAdvertised(ctx))  baseCaps.push("rcp.shell");
          // M2.S1 — rcp.file: policy.features.remoteFile
          if (rcpFileAdvertised(ctx))   baseCaps.push("rcp.file");
          // M3.S1 — rcp.screen: policy.features.remoteScreen
          if (rcpScreenAdvertised(ctx)) baseCaps.push("rcp.screen");
          // User-attended approval — advertise rcp.consent only when the agent
          // can actually prompt the user (a functional consentPrompter is wired).
          if (rcpConsentAdvertised(ctx)) baseCaps.push("rcp.consent");
        } catch {
          // Plugin module missing or threw — leave RCP caps off
          // rather than crash bootstrap.
        }
        const capabilities = Array.from(new Set(baseCaps));

        const clientCertThumbprint = String((ctx.enrollment as any)?.mtls?.clientCertThumbprint || "");
        const issuingCaThumbprint = String((ctx.enrollment as any)?.mtls?.issuingCaThumbprint || "");
        // Todas las CA aceptables. Si el enrolamiento es anterior a este
        // campo se manda la singular sola, que es el comportamiento previo.
        const issuingCaThumbprints: string[] = Array.isArray((ctx.enrollment as any)?.mtls?.issuingCaThumbprints)
          ? (ctx.enrollment as any).mtls.issuingCaThumbprints.map(String).filter(Boolean)
          : (issuingCaThumbprint ? [issuingCaThumbprint] : []);

        if (!tenantId || !deviceId) throw new Error("Missing enrollment tenantId/deviceId");
        if (!clientCertThumbprint) throw new Error("Missing mtls.clientCertThumbprint in enrollment");
        if (!issuingCaThumbprint) throw new Error("Missing mtls.issuingCaThumbprint in enrollment");

        // PrivSvc owns the gRPC stream and emits HELLO on its own. Without
        // this field, PrivSvc fills `policyVersion: ""` in HELLO and the
        // server flags every reconnect as policy drift — re-shipping the
        // full policyJson, writing two `policy_*` rows + an
        // `policy_hello_drift_detected` audit event per connect, and
        // drowning real drift events in noise. Forwarding the locally
        // persisted version closes the loop: server compares, finds them
        // equal on healthy reconnects, and only ships an update when the
        // operator actually changed the policy while the agent was offline.
        const policyVersion = String(ctx.policy.getVersion() || "");

        ctx.logger?.info("[grpc-client] requesting PrivSvc gRPC connect");

        const resp = await (ctx.priv as any).call({
          v: 1,
          id: "grpc-connect",
          method: "grpc.connect",
          params: {
            target,
            clientCertThumbprint,
            issuingCaThumbprint,
            issuingCaThumbprints,
            tenantId,
            deviceId,
            agentVersion,
            capabilities,
            policyVersion
          },
          meta: { tenantId, deviceId }
        });

        if (!resp?.ok) {
          throw new Error(resp?.error?.message || resp?.error || "PrivSvc connect failed");
        }

        const result = resp?.result ?? {};

        if (result.connected === true && result.ready === true) {
        clearConnectReadyTimeout();
        connected = true;
        ctx.logger?.info("[grpc-client] PrivSvc bridge READY (from connect response)");
        try {
          ctx.trayStatus.markGrpcConnected();
        } catch {}

        stream.emit("data", {
          connected: true,
          source: "connect_response"
        });

        return;
      }

      if (result.connected === true) {
        connected = false;
        ctx.logger?.info("[grpc-client] bridge accepted connect request, waiting for grpc.connected");
        // Guard the READY handshake: if the push never lands (PrivSvc
        // restarted mid-connect), recover instead of waiting forever.
        armConnectReadyTimeout();
        return;
      }

        // Otherwise wait for the push notification from the bridge.
        connected = false;
        ctx.logger?.info("[grpc-client] connect request accepted, waiting for grpc.connected confirmation");
        armConnectReadyTimeout();
      } catch (e: any) {
        connected = false;
        ctx.logger?.error("[grpc-client] connect failed", e?.message || e);
        stream.emit("error", e);
        throw e;
      } finally {
        connectPromise = null;
      }
    })();

    await connectPromise;
  }

  stream.write = (msg: any) => {
    writeChain = writeChain
      .then(async () => {
        await ensureConnected();

        if (ended && localClose) {
          ctx.logger?.warn("[grpc-client] write skipped: stream already ended locally");
          return;
        }

        if (!connected) {
          ctx.logger?.warn("[grpc-client] write skipped: bridge not fully ready yet");
          return;
        }

        // HELLO is handled by PrivSvc on connect; ignore hello from node
        if (msg?.hello) return;

        if (msg?.facts) {
          const eventId = String(msg.facts.eventId || "");
          if (inFlightEvents.has(eventId)) {
            ctx.logger?.warn("[grpc-client] duplicate send prevented (in-flight)", { eventId });
            return;
          }
          inFlightEvents.add(eventId);

          if (!eventId) throw new Error("facts.eventId required");
          const factNamespace = String(msg.facts.namespace || "");
          const factNamespaces = Array.isArray(msg.facts.namespaces)
            ? msg.facts.namespaces.filter((ns: unknown) => typeof ns === "string" && ns.length > 0)
            : [];
          ctx.logger?.info("[grpc-client] sending FACTS event", {
            eventId,
            namespace: factNamespace,
            namespaces: factNamespaces
          });

          let payloadJsonStr: string;
          if (Buffer.isBuffer(msg.facts.payloadJson)) payloadJsonStr = msg.facts.payloadJson.toString("utf8");
          else if (typeof msg.facts.payloadJson === "string") payloadJsonStr = msg.facts.payloadJson;
          else throw new Error("facts.payloadJson must be Buffer or string");

          const payloadSizeBytes = Buffer.byteLength(payloadJsonStr, "utf8");
          ctx.logger?.info("[grpc-client] FACTS payload size", payloadSizeBytes);

          // If payload fits, send normally
          if (payloadSizeBytes <= MAX_FACTS_IPC_BYTES) {
            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-${eventId}`,
              method: "grpc.facts.send",
              params: {
                eventId,
                namespace: factNamespace,
                namespaces: factNamespaces,
                payloadJson: payloadJsonStr
              },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
            });

            if (!resp?.ok) {
              const errorCode = String(resp?.error?.code || "");
              const errorMessage = String(resp?.error?.message || resp?.error || "facts.send failed");

              if (errorCode === "request_too_large") {
                ctx.logger?.warn("[grpc-client] switching to chunked FACTS send", { eventId, payloadSizeBytes });
              } else {
                throw new Error(errorMessage);
              }
            } else {
              // Release in-memory dedupe after PrivSvc accepts the IPC write. The
              // persisted outbox stays IN_FLIGHT until the backend ACK arrives, so a
              // stale-flight TTL can retry if the bridge dies before remote ACK.
              inFlightEvents.delete(eventId);
              // Bridge accepted FACTS payload AND wrote it to the live
              // gRPC stream without erroring → wire is alive. Updates
              // the send-side liveness signal the watchdog gates on.
              lastClientSendOkMs = Date.now();
              ctx.logger?.info?.("[grpc-client] IPC accepted; awaiting remote ACK", { eventId });
              return;
            }
          }

          // Chunked send fallback or large payload
          const chunks = chunkString(payloadJsonStr, FACTS_CHUNK_SIZE);
          ctx.logger?.info("[grpc-client] sending FACTS in chunks", {
            eventId,
            totalChunks: chunks.length
          });

          for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];

            // Per-chunk trace (always-on). If the IPC pipe dies mid-send,
            // this is the last line before the break — it pins down WHICH
            // chunk was in flight and how big, which the aggregate
            // "sending in chunks" line above cannot. Pairs with the
            // in-flight snapshot in privsvc-client-windows.onSocketError.
            ctx.logger?.info("[grpc-client] FACTS chunk send", {
              eventId,
              chunkIndex: i,
              totalChunks: chunks.length,
              chunkBytes: Buffer.byteLength(chunk, "utf8")
            });

            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `facts-chunk-${eventId}-${i}`,
              method: "grpc.facts.chunk",
              params: {
                eventId,
                namespace: factNamespace,
                namespaces: factNamespaces,
                chunkIndex: i,
                totalChunks: chunks.length,
                payloadChunk: chunk
              },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
            });

            if (!resp?.ok) {
              const errorMessage = String(resp?.error?.message || resp?.error || "facts.chunk failed");
              throw new Error(`FACTS_CHUNK_FAILED:${errorMessage} (chunkIndex=${i}/${chunks.length})`);
            }

            ctx.logger?.info("[grpc-client] FACTS chunk accepted", {
              eventId,
              chunkIndex: i,
              totalChunks: chunks.length
            });
          }

          ctx.logger?.info("[grpc-client] FACTS chunked send completed", { eventId });

          // Release local dedupe only; backend ACK remains responsible for SENT.
          inFlightEvents.delete(eventId);
          // All N chunks accepted by bridge AND written to the live
          // gRPC stream → wire is alive. Same liveness signal as the
          // single-shot facts path above.
          lastClientSendOkMs = Date.now();
          ctx.logger?.info("[grpc-client] FACTS chunked IPC accepted; awaiting remote ACK", { eventId });

          return;
        }

        if (msg?.heartbeat) {
          const deviceId = String(
            msg.heartbeat.deviceId ||
            ctx.enrollment.deviceId ||
            ""
          );
          const uptimeSeconds = Number(msg.heartbeat.uptimeSeconds || 0);
          const agentVersion = String(msg.heartbeat.agentVersion || ctx.config.agentVersion || "");
          const policyVersion = String(msg.heartbeat.policyVersion || "");

          if (!deviceId) {
            ctx.logger?.warn("[grpc-client] heartbeat ignored: deviceId missing");
            return;
          }

          // Forward the heartbeat to PrivSvc so it reaches the gRPC stream
          // and the server can refresh device_sessions.last_heartbeat. If
          // the IPC call fails (bridge dead, stream down) we mark the
          // connection broken so the reconnect loop kicks in — this is a
          // cheap liveness check every HEARTBEAT_INTERVAL_MS.
          try {
            const resp = await (ctx.priv as any).call({
              v: 1,
              id: `hb-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              method: "grpc.heartbeat",
              params: {
                deviceId,
                uptimeSeconds,
                agentVersion,
                policyVersion
              },
              meta: { tenantId: ctx.enrollment.tenantId, deviceId }
            });

            // CRITICAL: update tray-status BEFORE any error emissions so the
            // liveness watchdog is never triggered by a heartbeat failure.
            // A failed heartbeat is recoverable; a wedge false-positive is not.
            try {
              ctx.trayStatus.markHeartbeat();
            } catch {}

            if (!resp?.ok) {
              const errorCode = String(resp?.error?.code || "");
              const errorMessage = String(resp?.error?.message || resp?.error || "heartbeat failed");
              ctx.logger?.warn("[grpc-client] heartbeat IPC rejected — marking connection broken", {
                errorCode,
                errorMessage
              });
              connected = false;
              connectPromise = null;
              // Surface to stream.on('error') so scheduleReconnect() runs.
              safeEmitError(new Error(`heartbeat_failed:${errorCode || errorMessage}`));
            } else {
              // Bridge accepted heartbeat AND wrote it to the live
              // gRPC stream without erroring → wire is alive. See
              // `lastClientSendOkMs` declaration for full rationale.
              lastClientSendOkMs = Date.now();
            }
          } catch (err: any) {
            // Update liveness clock even when the IPC call throws.
            try { ctx.trayStatus.markHeartbeat(); } catch {}
            ctx.logger?.warn("[grpc-client] heartbeat IPC threw — marking connection broken", {
              error: err?.message || String(err)
            });
            connected = false;
            connectPromise = null;
            try {
              ctx.trayStatus.markGrpcDisconnected();
            } catch {}
            safeEmitError(err instanceof Error ? err : new Error(String(err)));
          }

          return;
        }

        ctx.logger?.warn("[grpc-client] stream.write ignored unknown message type", {
          keys: Object.keys(msg || {})
        });
      })
      .catch((err) => {
        const errCode = String(err?.code || "");
        const errMessage = String(err?.message || err || "");

        // "stream ended" is thrown by ensureConnected() when the local
        // side has already torn down (ended && localClose). This is
        // EXPECTED during the update teardown sequence: msiexec stops
        // the privsvc service → in-flight IPC writes throw "PrivSvc
        // timeout" → bridge calls stream.end() → ended+localClose flip
        // true → any subsequent stream.write that's already queued in
        // writeChain hits the early-throw and lands here. Emitting it
        // as `error` on an EventEmitter that has no 'error' listener
        // crashes the process with "Unhandled rejection" — visible in
        // TraceniumAgentCore_*.err.log every time an update fires. The
        // event is cosmetic (the install proceeds correctly via Task
        // Scheduler regardless), but the err.log noise misleads triage
        // into thinking the update itself failed. Downgrade to a debug
        // log + drop the in-flight tracking entry; nothing to recover.
        if (/stream ended/i.test(errMessage)) {
          ctx.logger?.debug?.("[grpc-client] write dropped after local teardown", {
            messageType: msg ? Object.keys(msg).join(",") : "?",
            ended,
            localClose
          });
          if (msg?.facts?.eventId) {
            inFlightEvents.delete(String(msg.facts.eventId));
          }
          return;
        }

        if (errCode === "EPIPE" || /EPIPE/i.test(errMessage)) {
          ctx.logger?.warn("[grpc-client] EPIPE detected, marking connection as broken", {
            errCode,
            errMessage
          });
          connected = false;
          connectPromise = null;
          try {
            ctx.trayStatus.markGrpcDisconnected();
          } catch {}
        }
        // release in-flight on failure
        if (msg?.facts?.eventId) {
          inFlightEvents.delete(String(msg.facts.eventId));
        }
        safeEmitError(err);
      });
  };

  stream.end = () => {
    if (ended) return;

    ended = true;
    localClose = true;
    connected = false;
    connectPromise = null;
    try {
      ctx.trayStatus.markGrpcDisconnected();
    } catch {}

    (ctx.priv as any)
      .call({
        v: 1,
        id: "grpc-close",
        method: "grpc.close",
        params: {},
        meta: { tenantId: ctx.enrollment.tenantId, deviceId: ctx.enrollment.deviceId }
      })
      .catch(() => {});

    // Wipe the singleton — see invalidateCachedClient docstring.
    invalidateCachedClient("local_end");

    stream.emit("end");
  };

  const client: GrpcBridgeClient & { close: () => void } = {
    Connect: () => {
      ended = false;
      localClose = false;
      ensureConnected().catch(() => {});
      return stream;
    },
    // Reports "live" only if (a) the local connect handshake completed
    // AND (b) the stream has shown liveness in EITHER direction within
    // the silence threshold — a server push (`lastServerActivityMs`) OR
    // a heartbeat/facts write the PrivSvc bridge accepted onto the live
    // gRPC stream (`lastClientSendOkMs`).
    //
    // WHY EITHER-DIRECTION (the idle-churn fix, 2026-06-30):
    //   The server does NOT push anything to the agent during idle (no
    //   facts to ACK, no jobs, no policy changes) and does NOT ping by
    //   design. So on a healthy-but-idle device `lastServerActivityMs`
    //   legitimately freezes at HELLO time. A receive-only check then
    //   crosses SILENCE_THRESHOLD_MS at ~270s, the heartbeat tick in
    //   grpc-stream sees isConnected()===false and force-reconnects — a
    //   pure false positive that recycled the stream every ~5 min,
    //   dropping live RCP sessions and (under any reconnect hiccup)
    //   marching toward the circuit-breaker process.exit. Confirmed in
    //   W11-JPR-LAB01 logs 2026-06-30: a clean HELLO→idle→close→reconnect
    //   loop at exactly the 270s mark, every heartbeat and ACK healthy.
    //   This mirrors the bidirectional logic the silence watchdog in
    //   grpc-stream already uses; isConnected() was simply left behind.
    //
    // ZOMBIE SAFETY — why a successful send is now trusted as liveness:
    //   The half-open-TCP case the old receive-only gate guarded against
    //   is already caught FASTER and more reliably one layer down. The
    //   PrivSvc bridge runs HTTP/2 keepalive (KeepAlivePingDelay=20s,
    //   KeepAlivePingTimeout=10s — see GrpcBridge.cs) and pushes
    //   `grpc.disconnected` within ~30s of a dead socket → the
    //   remote_disconnect path here. And a heartbeat the bridge cannot
    //   write throws → `stream.emit("error", …)` → reconnect (see the
    //   heartbeat IPC handler below). So a successful heartbeat write is
    //   valid end-to-end liveness proof, and the receive-only gate was
    //   redundant with the bridge keepalive while being the SOLE cause
    //   of the idle churn.
    isConnected: () => {
      if (!connected) return false;
      const now = Date.now();
      const recvFresh = now - lastServerActivityMs <= SILENCE_THRESHOLD_MS;
      const sendFresh = now - lastClientSendOkMs <= SILENCE_THRESHOLD_MS;
      return recvFresh || sendFresh;
    },
    // Explicit teardown. Callers (grpc-stream's reconnect loop) use
    // this when they've decided the current client is unrecoverable
    // — e.g. silence-watchdog tripped, isConnected() returned false,
    // or an error event was emitted. Without it, the only way to
    // invalidate the singleton was from inside grpc-client itself
    // (push handler / stream.end), which left the reconnect loop
    // unable to force a clean slate when those signals didn't fire.
    close: () => {
      // End the local stream (which already invalidates the cache and
      // notifies privsvc) — gated on `ended` so a no-op double-close
      // is safe.
      try {
        stream.end?.();
      } catch (e: any) {
        ctx.logger?.warn?.("[grpc-client] close: stream.end threw", e?.message || e);
        // Belt-and-braces: if stream.end didn't run cleanly, still
        // drop the cached instance ourselves.
        invalidateCachedClient("close_fallback");
      }
    }
  };

  (ctx as any).__grpcClientInstance = client;

  return client;
} 
