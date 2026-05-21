// src/transport/grpc-stream.ts
import { AgentContext } from "../core/agent-context";
import { createGrpcClient } from "./grpc-client";
import { outbox } from "../queue/sqlite-outbox";
import { PolicyStore } from "../core/policy-store";
import { buildDeviceFacts } from "../domain/device-facts-builder";
import type { Namespaces, DeviceFacts } from "../domain/device-facts";
import type { PmpNamespace } from "../domain/pmp-types";
import { updatePmpState, isRemediateInFlight } from "../plugins/pmp/state";
import { runRemediation } from "../plugins/pmp/remediation";
import { runSoftwareInstall } from "../plugins/sdp";
import { runUpdateTask } from "../update/update-task";

const ACK_TIMEOUT_MS = 60_000;
const MAX_IN_FLIGHT = 3;
const HEARTBEAT_INTERVAL_MS = 60_000;

// Server-silence watchdog. When a backend instance dies ungracefully
// (SIGKILL, OOM, network change, sleep/wake), the bridge layer often
// doesn't see a clean FIN/RST and the kernel TCP keepalive default
// won't fire for ~2 hours. Result: the agent thinks it's online,
// the dashboard says it's offline, and jobs fail with stream_not_found.
//
// The fix is application-level: every server message updates a
// `lastServerActivityMs` stamp on the stream object (see grpc-client
// attachPrivPushHandler). This watchdog ticks every 30s and forces a
// reconnect if the gap exceeds SILENCE_THRESHOLD_MS. With the server
// pinging at 90s, a healthy stream sees activity at most ~95s apart;
// 270s = 3× ping gives one missed-ping margin for lossy networks
// before declaring zombie.
//
// Trade-off: at 90s server ping × 10K agents the server emits
// ~111 pings/sec — well within budget for the bug fixed.
const WATCHDOG_TICK_MS = 30_000;
const SILENCE_THRESHOLD_MS = 270_000;

// Exponential backoff with full jitter for gRPC reconnect.
//
// Why: a flat 5s delay means every agent in a tenant reconnects on the
// same cadence after a backend deploy, hammering the new replicas and
// masking transient failures. Exponential with jitter spreads the herd.
//
// Schedule (worst-case deterministic):
//   attempt 0 →   0..2s
//   attempt 1 →   2..6s
//   attempt 2 →   4..12s
//   attempt 3 →   8..24s
//   attempt 4 →  16..48s
//   attempt 5+ → capped at 30..60s
//
// On first successful `data` event from the server we reset the counter
// to 0 — that's our "READY" signal; a socket that merely opened but got
// rejected (e.g. auth failure, TLS mismatch) won't produce data and the
// counter keeps climbing, which is what we want.
const RECONNECT_BASE_MS = 2_000;
const RECONNECT_MAX_MS = 60_000;
let reconnectAttempts = 0;

function nextReconnectDelayMs(): number {
  // min(base * 2^attempt, max) + uniform jitter [0, base * 2^attempt)
  const exp = Math.min(
    RECONNECT_BASE_MS * Math.pow(2, Math.min(reconnectAttempts, 6)),
    RECONNECT_MAX_MS
  );
  const jitter = Math.random() * exp;
  return Math.min(exp + jitter, RECONNECT_MAX_MS * 2);
}

let shutdownRequested = false;

// `reconnecting` prevents double-scheduling when `error` and `end` fire
// back-to-back on the same broken stream — both handlers call
// `scheduleReconnect`, and without this guard we'd start two agents.
let reconnecting = false;

// -----------------------------------------------------------------------------
// Structured metrics
// -----------------------------------------------------------------------------
// We don't have a Prometheus scrape endpoint (the agent is behind every
// customer's egress firewall), so for production diagnosis we emit a
// periodic structured log line like:
//
//   logger.info("grpc.metrics", { reconnectCount: 7, heartbeatSent: 312, ... })
//
// That hits the launchd log, gets captured by whatever log shipper the
// tenant runs, and is easy to grep retroactively when a device shows up
// offline. Cheap, no infra dependency, survives restarts (counters are
// session-scoped — a fresh daemon starts at 0, which is itself useful
// because a restart is an observability event).
//
// Keep this intentionally small: five counters and a timestamp. More
// fields = more pressure to evolve into a real metrics system, which
// we don't want here.
const METRICS_FLUSH_INTERVAL_MS = 5 * 60 * 1000;

const grpcMetrics = {
  reconnectCount: 0,
  heartbeatSent: 0,
  heartbeatFailed: 0,
  ackReceived: 0,
  outboxDrainLeases: 0,
  connectedSinceUtc: null as string | null
};

type PmpRemediationResult = NonNullable<NonNullable<PmpNamespace["remediation"]>["results"]>[number];

let metricsFlushTimer: NodeJS.Timeout | null = null;

function armMetricsFlush(ctx: AgentContext) {
  if (metricsFlushTimer) return; // already armed (first stream only)
  metricsFlushTimer = setInterval(() => {
    try {
      ctx.logger?.info?.("grpc.metrics", { ...grpcMetrics });
    } catch {
      // never let a log failure kill the transport
    }
  }, METRICS_FLUSH_INTERVAL_MS);
  // Don't let this keep the process alive during shutdown.
  (metricsFlushTimer as any)?.unref?.();
}

function buildEventId(deviceId: string, outboxId: number) {
  return `${deviceId}:${outboxId}`;
}

function normalizePmpResults(results: unknown): NonNullable<PmpNamespace["remediation"]>["results"] {
  if (!Array.isArray(results)) {
    return [];
  }

  return results.map((entry) => {
    const item = (entry && typeof entry === "object") ? entry as Record<string, unknown> : {};
    const rawResult = String(item.result || "failed").trim().toLowerCase();
    const result: PmpRemediationResult["result"] =
      rawResult === "installed" || rawResult === "downloaded" || rawResult === "skipped"
        ? rawResult
        : "failed";

    return {
      updateId: item.updateId ? String(item.updateId) : undefined,
      kb: item.kb ? String(item.kb) : undefined,
      title: item.title ? String(item.title) : undefined,
      result,
      hresult: item.hresult ? String(item.hresult) : undefined,
      message: item.message ? String(item.message) : undefined
    };
  });
}

// Minimum gap between scheduler-emitted and control-forced facts of
// the same factType. The scheduler ticks slowly (hourly+), so 60s is
// a comfortable window: any control message that lands inside this
// window is overwhelmingly a duplicate (the backend's job dispatcher
// re-asks for a snapshot moments after a regular send) and we'd be
// shipping a near-identical fact for no operator benefit. The
// observed failure mode without this guard was a paired empty-twin
// fact 4s after every full snapshot — see the JPR-MacBookPro tenant
// DB inspection that motivated the fix.
const CONTROL_FACTS_COOLDOWN_MS = 60_000;

const FACT_TYPE_COOLDOWN_KEYS: Record<string, string> = {
  inventory:  "lastSentFactsAt:inventory",
  compliance: "lastSentFactsAt:compliance",
  patch:      "lastSentFactsAt:patch"
};

function isOnCooldown(factType: string): { skip: boolean; ageMs: number | null } {
  const key = FACT_TYPE_COOLDOWN_KEYS[factType];
  if (!key) return { skip: false, ageMs: null };
  try {
    const raw = outbox.getState(key);
    if (!raw) return { skip: false, ageMs: null };
    const ts = Number(raw);
    if (!Number.isFinite(ts)) return { skip: false, ageMs: null };
    const ageMs = Date.now() - ts;
    return { skip: ageMs < CONTROL_FACTS_COOLDOWN_MS && ageMs >= 0, ageMs };
  } catch {
    return { skip: false, ageMs: null };
  }
}

async function collectFactsSnapshot(
  ctx: AgentContext,
  source: string,
  factType = "inventory"
) {
  // Cooldown guard: if the scheduler already shipped a fact of this
  // type within CONTROL_FACTS_COOLDOWN_MS, skip the redundant collect.
  // Returns a sentinel `outboxId: 0` and `cooldown: true` so the
  // runJob handler can ACK back as a no-op success rather than a
  // failure — the backend asked for fresh data, we just shipped it.
  // factType "all" still goes through (rare, only when explicitly
  // requested) since at least one of its components is always due.
  if (factType !== "all") {
    const { skip, ageMs } = isOnCooldown(factType);
    if (skip) {
      ctx.logger?.info?.("FACTS_SNAPSHOT skipped — cooldown active", {
        source,
        factType,
        ageMs,
        cooldownMs: CONTROL_FACTS_COOLDOWN_MS
      });
      return {
        outboxId: 0,
        modules: [],
        softwareCount: 0,
        cooldown: true,
        ageMs
      };
    }
  }

  const namespaces = {} as Namespaces;

  if ((factType === "inventory" || factType === "all") && ctx.policyRuntime.isInventoryEnabled() && ctx.policyRuntime.pluginEnabled("amp")) {
    try {
      namespaces.amp = await ctx.plugins.run("amp.collect");
    } catch (err) {
      ctx.logger?.error?.(`AMP collect failed (${source})`, { err });
    }
  }

  if ((factType === "compliance" || factType === "all") && ctx.policyRuntime.isComplianceEnabled() && ctx.policyRuntime.pluginEnabled("scp")) {
    try {
      namespaces.scp = await ctx.plugins.run("scp.collect");
    } catch (err) {
      ctx.logger?.error?.(`SCP collect failed (${source})`, { err });
    }
  }

  if ((factType === "patch" || factType === "all") && ctx.policyRuntime.isPatchEnabled() && ctx.policyRuntime.pluginEnabled("pmp")) {
    try {
      namespaces.pmp = await ctx.plugins.run("pmp.collect");
    } catch (err) {
      ctx.logger?.error?.(`PMP collect failed (${source})`, { err });
    }
  }

  if (Object.keys(namespaces).length === 0) {
    throw new Error(`${source}: no plugin namespaces collected`);
  }

  // Rehydrate software items from the persisted baseline when the AMP
  // collector returned `items: undefined` (its delta-detection path
  // returns no items when nothing changed since the last scan). A
  // control-message-driven snapshot is supposed to be a *complete*
  // picture of the device — without rehydration the backend gets a
  // partial fact (count present, items missing) and the recent
  // tenant-DB inspection on JPR-MacBookPro showed exactly this
  // pathology: every full snapshot was followed ~4s later by a paired
  // empty snapshot from this control path. Mirroring the scheduler's
  // `needsRehydrate` logic eliminates the empty-twin sends.
  if (namespaces.amp?.software && namespaces.amp.software.items == null) {
    try {
      const { loadSoftwareBaseline } = await import("../domain/software-baseline-repo");
      const baseline = loadSoftwareBaseline() ?? [];
      if (baseline.length > 0) {
        namespaces.amp.software.items = baseline as any;
        namespaces.amp.software.count = baseline.length;
      }
    } catch (err) {
      ctx.logger?.warn?.("Failed to rehydrate AMP software baseline for control-forced snapshot", { err });
    }
  }

  const facts = await buildDeviceFacts(ctx, namespaces);
  const outboxId = outbox.enqueue({
    type: "FACTS_SNAPSHOT",
    payload: facts
  });

  // Stamp the cooldown so a backend retry of this same job (or a
  // separate scheduler tick that lands in the next minute) is treated
  // as redundant. Symmetric with the scheduler's own stamping.
  const cooldownKey = FACT_TYPE_COOLDOWN_KEYS[factType];
  if (cooldownKey) {
    try {
      outbox.setState(cooldownKey, String(Date.now()));
    } catch (err) {
      ctx.logger?.warn?.("Failed to stamp cooldown after control-forced send", { factType, err });
    }
  }

  const softwareCount = Number(namespaces.amp?.software?.count ?? 0);

  ctx.logger?.info?.("FACTS_SNAPSHOT enqueued from control message", {
    source,
    factType,
    outboxId,
    modules: Object.keys(namespaces),
    softwareCount
  });

  return {
    outboxId,
    modules: Object.keys(namespaces),
    softwareCount
  };
}

async function sendControlAck(
  ctx: AgentContext,
  eventId: string,
  status: number,
  message: string
) {
  try {
    await (ctx.priv as any).call({
      v: 1,
      id: `ack-${eventId}`,
      method: "grpc.ack",
      params: {
        eventId,
        status,
        message
      }
    });

    ctx.logger?.info?.("[grpc-stream] control ACK sent", {
      eventId,
      status,
      message
    });
  } catch (ackErr: any) {
    const errMessage = String(ackErr?.message || ackErr);

    if (errMessage.includes("not_supported")) {
      ctx.logger?.warn?.("[grpc-stream] ACK not supported by PrivSvc yet, skipping", {
        eventId,
        status
      });
      return;
    }

    ctx.logger?.error?.("[grpc-stream] failed to send control ACK", {
      eventId,
      status,
      err: errMessage
    });
  }
}

function parseRunJobPayload(runJob: any): any {
  const directPayload = runJob?.payload ?? runJob?.params;
  if (directPayload && typeof directPayload === "object") return directPayload;

  const rawPayload = runJob?.payloadJson;
  if (!rawPayload) return {};

  let payloadJson: string;
  if (Buffer.isBuffer(rawPayload)) payloadJson = rawPayload.toString("utf8");
  else if (rawPayload instanceof Uint8Array) payloadJson = Buffer.from(rawPayload).toString("utf8");
  else if (typeof rawPayload === "string") payloadJson = rawPayload;
  else return {};

  try {
    const parsed = JSON.parse(payloadJson);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function executeRunJob(ctx: AgentContext, runJob: any) {
  const jobId = String(runJob?.jobId || "").trim();
  const jobType = String(
    runJob?.jobType ||
    runJob?.type ||
    runJob?.task ||
    ""
  ).trim();
  const payload = parseRunJobPayload(runJob);

  if (!jobId) {
    return {
      status: 2,
      message: "runJob rejected: missing jobId"
    };
  }

  if (!jobType) {
    return {
      status: 2,
      message: "runJob rejected: missing jobType/payload in control message"
    };
  }

  switch (jobType) {
    case "facts_snapshot": {
      const factType = String(payload?.factType || "inventory");
      const result = await collectFactsSnapshot(ctx, `runJob:${jobId}`, factType);
      // Cooldown hit → ACK as success with a recognizable message so
      // the backend's job dispatcher records the job as completed
      // without thinking we lost it. The "fresh" message is a hint to
      // operators that the data they're about to look at is current.
      if ((result as any).cooldown) {
        return {
          status: 0,
          message: `facts_fresh:cooldown_${(result as any).ageMs}ms`
        };
      }
      return {
        status: 0,
        message: `facts_enqueued:${result.outboxId}`
      };
    }

    case "patch_scan": {
      if (!ctx.policyRuntime.isPatchEnabled()) {
        return {
          status: 2,
          message: "patch_scan rejected: patch module disabled by policy"
        };
      }

      if (!ctx.policyRuntime.pluginEnabled("pmp")) {
        return {
          status: 2,
          message: "patch_scan rejected: pmp plugin disabled by policy"
        };
      }

      const result = await collectFactsSnapshot(ctx, `runJob:${jobId}`, "patch");
      if ((result as any).cooldown) {
        return {
          status: 0,
          message: `patch_scan_fresh:cooldown_${(result as any).ageMs}ms`
        };
      }
      return {
        status: 0,
        message: `patch_scan_enqueued:${result.outboxId}`
      };
    }

    case "patch_install": {
      if (!ctx.policyRuntime.isPatchEnabled()) {
        return {
          status: 2,
          message: "patch_install rejected: patch module disabled by policy"
        };
      }

      if (!ctx.policyRuntime.pluginEnabled("pmp")) {
        return {
          status: 2,
          message: "patch_install rejected: pmp plugin disabled by policy"
        };
      }

      if ((ctx as any)._patchInstallInProgress) {
        return {
          status: 1,
          message: "patch_install retry: patch install already in progress"
        };
      }

      // PMv2 cross-lock: refuse a patch_install while a
      // patch_remediate is in flight. The remediate path uses a
      // module-level flag in plugins/pmp/state.ts; the install
      // path uses _patchInstallInProgress on ctx. Both check the
      // OTHER lock so a registry edit can't race a Windows Update
      // installer.
      if (isRemediateInFlight()) {
        return {
          status: 1,
          message: "patch_install retry: patch_remediate in progress"
        };
      }

      const mode = String(payload?.mode || "install").trim().toLowerCase();
      const kbArticleIds = Array.isArray(payload?.kbArticleIds)
        ? payload.kbArticleIds.map((item: unknown) => String(item || "").trim()).filter(Boolean)
        : [];

      if (mode !== "install" && mode !== "download") {
        return {
          status: 2,
          message: "patch_install rejected: invalid mode"
        };
      }

      (ctx as any)._patchInstallInProgress = true;
      updatePmpState({
        status: "in_progress",
        mode,
        startedAtUtc: new Date().toISOString(),
        selectedCount: kbArticleIds.length || undefined,
        installedCount: 0,
        failedCount: 0,
        rebootRequired: false,
        results: [],
        lastError: undefined
      });

      try {
        try {
          const resp = await ctx.priv.call({
            v: 1,
            id: `patch-install-${jobId}-${Date.now()}`,
            method: "patch.install",
            params: {
              mode,
              kbArticleIds
            },
            meta: {
              tenantId: ctx.enrollment.tenantId,
              deviceId: ctx.enrollment.deviceId
            }
          });

          if (!resp?.ok) {
            updatePmpState({
              status: "failed",
              mode,
              finishedAtUtc: new Date().toISOString(),
              lastError: String(resp?.error?.message || "patch.install failed"),
              rebootRequired: false,
              results: []
            });
            return {
              status: 2,
              message: `patch_install failed: ${String(resp?.error?.message || "patch.install failed")}`
            };
          }

          const result = resp.result || {};
          const resultStatus = String(result?.status || "").trim().toLowerCase();
          const installedCount = Number(result?.installedCount ?? 0);
          const failedCount = Number(result?.failedCount ?? 0);
          const rebootRequired = result?.rebootRequired === true;
          const results = normalizePmpResults(result?.results);

          updatePmpState({
            status: resultStatus === "success" || resultStatus === "no_updates"
              ? "success"
              : resultStatus === "partial"
                ? "partial"
                : "failed",
            mode,
            finishedAtUtc: new Date().toISOString(),
            rebootRequired,
            selectedCount: Number(result?.selectedCount ?? kbArticleIds.length ?? 0),
            installedCount,
            failedCount,
            results,
            lastError: resultStatus === "success" || resultStatus === "no_updates"
              ? undefined
              : `patch_install ${resultStatus || "failed"}`
          });

          try {
            await collectFactsSnapshot(ctx, `runJob:${jobId}:post_patch_install`, "patch");
          } catch (err) {
            ctx.logger?.warn?.("Post patch-install scan enqueue failed", { err, jobId });
          }

          if (resultStatus === "success" || resultStatus === "no_updates") {
            return {
              status: 0,
              message: `patch_install ${resultStatus}; installed=${installedCount}; failed=${failedCount}; rebootRequired=${rebootRequired}`
            };
          }

          return {
            status: 2,
            message: `patch_install ${resultStatus || "failed"}; installed=${installedCount}; failed=${failedCount}; rebootRequired=${rebootRequired}`
          };
        } catch (err: any) {
          updatePmpState({
            status: "failed",
            mode,
            finishedAtUtc: new Date().toISOString(),
            lastError: err?.message || String(err),
            rebootRequired: false,
            results: []
          });
          throw err;
        };
      } finally {
        (ctx as any)._patchInstallInProgress = false;
      }
    }

    case "patch_remediate": {
      // Patch Management v2 — non-patch security remediation
      // (TLS, ciphers, SMB, firewall). Routed through the existing
      // PMP plugin so it shares the install/remediate concurrency
      // lock; envelope + outcome encoding follow the same pattern
      // as software_install (see runRemediation in
      // plugins/pmp/remediation.ts).
      try {
        const ack = await runRemediation(ctx, jobId, payload);
        return { status: ack.ackStatus, message: ack.ackMessage };
      } catch (err: any) {
        // runRemediation is documented as non-throwing — this is a
        // belt-and-braces guard. Treat as transient so the
        // orchestrator may retry (a transient privsvc IPC blip
        // shouldn't burn the job).
        ctx.logger?.error?.("patch_remediate handler threw unexpectedly", {
          jobId,
          error: err?.message || String(err),
        });
        return {
          status: 1,
          message: `patch_remediate:failed;remediationId=${Number(payload?.remediationId) || 0};reason=handler_threw`,
        };
      }
    }

    case "software_install": {
      // SDP — Phase 1. The plugin returns a structured ack contract
      // (ackStatus / ackMessage / outcome) that we surface as-is to
      // the orchestrator. The plugin is responsible for owning
      // concurrency, retries decisions, and the privsvc dance — we
      // only translate to the runJob ack envelope here.
      //
      // Outcome ∈ { success, already_installed, reboot_required,
      //             failed, rejected, timed_out } is encoded in the
      // ack message as `software_install:<outcome>;...` so the
      // backend's P1-G ack handler can update software_install_results
      // without needing a new gRPC field.
      try {
        const ack = await runSoftwareInstall(ctx, jobId, payload);
        return { status: ack.ackStatus, message: ack.ackMessage };
      } catch (err: any) {
        // runSoftwareInstall is documented as non-throwing — if it
        // does throw, treat as transient. Should not happen.
        ctx.logger?.error?.("software_install handler threw unexpectedly", {
          jobId,
          error: err?.message || String(err),
        });
        return {
          status: 1,
          message: `software_install:failed;deploymentId=${Number(payload?.deploymentId) || 0};reason=handler_threw`,
        };
      }
    }

    case "reset_baseline": {
      // M1 (cold-projection recovery): the backend asks us to drop
      // the local namespace-hash cache so the next compliance tick
      // re-sends a full baseline snapshot instead of another delta.
      // The backend dispatches this when its projection table
      // (software_current_app today; pmp/scp tables could follow
      // the same pattern) is empty for this device but the agent is
      // sending deltas — a divergence we want to self-heal rather
      // than wait for manual operator intervention.
      const namespace = String(payload?.namespace || "").trim().toLowerCase();
      if (namespace !== "amp") {
        // Only "amp" is wired today (it's the only namespace with a
        // delta protocol). Others reject cleanly so a future
        // backend that dispatches a different namespace gets a
        // recognizable error in audit instead of silent acceptance.
        return {
          status: 2,
          message: `reset_baseline rejected: unsupported namespace "${namespace}"`,
        };
      }
      const stateKey = `namespaceHash:${namespace}`;
      try {
        // outbox.deleteState() with a falsy default. The actual
        // behavior of "clear" we want is: forget the prior hash so
        // the next collect pass sees `previousHash !== currentHash`
        // and enqueues. setState("") is equivalent — empty string
        // can't match any sha256 output.
        outbox.setState(stateKey, "");
        ctx.logger?.warn?.("[reset_baseline] cleared namespace hash, next compliance tick will re-send baseline", {
          namespace,
          stateKey,
        });
        return {
          status: 0,
          message: `reset_baseline:cleared:${namespace}`,
        };
      } catch (err: any) {
        ctx.logger?.error?.("[reset_baseline] failed to clear state", {
          namespace,
          error: err?.message || String(err),
        });
        return {
          status: 1,
          message: `reset_baseline:state_write_failed:${err?.message || "unknown"}`,
        };
      }
    }

    case "agent_update": {
      const version = String(payload?.version || runJob?.version || "").trim();
      if (!version) {
        return {
          status: 2,
          message: "agent_update rejected: missing version"
        };
      }

      // ── Optional payload overrides (Phase 11) ────────────────────
      //
      // The dispatcher MAY include `downloadUrl` + `expectedHash` in
      // the payload to force a specific binary location instead of
      // routing through the `/binaries/agent/metadata` lookup. Useful
      // for hot-fixes, controlled downgrades, and rescuing devices on
      // a broken update-task that wouldn't otherwise pick up the
      // metadata's latestVersion. Both fields must travel together —
      // runUpdateTask enforces the pairing and rejects half-set
      // overrides explicitly so we don't silently fall back to a
      // metadata lookup the operator didn't authorize.
      //
      // Hash is normalized to lowercase hex on the agent side because
      // downstream comparison is case-insensitive but it's cheaper to
      // canonicalize once than to lowercase on every compare.
      const downloadUrl = payload?.downloadUrl ? String(payload.downloadUrl).trim() : undefined;
      const expectedHash = payload?.expectedHash
        ? String(payload.expectedHash).trim().toLowerCase()
        : undefined;

      if ((ctx as any)._agentUpdateInProgress) {
        return {
          status: 1,
          message: "agent_update retry: update already in progress"
        };
      }

      (ctx as any)._agentUpdateInProgress = true;
      try {
        await runUpdateTask(ctx, {
          targetVersion: version,
          downloadUrl,
          expectedHash,
          logger: ctx.logger
        });

        return {
          status: 0,
          message: "update_completed"
        };
      } finally {
        (ctx as any)._agentUpdateInProgress = false;
      }
    }

    default:
      return {
        status: 2,
        message: `runJob rejected: unsupported jobType ${jobType}`
      };
  }
}

export function startGrpcStream(ctx: AgentContext) {
  shutdownRequested = false;
  // We're actively starting a stream now; if scheduleReconnect fires
  // later it can safely set `reconnecting = true` again.
  reconnecting = false;

  // RCP M1.S1 — install the outbound control-message write surface
  // for plugins that don't fit the FACTS / job lifecycle. The RCP
  // SessionManager calls this to send RemoteSessionAnswer / Ice /
  // Close / Error back to the backend over the existing stream.
  // We route through PrivSvc (same path as ACKs) so PrivSvc remains
  // the single owner of the gRPC connection.
  if (!ctx.sendControl) {
    ctx.sendControl = (msg: any) => {
      // Identify the oneof variant for PrivSvc routing. Each
      // method maps to a single proto field on the C# side. PrivSvc
      // serializes the params into the appropriate ControlMessage
      // and writes to the gRPC stream.
      const variants: Array<[string, string]> = [
        ["remoteSessionAnswer", "grpc.send.remoteSessionAnswer"],
        ["remoteSessionIce", "grpc.send.remoteSessionIce"],
        ["remoteSessionClose", "grpc.send.remoteSessionClose"],
        ["remoteSessionError", "grpc.send.remoteSessionError"],
        // Sprint 3 — transcript chunks (agent → server) for audit
        // persistence into remote_session_io.
        ["remoteSessionTranscript", "grpc.send.remoteSessionTranscript"]
      ];
      for (const [field, method] of variants) {
        if (msg && msg[field]) {
          (ctx.priv as any)
            .call({ v: 1, id: `${field}-${Date.now()}`, method, params: msg[field] })
            .catch((err: any) => {
              ctx.logger?.warn?.(`[rcp] ${method} failed`, {
                err: err?.message || String(err)
              });
            });
          return;
        }
      }
      ctx.logger?.warn?.("[rcp] sendControl: unknown message shape", {
        keys: msg ? Object.keys(msg) : []
      });
    };
  }

  let startDelayTimer: NodeJS.Timeout | null = null;
  let retryTimer: NodeJS.Timeout | null = null;
  let reconnectTimer: NodeJS.Timeout | null = null;
  // Heartbeat is a chained setTimeout (not setInterval) so we can
  // re-anchor the next fire time whenever the bridge goes through a
  // state change (READY, rotation-end, etc.) without inheriting the
  // setInterval's fixed wall-clock cadence from the previous cycle.
  let heartbeatTimer: NodeJS.Timeout | null = null;
  // Server-silence watchdog. setInterval is fine here — we want a
  // fixed cadence regardless of stream state. Cleared in stop().
  let watchdogTimer: NodeJS.Timeout | null = null;
  let unsubscribeOutbox: (() => void) | null = null;
  let draining = false;
  let drainScheduled = false;
  const runningJobIds = new Set<string>();
  const client: any = createGrpcClient(ctx);
  ctx.logger?.info?.("gRPC stream: creating client");
let stream: any;
stream = client.Connect();
// NOTE: pending ACK tracking removed; outbox lifecycle handled by grpc-client ACKs

  let rotationInProgress = false;
  let stopped = false;
  // ensure state reset on each stream start
  rotationInProgress = false;

  // Load persisted baseline hash and sent flag from SQLite state
  let lastBaselineHash: string | null = null;
  let baselineSent = false;
  try {
    lastBaselineHash = outbox.getState("baselineHash:amp");
    baselineSent = outbox.getState("baselineSent:amp") === "1";
  } catch {
    lastBaselineHash = null;
    baselineSent = false;
  }

  const stop = (opts?: { localClose?: boolean }) => {
    if (stopped) return;
    ctx.logger?.warn?.("gRPC stream: stop() invoked, closing stream and timers");
    stopped = true;
    rotationInProgress = false;
    try { if (startDelayTimer) clearTimeout(startDelayTimer); } catch {}
    try { if (retryTimer) clearTimeout(retryTimer); } catch {}
    try { if (reconnectTimer) clearTimeout(reconnectTimer); } catch {}
    try { if (heartbeatTimer) clearTimeout(heartbeatTimer); } catch {}
    heartbeatTimer = null;
    try { if (watchdogTimer) clearInterval(watchdogTimer); } catch {}
    watchdogTimer = null;
    try { stream.removeAllListeners(); } catch {}

    try { unsubscribeOutbox?.(); } catch {}
    unsubscribeOutbox = null;

    if (opts?.localClose) {
      try { stream.end(); } catch {}
    }
  };

  // Arm a single-shot heartbeat timer. Each fire re-arms the next one,
  // so the cadence is always anchored at "last heartbeat attempt" rather
  // than "T=0 of this stream life". Call this from READY to reset the
  // phase; no-op if the stream has already stopped.
  const armHeartbeat = () => {
    if (stopped) return;
    if (heartbeatTimer) {
      clearTimeout(heartbeatTimer);
      heartbeatTimer = null;
    }
    heartbeatTimer = setTimeout(() => {
      heartbeatTimer = null;
      if (stopped) return;
      try {
        if (rotationInProgress) {
          // During rotation we skip the write but still re-anchor the
          // next attempt from NOW — otherwise, coming out of a multi-
          // minute rotation we'd have a stale 60-s-ago tick firing
          // immediately as soon as rotationInProgress flips off.
          armHeartbeat();
          return;
        }
        if (!stream) {
          // No stream object at all — defensive guard. Re-arming
          // here would NPE on the write below.
          return;
        }
        if (!client.isConnected?.()) {
          // BEFORE Patch D: we returned silently here on the
          // assumption that READY would re-kick us. That created a
          // dead-end after the silence-staleness check in
          // `isConnected()` (Patch B): once `lastServerActivityMs`
          // crossed SILENCE_THRESHOLD_MS, `isConnected()` started
          // reporting false even with the local `connected` flag
          // still true — heartbeats stopped, NOTHING ELSE on either
          // side noticed (privsvc thinks it's still connected, no
          // grpc.disconnected push ever arrives), and the stream sat
          // zombie until an operator kicked privsvc by hand.
          //
          // Patch D — treat this exactly like an explicit error:
          // mark tray disconnected immediately, emit("error") so the
          // existing on("error") flow runs `stop()` + scheduleReconnect()
          // → eventual `priv.call("grpc.connect")` that opens a fresh
          // socket. The heartbeat path becomes the active liveness
          // detector when the watchdog hasn't fired (e.g. because
          // `lastServerActivityMs` was updated by some non-server
          // event we shouldn't have counted as activity).
          ctx.logger?.warn?.("gRPC stream: heartbeat tick saw stale connection, forcing reconnect");
          try { ctx.trayStatus.markGrpcDisconnected(); } catch {}
          try { stream.emit("error", new Error("heartbeat_saw_stale_connection")); } catch {}
          return;
        }

        stream.write({
          heartbeat: {
            deviceId: ctx.enrollment.deviceId,
            tenantId: ctx.enrollment.tenantId,
            agentVersion: ctx.config.agentVersion,
            ts: Date.now()
          }
        });
        grpcMetrics.heartbeatSent += 1;
      } catch (err: any) {
        grpcMetrics.heartbeatFailed += 1;
        ctx.logger?.error?.("Heartbeat send failed", err?.message || err);
      } finally {
        // Re-arm regardless of success — a transient write failure
        // shouldn't silence heartbeats forever. (When we DO bail out
        // via the staleness branch above, we returned BEFORE this
        // finally — `stop()` will run via the on("error") handler
        // and clear the timer state cleanly.)
        armHeartbeat();
      }
    }, HEARTBEAT_INTERVAL_MS);
  };

  // Arm the server-silence watchdog. Reads `lastServerActivityMs`
  // from the stream object (set by grpc-client.attachPrivPushHandler
  // on every server push). If the stamp is older than
  // SILENCE_THRESHOLD_MS we treat the stream as zombie and force a
  // reconnect via the same code path that handles bridge errors —
  // emit("error") flows into stop() + scheduleReconnect.
  //
  // We don't `stop()` directly here so the existing reconnect
  // serialization (`reconnecting` flag + exponential backoff) still
  // applies. If the reason is genuine network change, the agent
  // will back off correctly instead of hammer-reconnecting.
  const armWatchdog = () => {
    if (stopped) return;
    if (watchdogTimer) {
      clearInterval(watchdogTimer);
      watchdogTimer = null;
    }
    watchdogTimer = setInterval(() => {
      if (stopped) return;
      const lastActivityMs = (stream as any).getLastServerActivityMs?.();
      if (typeof lastActivityMs !== "number") {
        // Stream object doesn't expose the tracker — older bridge
        // build, fail open (don't trigger spurious reconnects).
        return;
      }
      const silentMs = Date.now() - lastActivityMs;

      // Outbound liveness signal — track the LAST time we successfully
      // wrote something onto the gRPC stream via PrivSvc. Without this
      // counterpart, the watchdog used to false-fire every
      // SILENCE_THRESHOLD_MS on idle devices: the server doesn't ACK
      // heartbeats by design, so on a device that isn't generating
      // FACTS, `lastServerActivityMs` legitimately doesn't update —
      // but the stream is perfectly alive (heartbeats keep flowing
      // outbound, the bridge's HTTP/2 keepalive ping-pong runs every
      // 20s underneath, etc.). Real zombie streams DO show up here:
      // if the wire is half-open, the bridge's `WriteAsync` throws,
      // privsvc returns ok:false, and `lastClientSendOkMs` stops
      // updating — that's when we want to fire.
      //
      // Confirmed empirically in VM logs 2026-05-19 after host Mac
      // wake from sleep: 27 spurious reconnects over 2h, every cycle
      // ending with `silentMs ≈ 271000 / thresholdMs: 270000`, every
      // HELLO ACK succeeding, every FACTS ACK succeeding, every
      // heartbeat sent — pure agent-side false positive.
      const lastSendOkMs = (stream as any).getLastClientSendOkMs?.();
      const sendIdleMs = typeof lastSendOkMs === "number"
        ? Date.now() - lastSendOkMs
        : Infinity; // older bridge build → defer to receive-only check

      // Require BOTH directions stale before declaring zombie. Either
      // direction having recent activity is sufficient evidence the
      // stream is alive end-to-end.
      if (silentMs > SILENCE_THRESHOLD_MS && sendIdleMs > SILENCE_THRESHOLD_MS) {
        ctx.logger?.warn?.("gRPC stream: bidirectional silence past threshold, forcing reconnect", {
          silentMs,
          sendIdleMs,
          thresholdMs: SILENCE_THRESHOLD_MS
        });
        // Mark tray disconnected immediately. The PrivSvc bridge is
        // supposed to push `grpc.disconnected` when the stream dies —
        // but if we got here it's BECAUSE the bridge has gone silent
        // and is failing to emit anything (zombie TCP / half-open
        // socket post sleep+wake). Without this nudge, the tray keeps
        // showing green for the entire reconnect cycle (potentially
        // minutes) while the dashboard already shows the device as
        // offline. Same fix as the catch in scheduleReconnect.
        try { ctx.trayStatus.markGrpcDisconnected(); } catch {}
        // Tear down via the standard error path so reconnect
        // scheduling and metrics increment work as designed.
        try {
          stream.emit("error", new Error("server_silent_timeout"));
        } catch {}
      }
    }, WATCHDOG_TICK_MS);
    (watchdogTimer as any)?.unref?.();
  };

  const scheduleReconnect = (reason: string) => {
    if (shutdownRequested) return;
    // Both stream.on("error") and stream.on("end") can fire for the same
    // broken connection. Without this guard we'd schedule two reconnects
    // and spawn two concurrent startGrpcStream calls.
    if (reconnecting) {
      ctx.logger?.debug?.("gRPC stream: reconnect already scheduled, ignoring", { reason });
      return;
    }
    reconnecting = true;

    // Reset the "currently connected since" timestamp — disconnect just
    // happened, we are NOT connected, and the next metrics flush should
    // reflect that. The frozen production zombie kept dumping
    // `connectedSinceUtc: '2026-05-11T03:43:31.467Z'` in every 5-minute
    // metrics line for ~36 hours because this field was only ever set
    // (on READY), never cleared. That timestamp lied about agent
    // liveness to anyone scanning logs.
    grpcMetrics.connectedSinceUtc = null;

    // Force-close the current client even if the disconnect path
    // (push handler / stream.end) already nullified the singleton.
    // Idempotent; cost is one no-op IPC call. Without this, an error
    // path that emits stream.emit("error", …) WITHOUT calling end()
    // or sending a `grpc.disconnected` push (see grpc-client.ts:511,
    // 524, 547, 557) leaves the per-ctx cached instance in place,
    // and the next startGrpcStream → createGrpcClient cycle resurrects
    // the same corpse. Closing here guarantees the next attempt builds
    // a clean instance.
    try {
      client.close?.();
    } catch (e: any) {
      ctx.logger?.warn?.("gRPC stream: client.close() during reconnect threw", {
        error: e?.message || String(e)
      });
    }

    reconnectAttempts += 1;
    grpcMetrics.reconnectCount += 1;
    const delayMs = nextReconnectDelayMs();

    ctx.logger?.warn?.("gRPC stream: scheduling reconnect", {
      reason,
      delayMs: Math.round(delayMs),
      attempt: reconnectAttempts
    });

    try { if (reconnectTimer) clearTimeout(reconnectTimer); } catch {}
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (shutdownRequested) return;
      // Defensive try/catch around the recursive startGrpcStream call.
      // Without it, ANY synchronous throw — e.g. createGrpcClient
      // throwing because the cached PrivSvc IPC client is stale, or
      // outbox.recoverStaleInflight failing on a corrupt SQLite —
      // becomes an uncaught exception in the setTimeout callback. The
      // process keeps running (Node logs unhandledException and
      // continues), but `reconnecting = true` is never reset and the
      // previous stream's `stopped = true` already fired, so NOTHING
      // ever schedules another reconnect. The agent goes silently
      // zombie: tray stays "connected", the bridge sees no traffic,
      // and the dashboard slowly marks the device offline (~90s) while
      // the user has no idea anything is wrong. We've seen 3 macOS
      // hosts hit exactly this state after sleep/wake.
      //
      // On catch we reset the `reconnecting` flag and re-arm via
      // scheduleReconnect so the exponential backoff carries us through
      // whatever transient cause threw.
      try {
        startGrpcStream(ctx);
      } catch (err: any) {
        ctx.logger?.error?.("gRPC stream: reconnect attempt threw, rescheduling", {
          reason,
          error: err?.message || String(err),
          attempt: reconnectAttempts
        });
        // Mark tray disconnected immediately — the bridge thinks it's
        // up, but our retry path just blew up. Lying to the user with
        // a green tray icon is worse than showing the truth.
        try { ctx.trayStatus.markGrpcDisconnected(); } catch {}
        reconnecting = false;
        scheduleReconnect("reconnect_attempt_threw");
      }
    }, delayMs);
  };

  // Accelerate recovery of IN_FLIGHT on restart
  try {
    outbox.recoverStaleInflight(60); // DEV
  } catch {}

  ctx.logger?.info?.("gRPC stream: Connect() stream opened");

  ctx.logger?.info?.("Agent hello context", {
    deviceId: ctx.enrollment.deviceId,
    tenantId: ctx.enrollment.tenantId,
    agentVersion: ctx.config.agentVersion,
    policyVersion: ctx.policy.getVersion(),
    capabilities: Array.from(new Set([
      ...(ctx.enrollment.bootstrap.capabilities || []),
      ...ctx.policyRuntime.getEnabledPlugins()
    ]))
  });

  // NOTE:
  // HELLO is now sent by PrivSvc during grpc.connect().
  // If you want to keep the same mental model, you can still write hello and PrivSvc will ignore.
  // stream.write({ hello: { ... } });

  // ---- Receiver (Control plane) ----
  stream.on("data", (msg: any) => {
    //logger.info("gRPC raw message received", msg);
    //logger.info("gRPC stream: message received", Object.keys(msg || {}));
    // First byte from the server = the bridge is really up (TCP + TLS +
    // auth + stream init all passed). Reset the reconnect counter so the
    // next transient blip starts its backoff fresh at 2s, not at minute 10.
    if (reconnectAttempts !== 0) {
      ctx.logger?.info?.("gRPC stream: connected, resetting reconnect backoff", {
        priorAttempts: reconnectAttempts
      });
      reconnectAttempts = 0;
    }
    if (msg?.connected === true) {
      ctx.logger?.info?.("gRPC stream: bridge ready", msg);
      grpcMetrics.connectedSinceUtc = new Date().toISOString();
      rotationInProgress = false;
      requestDrain("bridge_connected");
      // Restart the heartbeat cadence from T=0 on READY. This way the
      // first heartbeat lands exactly HEARTBEAT_INTERVAL_MS after the
      // bridge is confirmed up, regardless of how long TLS/auth took,
      // and regardless of whether the previous interval was mid-tick
      // when the stream broke. Prevents the degenerate case where a
      // 3-minute rotation causes three "return-early" ticks to fire
      // and accumulate 0-60s of skew before the next real HB.
      armHeartbeat();
      // Server-silence watchdog: armed on READY so we only watchdog
      // when there's actually a stream to be silent on. Re-armed on
      // every READY, and cleared in stop() — same lifetime as
      // heartbeat.
      armWatchdog();
      // Start the metrics flush on the first READY of the process —
      // we didn't want to arm it in startGrpcStream() because every
      // reconnect would re-enter and we'd end up with N timers.
      armMetricsFlush(ctx);
      return;
    }
    // ACK
    if (msg.ack) {
      const eventId: string = String(msg.ack.eventId ?? "").trim();
      if (!eventId) return;
      grpcMetrics.ackReceived += 1;
      ctx.logger?.info?.("gRPC ACK received", {
        eventId,
        status: Number(msg.ack.status ?? 0),
        message: msg.ack.message || ""
      });
      return;
    }

    if (msg.queueFull) {
      ctx.logger?.warn?.("gRPC bridge queueFull signal received", msg.queueFull);
      return;
    }
    // Jobs / rotate
    if (msg.runJob) {
      const jobId = String(msg.runJob?.jobId || "").trim();
      const eventId = jobId || `runJob-${Date.now()}`;
      const jobType = String(msg.runJob?.jobType || msg.runJob?.type || msg.runJob?.task || "").trim();

      ctx.logger?.info?.("gRPC control message: runJob received", {
        jobId,
        jobType: jobType || null
      });

      if (jobId && runningJobIds.has(jobId)) {
        ctx.logger?.warn?.("runJob ignored: job already in progress", { jobId });
        sendControlAck(ctx, eventId, 1, "job_retry: already in progress").catch(() => {});
        return;
      }

      if (jobId) {
        runningJobIds.add(jobId);
      }

      try {
        if (jobType) {
          ctx.trayStatus.markJobStarted(jobType);
        }
      } catch {}

      setImmediate(() => {
        executeRunJob(ctx, msg.runJob)
          .then((result) => {
            try {
              if (jobType) {
                const normalizedStatus =
                  result.status === 0 ? "success" :
                  result.status === 1 ? "retry" :
                  "failed";
                ctx.trayStatus.markJobFinished(jobType, normalizedStatus);
              }
            } catch {}
            return sendControlAck(ctx, eventId, result.status, result.message);
          })
          .catch((err: any) => {
            ctx.logger?.error?.("runJob execution failed", {
              jobId,
              err: err?.message || err
            });
            try {
              if (jobType) {
                ctx.trayStatus.markJobFinished(jobType, "failed");
              }
            } catch {}
            return sendControlAck(ctx, eventId, 2, err?.message || "job_failed");
          })
          .finally(() => {
            if (jobId) {
              runningJobIds.delete(jobId);
            }
          });
      });

      return;
    }
    if (msg.rotateCert) {
      ctx.logger?.warn?.("gRPC control message: rotateCert received, pausing sender loop");
      rotationInProgress = true;
      ctx.logger?.info?.("Rotate cert received:", msg.rotateCert || "");
      // PrivSvc should perform rotation and keep the bridge alive.
      // While rotation is in progress, we pause sending new facts to avoid churn.
    }

    if (msg.policyUpdate) {
      try {
        const eventId = String(
          msg.policyUpdate?.eventId ||
          `policy:${ctx.enrollment.tenantId}:${ctx.enrollment.deviceId}:${String(msg.policyUpdate?.policyVersion || "")}`
        ).trim();
        const policyVersion = String(msg.policyUpdate?.policyVersion || "");
        const payload = msg.policyUpdate?.policyJson;

        ctx.logger?.info?.("gRPC control message: policyUpdate received", {
          eventId,
          policyVersion
        });

        if (!policyVersion || !payload) {
          ctx.logger?.warn?.("policyUpdate ignored: missing required fields");
          sendControlAck(ctx, eventId, 2, "policy_update rejected: missing required fields").catch(() => {});
          return;
        }

        const payloadStr = Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload);

        let parsed: any;
        try {
          parsed = JSON.parse(payloadStr);
        } catch (e) {
          ctx.logger?.error?.("policyUpdate JSON parse failed", e);
          sendControlAck(ctx, eventId, 2, "policy_update rejected: invalid json").catch(() => {});
          return;
        }

        const computedHash = PolicyStore.computeHash(parsed);

        const localHash = ctx.policy.getHash();
        if (localHash === computedHash) {
          // El disco ya tiene esta policy — save() es innecesario.
          // PERO el runtime puede estar fuera de sincronía con el disco.
          //
          // Caso de bug que esto resuelve (vivido en producción):
          //   1. Agent corriendo. policy.json en disco ya está NEW (de
          //      un save() previo). Runtime tiene NEW (applyUpdate ran).
          //   2. Auto-update se dispara. Daemon shutdown → install → restart.
          //   3. Nuevo proceso boot: PolicyStore.load() lee disk → current=NEW.
          //   4. PolicyRuntime se inicializa con DEFAULT_POLICY (no llama
          //      applyUpdate en boot — ese era el gap).
          //   5. Heartbeat reconciler manda policyUpdate con NEW.
          //   6. localHash (NEW) === computedHash (NEW) → "already_applied" → skip.
          //   7. Runtime sigue con DEFAULT_POLICY. Capabilities reportadas
          //      en facts no incluyen plugins habilitados (ej: PMP).
          //   8. Plugin coverage UI muestra el plugin como desactivado
          //      en flota a pesar de que el ack server-side dice "applied".
          //
          // Defensa: forzar applyUpdate() acá garantiza que runtime
          // siempre refleje disco después de un policyUpdate, sin
          // importar el state pre-existente. applyUpdate() es idempotente:
          // si runtime ya tenía NEW, simplemente re-emite los events
          // (pluginsChanged, modulesChanged) y el scheduler maneja
          // gracefully — incluyendo el inventory tick forzado de Fix 4
          // que asegura que las capabilities reportadas reflejan el
          // estado actual.
          ctx.logger?.info?.("policyUpdate hash matched — runtime resync", { eventId, policyVersion });
          // applyUpdate es async, pero el outer handler stream.on("data", ...)
          // no lo es. Invocamos como promise chain en vez de await — el ACK se
          // envía después de que el resync intenta correr (success o falla).
          ctx.policyRuntime.applyUpdate()
            .then(() => {
              try {
                ctx.trayStatus.markPolicyApplied(ctx);
              } catch {}
            })
            .catch((err: any) => {
              ctx.logger?.warn?.("Runtime resync failed during already_applied path", {
                eventId,
                err: err?.message || err
              });
            })
            .finally(() => {
              sendControlAck(ctx, eventId, 0, "policy_already_applied").catch(() => {});
            });
          return;
        }

            ctx.policy
          .save(policyVersion, computedHash, parsed)
          .then(async () => {
            ctx.logger?.info?.("Policy successfully updated", { eventId, policyVersion });
            await ctx.policyRuntime.applyUpdate();
            ctx.logger?.info?.("Policy runtime reloaded", ctx.policyRuntime.snapshot());
            try {
              ctx.trayStatus.markPolicyApplied(ctx);
            } catch {}
            await sendControlAck(ctx, eventId, 0, "policy_applied");
          })
          .catch(async (err: any) => {
            const message = String(err?.message || err || "policy_apply_failed");
            ctx.logger?.error?.("policyUpdate apply failed", { eventId, policyVersion, err: message });
            await sendControlAck(ctx, eventId, 2, message);
          });

      } catch (err: any) {
        ctx.logger?.error?.("policyUpdate handler error", err?.message || err);
      }
      return;
    }

    if (msg.agentUpdate) {
      const params = msg.agentUpdate;

      const version = String(params?.version || "").trim();
      const jobId = String(params?.jobId || "").trim();
      const eventId = jobId || `agentUpdate-${Date.now()}`;

      ctx.logger?.info?.("gRPC control message: agentUpdate received", {
        jobId,
        version
      });

      // avoid concurrent updates
      if ((ctx as any)._agentUpdateInProgress) {
        ctx.logger?.warn?.("agentUpdate ignored: update already in progress");
        return;
      }

      // validate payload
      if (!version) {
        ctx.logger?.error?.("agentUpdate invalid payload", {
          jobId,
          version
        });
        return;
      }

      (ctx as any)._agentUpdateInProgress = true;

      // lazy import to avoid circular deps
      const { runUpdateTask } = require("../update/update-task");

      setImmediate(() => {
        runUpdateTask(ctx, {
          targetVersion: version,
          logger: ctx.logger
        })
          .then(async () => {
            await sendControlAck(ctx, eventId, 0, "update_completed");
          })
          .catch((err: any) => {
            ctx.logger?.error?.("agentUpdate execution failed", {
              err: err?.message || err
            });
            return sendControlAck(
              ctx,
              eventId,
              2,
              err?.message || "update_failed"
            );
          })
          .finally(() => {
            (ctx as any)._agentUpdateInProgress = false;
          });
      });

      return;
    }

    if (msg.disconnect) {
      ctx.logger?.warn?.("gRPC control message: disconnect requested by server");
      stop();
      scheduleReconnect("server_disconnect");
      return;
    }

    // RCP M1.S1 — signaling dispatch. The plugin manages WebRTC
    // peers + DataChannel I/O; we just route the inbound proto
    // oneof variants to it. Lazy import keeps the bootstrap cost
    // zero for agents that never receive an RCP offer.
    if (
      msg.remoteSessionOffer ||
      msg.remoteSessionIce ||
      msg.remoteSessionClose ||
      msg.remoteSessionError
    ) {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { handleRemoteSessionMessage } = require("../plugins/rcp");
      const params =
        msg.remoteSessionOffer ||
        msg.remoteSessionIce ||
        msg.remoteSessionClose ||
        msg.remoteSessionError;
      const type = msg.remoteSessionOffer
        ? "offer"
        : msg.remoteSessionIce
        ? "ice"
        : msg.remoteSessionClose
        ? "close"
        : "error";
      handleRemoteSessionMessage(ctx, type, params).catch((err: any) => {
        ctx.logger?.error?.("[rcp] dispatch failed", {
          type,
          err: err?.message || String(err)
        });
      });
      return;
    }
  });

  stream.on("error", (err: any) => {
    if (stopped) return;
    ctx.logger?.error?.("gRPC bridge error:", err?.message || err);
    // Do not mark events SENT here. IN_FLIGHT will be recovered by TTL.
    stop();
    scheduleReconnect("stream_error");
  });

  stream.on("end", () => {
    if (stopped) return;
    ctx.logger?.warn?.("gRPC bridge closed. Reconnecting soon...");
    stop();
    scheduleReconnect("stream_end");
  });


  // ---- Sender loop (Data plane) ----
  const armRetryTimer = () => {
    if (stopped) return;
    const delayMs = (outbox as any).getNextReadyDelayMs?.();
    if (delayMs == null) return;
    try { if (retryTimer) clearTimeout(retryTimer); } catch {}
    retryTimer = setTimeout(() => {
      retryTimer = null;
      requestDrain("retry_timer");
    }, delayMs);
  };

  const drainOnce = () => {
    drainScheduled = false;

    if (stopped || draining) return;
    if (rotationInProgress) { armRetryTimer(); return; }
    if (!stream || !client.isConnected?.()) { armRetryTimer(); return; }

    draining = true;
    try {
      const batch = outbox.leaseReady(MAX_IN_FLIGHT);
      if (!batch || batch.length === 0) {
        armRetryTimer();
        return;
      }

      grpcMetrics.outboxDrainLeases += 1;
      ctx.logger?.info?.("Sender loop leased events", { count: batch.length });

      for (const ev of batch) {
        const outboxId = Number(ev.id);
        const eventId = buildEventId(ctx.enrollment.deviceId, outboxId);

        if (!ev.payload_json) {
          outbox.markFailed(outboxId, "Empty payload_json");
          continue;
        }

        try {
          if (ev.type === "FACTS_SNAPSHOT") {
            const parsedPayload: DeviceFacts =
              typeof ev.payload_json === "string"
                ? JSON.parse(ev.payload_json)
                : ev.payload_json;

            const baselineHash = parsedPayload?._meta?.baselineHash;
            const forceBaseline = parsedPayload?._meta?.forceBaseline === true;
            const namespaceKeys = parsedPayload?.namespaces
              ? Object.keys(parsedPayload.namespaces).filter(k => Boolean((parsedPayload.namespaces as any)[k]))
              : [];
            const wireNamespace = namespaceKeys.length === 1 ? namespaceKeys[0] : "multi";

            ctx.logger?.info?.("Sending FACTS event", { outboxId, eventId, type: ev.type });
            ctx.logger?.info?.("FACTS payload metadata", {
              eventId,
              baselineHash,
              baselineSent,
              forceBaseline,
              namespaces: namespaceKeys
            });

            try {
              const sw = parsedPayload?.namespaces?.amp?.software;
              ctx.logger?.info?.("STREAM FINAL SOFTWARE CHECK", {
                hasItems: !!sw?.items,
                itemsLength: sw?.items?.length,
                keys: Object.keys(sw || {})
              });
            } catch (e: any) {
              ctx.logger?.error?.("STREAM SOFTWARE CHECK FAILED", e?.message || e);
            }

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace: wireNamespace,
                namespaces: namespaceKeys,
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string" ? ev.payload_json : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });

          } else if (ev.type === "FACTS_DELTA") {
            ctx.logger?.info?.("Sending FACTS_DELTA event", { outboxId, eventId });

            stream.write({
              facts: {
                eventId,
                deviceId: ctx.enrollment.deviceId,
                namespace: "amp",
                namespaces: ["amp"],
                payloadJson: Buffer.from(
                  typeof ev.payload_json === "string" ? ev.payload_json : JSON.stringify(ev.payload_json),
                  "utf8"
                )
              }
            });

          } else {
            outbox.markFailed(outboxId, `Unsupported event type: ${ev.type}`);
          }
        } catch (err: any) {
          ctx.logger?.error?.("FACTS send failed", { eventId, error: err?.message || err });
          outbox.markFailed(outboxId, err?.message || "facts.send failed");
        }
      }
    } catch (err: any) {
      ctx.logger?.error?.("Sender loop error:", err?.message || err);
    } finally {
      draining = false;
      const nextDelay = (outbox as any).getNextReadyDelayMs?.();
      if (nextDelay === 0) {
        requestDrain("more_ready_now");
      } else {
        armRetryTimer();
      }
    }
  };

  const requestDrain = (_reason: string) => {
    if (stopped || drainScheduled) return;
    drainScheduled = true;
    setImmediate(drainOnce);
  };

  ctx.logger?.info?.("gRPC sender loop will start shortly...");
  // Start sender loop after a short delay to allow gRPC bridge to establish
  startDelayTimer = setTimeout(() => {
    if (!stopped) {
      ctx.logger?.info?.("gRPC sender loop started");
      if (typeof (outbox as any).onChanged === "function") {
        unsubscribeOutbox = (outbox as any).onChanged(() => {
          requestDrain("outbox_changed");
        });
      } else {
        // Fallback: trigger a single drain at startup if event API not available
        requestDrain("outbox_changed_fallback");
      }
      requestDrain("startup");
      // Heartbeat is now driven by armHeartbeat(), which is kicked off
      // from the `{connected: true}` READY handler in the data listener.
      // No need to start a timer here — the READY signal is what anchors
      // the first real HB, not the arbitrary 1-s startDelayTimer.
    }
  }, 1000);

  // (Optional) return stop handle if you later want to cleanly shut down
  return () => {
    shutdownRequested = true;
    stop({ localClose: true });
  };
}
