// src/plugins/sdp/index.ts
//
// SDP — Phase 1. Software Delivery Plugin orchestrator.
//
// Entry point invoked by the runJob handler in grpc-stream.ts when
// jobType="software_install" arrives. The flow is platform-agnostic
// at this layer; per-OS specifics live in the privsvc primitives
// (`sdp.detect`, `sdp.download`, `sdp.install`) that this file
// drives via IPC.
//
// Outcome contract (returned to the caller in grpc-stream.ts which
// then translates to the gRPC ACK):
//
//   { ackStatus, ackMessage, outcome }
//
//     ackStatus 0 — success / already_installed / reboot_required.
//                   The orchestrator marks the job done.
//     ackStatus 1 — transient failure (concurrent install, network
//                   blip during download). Orchestrator retries.
//     ackStatus 2 — permanent failure (sha256 mismatch, install
//                   exit code outside expected set, post-detection
//                   mismatch). Orchestrator does NOT retry —
//                   operator needs to look.
//
//   `outcome` is a stable string that maps 1:1 to the
//   `software_install_results.outcome` enum on the backend. We
//   encode it in `ackMessage` as `software_install:<outcome>;...`
//   so the P1-G ack handler can parse it. (Long-term the right
//   shape is a structured facts envelope; that's also P1-G.)

import os from "os";
import type { AgentContext } from "../../core/agent-context";
import { tryStartInstall, finishInstall } from "./state";
import { evaluate, normalizeRule, type DetectionEvaluation } from "./detection";
import {
  parseMode,
  preDetectDecision,
  argsForMode,
  postDetectIsFailure,
  postDetectFailureReason,
  identityForUninstall,
} from "./mode";
import { evaluateSignatureGate, normalizeVerifyResponse } from "./signature-gate";

// Mirror of the backend's `InstallOutcome` enum. Keep in lockstep.
export type InstallOutcome =
  | "success"
  | "already_installed"
  | "failed"
  | "rejected"
  | "reboot_required"
  | "timed_out"
  | "signature_invalid" // signingRequired but WinVerifyTrust failed — permanent
  // 'pending' / 'running' / 'cancelled' are server-side only — the
  // agent never reports them.
  ;

// Subset of `software_packages` the agent needs at runtime. Mirror
// of the backend's `SoftwarePackageDto` minus the catalog metadata
// (createdAt etc) we don't use here.
type PackageSnapshot = {
  id: number;
  name: string;
  version: string;
  platform: "windows" | "macos" | "linux";
  arch: "x64" | "arm64" | "x86" | "any";
  format: "exe" | "msi" | "pkg" | "dmg" | "deb" | "rpm" | "tar.gz";
  downloadPath: string;
  sha256: string;
  silentInstallArgs?: string | null;
  silentUninstallArgs?: string | null;
  detectionRule?: any | null;
  expectedExitCodes?: number[];
  requiresReboot?: boolean;
  signingRequired?: boolean;
  sizeBytes?: number | null;
};

export type SoftwareInstallAck = {
  ackStatus: 0 | 1 | 2;
  ackMessage: string;
  outcome: InstallOutcome;
};

/**
 * Budget we give privsvc for the WHOLE download, across every source it tries.
 *
 * This has to stay strictly under the IPC client's `sdp.download` ceiling
 * (700s — see getTimeoutForMethod in src/priv/privsvc-client-*.ts), or the
 * caller hangs up while the handler is still working and the failure surfaces
 * as a bare "PrivSvc timeout" that says nothing about which source was slow.
 *
 * Sending it explicitly instead of letting privsvc fall back to its own
 * default is the point: the two numbers are a pair, and a pair that lives in
 * two files with no link between them drifts. A test pins the relationship.
 */
export const DOWNLOAD_BUDGET_SECONDS = 600;

/**
 * Is this package the agent installing itself?
 *
 * Distributing the agent through SDP is the one case where the installer kills
 * the process that has to report the result: msiexec stops AgentCore, so the
 * ACK for `sdp.install` never leaves the machine. The job then sits in `sent`
 * until the orchestrator retries it ~32 minutes later, and only that retry —
 * which finds the software already installed — closes it. Observed on every
 * self-deployment so far: `attempts: 2`, half an hour of nothing.
 *
 * Recognising the case lets us ACK before handing off to the installer. See
 * SELF_INSTALL_ACK_REASON for what that ACK does and does not claim.
 *
 * Name matching is deliberate rather than clever: the MSI's ProductCode is not
 * in the catalog snapshot, so there is nothing stronger available here. A
 * mismatch is safe in both directions — a false negative just restores today's
 * retry behaviour, and a false positive would need a third-party package
 * literally named "Tracenium Agent" from this vendor.
 */
export function isSelfPackage(snapshot: any): boolean {
  const name = String(snapshot?.name ?? "").trim().toLowerCase();
  if (!name) return false;
  const vendor = String(snapshot?.vendor ?? "").trim().toLowerCase();
  const looksLikeAgent = name === "tracenium agent" || name.startsWith("tracenium agent");
  const looksLikeUs = vendor === "" || vendor.includes("certus");
  return looksLikeAgent && looksLikeUs;
}

/**
 * Why the early ACK is honest, and what it deliberately does not say.
 *
 * By the time we send it the agent has: downloaded the package, verified its
 * sha256 against the catalog, and passed the signature gate. What it cannot
 * know is the installer's exit code, because it is about to be terminated by
 * that installer — the same limit that made `agent_update` ACK `update_started`
 * rather than `update_completed`.
 *
 * So the message carries no `exit=`: claiming an exit code we never read is
 * exactly the class of lie that made failed updates report as completed. The
 * reason field marks the row as launched-not-confirmed, and the real
 * confirmation is the version the device reports when it comes back.
 */
export const SELF_INSTALL_ACK_REASON = "self_install_launched";

// Distribution Phase A — ordered download sources from the backend
// (dp → cdn → origin). Passed through to privsvc, which tries them in order
// with the sha256 gate deciding per-source. Malformed entries are dropped;
// an empty result means "no sources" and privsvc falls back to downloadPath.
export function normalizeSources(raw: unknown): Array<{ tier: string; url: string }> {
  if (!Array.isArray(raw)) return [];
  const out: Array<{ tier: string; url: string }> = [];
  for (const s of raw) {
    if (!s || typeof s !== "object") continue;
    const url = (s as any).url;
    if (typeof url !== "string" || !/^https:\/\//i.test(url)) continue;
    const tier = typeof (s as any).tier === "string" && (s as any).tier ? (s as any).tier : "origin";
    out.push({ tier, url });
  }
  return out;
}

// Platform name normalization. Backend stores 'windows'/'macos'/
// 'linux'; Node's os.platform() returns 'win32'/'darwin'/'linux'.
function normalizePlatform(): "windows" | "macos" | "linux" | null {
  const p = os.platform();
  if (p === "win32") return "windows";
  if (p === "darwin") return "macos";
  if (p === "linux") return "linux";
  return null;
}

// B3 forensics — max length of a single base64url-encoded snapshot
// value we'll put on the wire. The backend's ack parser
// (install-result-reducer.ts:decodeJsonB64) hard-rejects any value
// with `value.length > 24_000` (its ~16KB-decoded ceiling), returning
// undefined and leaving the JSONB column empty. We stay strictly under
// that so a snapshot that WOULD be accepted always is; anything larger
// is dropped agent-side (with a warn) rather than shipped only to be
// silently discarded by the backend. 20_000 leaves headroom for the
// rest of the ack message + a safety margin below the backend gate.
export const FORENSICS_B64_MAX_LEN = 20_000;

// Encode an arbitrary JSON-serializable snapshot to base64url. The ack
// message is split on `;` and `=` and sanitized server-side, so a raw
// JSON blob can't survive — but base64url ([A-Za-z0-9_-], no '+' '/'
// '=') rides through untouched. Node's Buffer supports 'base64url'
// directly and the backend decodes with the same alphabet
// (Buffer.from(value, "base64url")), so this is contract-exact.
//
// Returns undefined when the snapshot is absent OR when the encoded
// value would exceed FORENSICS_B64_MAX_LEN (oversized → omit the key,
// warn). Never throws.
function encodeForensicsB64(
  snapshot: unknown,
  onOversize?: (len: number) => void
): string | undefined {
  if (snapshot === undefined || snapshot === null) return undefined;
  try {
    const b64 = Buffer.from(JSON.stringify(snapshot), "utf8").toString("base64url");
    if (b64.length > FORENSICS_B64_MAX_LEN) {
      onOversize?.(b64.length);
      return undefined;
    }
    return b64;
  } catch {
    return undefined;
  }
}

// Encode the outcome into the ACK message. The backend's P1-G ack
// handler parses this prefix to update `software_install_results`.
// Format:
//   software_install:<outcome>;deploymentId=<n>[;exit=<code>][;duration=<ms>][;reason=<short>][;detectBefore=<b64url>][;detectAfter=<b64url>]
//
// `detectBefore` / `detectAfter` (B3 forensics) are already base64url
// so must NOT be run through the `;`/`\n` sanitizer + 200-char slice
// that the free-form extras get — that would corrupt the blob. They're
// passed via the dedicated `forensics` bag and appended verbatim.
function encodeAckMessage(
  outcome: InstallOutcome,
  deploymentId: number,
  extras: Record<string, string | number | undefined> = {},
  forensics: Record<string, string | undefined> = {}
): string {
  const parts = [`software_install:${outcome}`, `deploymentId=${deploymentId}`];
  for (const [k, v] of Object.entries(extras)) {
    if (v === undefined) continue;
    parts.push(`${k}=${String(v).replace(/[;\n]/g, " ").slice(0, 200)}`);
  }
  // Forensics blobs are already base64url ([A-Za-z0-9_-]) — append
  // verbatim (no sanitizing/slicing) so the backend round-trips them.
  // Absent keys are omitted so the backend's COALESCE keeps existing
  // column data instead of nulling it.
  for (const [k, v] of Object.entries(forensics)) {
    if (v === undefined) continue;
    parts.push(`${k}=${v}`);
  }
  return parts.join(";");
}

/**
 * Build a stderr excerpt safe to put on the wire. Cap at 1KB and
 * strip CR/NUL because they break log readers downstream.
 */
function trimStderr(stderr: unknown): string | undefined {
  if (typeof stderr !== "string" || stderr.length === 0) return undefined;
  return stderr.replace(/\r/g, "").replace(/ /g, "").slice(0, 1024);
}

/**
 * Main entry. Called from grpc-stream.ts:executeRunJob's
 * `case "software_install"`. Always returns a non-throwing
 * SoftwareInstallAck — any internal error is mapped to outcome
 * 'failed' / ackStatus 2 with `reason=` describing why.
 */
export async function runSoftwareInstall(
  ctx: AgentContext,
  jobId: string,
  payload: any,
  /**
   * Sends an ACK for this job WITHOUT waiting for the handler to return.
   * Supplied by the transport (which owns the gRPC stream); optional so the
   * plugin stays callable from tests and from any caller that has no stream.
   * Used only for the self-install case — see isSelfPackage.
   */
  sendEarlyAck?: (message: string) => Promise<void>
): Promise<SoftwareInstallAck> {
  const deploymentId = Number(payload?.deploymentId);
  const snapshot = payload?.packageSnapshot as PackageSnapshot | undefined;
  // Phase 2 — deployment mode drives the pre-detect short-circuit, which
  // args we run, and the post-detect expectation. Absent (older backend)
  // → "install". See ./mode.
  const mode = parseMode(payload?.mode);

  // ── Validate envelope ─────────────────────────────────────────
  if (!Number.isInteger(deploymentId) || deploymentId <= 0 || !snapshot) {
    return {
      ackStatus: 2,
      ackMessage: encodeAckMessage("failed", deploymentId || 0, {
        reason: "invalid_payload",
      }),
      outcome: "failed",
    };
  }

  // ── Platform fit ──────────────────────────────────────────────
  // The backend should never dispatch a windows package to a mac,
  // but the catalog has no FK enforcing platform alignment with the
  // device — if the asset_group resolution returns mixed platforms
  // we reject here so the operator sees the failure attributed to
  // the right device.
  const localPlatform = normalizePlatform();
  if (localPlatform == null || localPlatform !== snapshot.platform) {
    return {
      ackStatus: 2,
      ackMessage: encodeAckMessage("rejected", deploymentId, {
        reason: `platform_mismatch_${localPlatform}_vs_${snapshot.platform}`,
      }),
      outcome: "rejected",
    };
  }

  // ── Plugin-policy gate ────────────────────────────────────────
  // If the tenant disables the SDP plugin we refuse the job. This
  // mirrors how patch_install checks `pluginEnabled("pmp")`. The
  // policyRuntime treats unknown plugin names as enabled-by-default
  // so this is a no-op for tenants that haven't explicitly disabled.
  if (typeof ctx.policyRuntime?.pluginEnabled === "function"
      && ctx.policyRuntime.pluginEnabled("sdp") === false) {
    return {
      ackStatus: 2,
      ackMessage: encodeAckMessage("rejected", deploymentId, {
        reason: "sdp_plugin_disabled_by_policy",
      }),
      outcome: "rejected",
    };
  }

  // ── Concurrency lock ──────────────────────────────────────────
  // OS-level constraint: only one installer can run at a time
  // (msiexec / installer don't tolerate concurrent invocations).
  // If another install is in flight, ack as transient retry — the
  // orchestrator's retry policy will refire after backoff.
  const acquired = tryStartInstall({
    packageId: snapshot.id,
    packageName: snapshot.name,
    packageVersion: snapshot.version,
  });
  if (!acquired) {
    return {
      ackStatus: 1,
      ackMessage: encodeAckMessage("failed", deploymentId, {
        reason: "another_install_in_progress",
      }),
      outcome: "failed",
    };
  }

  let outcome: InstallOutcome = "failed";
  let exitCode: number | undefined;
  let extraReason: string | undefined;
  let durationMs: number | undefined;
  // Distribution Phase A — which source tier actually served the bytes
  // (dp/cdn/origin). Reported in the ACK (`src=`) for the per-tier KPIs.
  let servedBy: string | undefined;

  // B3 forensics: retain the pre/post detection evaluations across the
  // pipeline so terminal ACKs can carry their `.snapshot`s. Populated as
  // the pre- and post-detect steps run; undefined until then.
  let preDetectEval: DetectionEvaluation | undefined;
  let postDetectEval: DetectionEvaluation | undefined;

  // Build the base64url forensics bag for the ACK. Emits `detectBefore`
  // /`detectAfter` ONLY when the corresponding snapshot exists and fits
  // under the size ceiling — an absent/oversized snapshot omits the key
  // so the backend's COALESCE preserves any existing column value.
  const buildForensics = (): Record<string, string | undefined> => {
    const bag: Record<string, string | undefined> = {};
    const before = encodeForensicsB64(preDetectEval?.snapshot, (len) =>
      ctx.logger?.warn?.("[sdp.install] detectBefore snapshot oversized, omitting", {
        jobId,
        deploymentId,
        encodedLen: len,
        limit: FORENSICS_B64_MAX_LEN,
      })
    );
    if (before !== undefined) bag.detectBefore = before;
    const after = encodeForensicsB64(postDetectEval?.snapshot, (len) =>
      ctx.logger?.warn?.("[sdp.install] detectAfter snapshot oversized, omitting", {
        jobId,
        deploymentId,
        encodedLen: len,
        limit: FORENSICS_B64_MAX_LEN,
      })
    );
    if (after !== undefined) bag.detectAfter = after;
    return bag;
  };

  try {
    const rule = normalizeRule(snapshot.detectionRule);

    // ── Pre-detection (idempotency / desired-state short-circuit) ─
    // install:   already present → already_installed, skip the work.
    // uninstall: already absent  → already in desired state, skip.
    // reinstall: never short-circuit (force the re-run).
    // We skip downloading, skip running, and ACK as already_installed
    // so the deployment counts reflect "this device was already good".
    let preDetect: DetectionEvaluation = {
      matched: false,
      skipped: true,
      skipReason: "no_rule",
    };
    if (rule) {
      preDetect = await evaluate(ctx, rule, jobId);
      preDetectEval = preDetect;
      const decision = preDetectDecision(mode, preDetect.matched);
      if (decision.shortCircuit) {
        outcome = decision.outcome!; // "already_installed"
        return {
          ackStatus: 0,
          ackMessage: encodeAckMessage(
            outcome,
            deploymentId,
            { reason: decision.reason },
            buildForensics()
          ),
          outcome,
        };
      }
    }

    const expectedExitCodes =
      Array.isArray(snapshot.expectedExitCodes) && snapshot.expectedExitCodes.length > 0
        ? snapshot.expectedExitCodes
        : [0, 3010];

    // `runResp` is the terminal runner response — from sdp.install for
    // install/reinstall, or sdp.uninstall for uninstall. Both share the
    // `{ exitCode, stderrExcerpt, durationMs }` result contract so the
    // exit-code + post-detect handling below is identical.
    let runResp: any;
    const installStart = Date.now();

    if (mode === "uninstall") {
      // ── Uninstall (by identity, no download) ──────────────────
      // Uninstall doesn't run the installer bytes — it removes the software
      // by identity (MSI ProductCode / app bundle / package name), which the
      // detection rule already encodes. So we SKIP download + signature and
      // hand the identity to privsvc's sdp.uninstall. A rule with no removable
      // identity (file_exists / command_exit) can't be uninstalled → reject.
      const identity = identityForUninstall(snapshot.detectionRule);
      if (!identity) {
        outcome = "rejected";
        extraReason = "uninstall_no_identity";
        ctx.logger?.warn?.("[sdp.install] uninstall has no removable identity", {
          jobId,
          packageId: snapshot.id,
          ruleType: (snapshot.detectionRule as any)?.type ?? null,
        });
        return {
          ackStatus: 2,
          ackMessage: encodeAckMessage(outcome, deploymentId, { reason: extraReason }),
          outcome,
        };
      }
      runResp = await ctx.priv.call({
        v: 1,
        id: `sdp-uninstall-${jobId}-${Date.now()}`,
        method: "sdp.uninstall",
        params: {
          format: snapshot.format,
          mode,
          identity,
          // silentUninstallArgs when the OS runner honours custom args
          // (Windows EXE uninstallers); mac/linux use the package manager.
          args: argsForMode(mode, snapshot),
          expectedExitCodes,
          timeoutSeconds: 1740,
          packageId: snapshot.id,
        },
        meta: {
          tenantId: ctx.enrollment.tenantId,
          deviceId: ctx.enrollment.deviceId,
        },
      });

      if (!runResp?.ok) {
        const errCode = (runResp as any)?.error?.code || "uninstall_failed";
        const isPermanent =
          errCode === "format_unsupported" ||
          errCode === "uninstall_no_identity" ||
          errCode === "identity_not_found";
        outcome = errCode === "install_timeout" || errCode === "uninstall_timeout"
          ? "timed_out"
          : isPermanent ? "rejected" : "failed";
        extraReason = errCode;
        return {
          ackStatus: outcome === "timed_out" ? 1 : isPermanent ? 2 : 2,
          ackMessage: encodeAckMessage(outcome, deploymentId, { reason: errCode }),
          outcome,
        };
      }
    } else {
      // ── Download + sha256 verify ────────────────────────────────
      // privsvc fetches into a privileged staging dir (root-owned on
      // *nix, system-owned on Windows) and verifies sha256 against
      // the snapshot's expected hash. We pass the EXPECTED hash
      // explicitly so privsvc can fail-closed on mismatch.
      // Distribution Phase A: ordered sources (dp → cdn → origin) ride along;
      // privsvc tries them in order and falls back to `url` when absent.
      const sources = normalizeSources(payload?.sources);
      const downloadStart = Date.now();
      const downloadResp = await ctx.priv.call({
        v: 1,
        id: `sdp-download-${jobId}-${Date.now()}`,
        method: "sdp.download",
        params: {
          url: snapshot.downloadPath,
          sha256: snapshot.sha256,
          format: snapshot.format,
          packageId: snapshot.id,
          sizeBytes: snapshot.sizeBytes ?? undefined,
          // Total budget across all sources — privsvc splits it between the
          // tiers it still has to try. See DOWNLOAD_BUDGET_SECONDS.
          timeoutSeconds: DOWNLOAD_BUDGET_SECONDS,
          ...(sources.length > 0 ? { sources } : {}),
          // Phase D — per-tenant bandwidth cap (Kbps) from policy, rides the
          // job payload. Absent/0 = full speed.
          ...(Number(payload?.bandwidthLimitKbps) > 0
            ? { rateLimitKbps: Number(payload.bandwidthLimitKbps) }
            : {}),
        },
        meta: {
          tenantId: ctx.enrollment.tenantId,
          deviceId: ctx.enrollment.deviceId,
        },
      });

      if (!downloadResp?.ok) {
        const errCode = (downloadResp as any)?.error?.code || "download_failed";
        // sha256 mismatch is permanent (catalog is wrong); other
        // download failures (network) are transient.
        const isPermanent =
          errCode === "sha256_mismatch" ||
          errCode === "signature_invalid" ||
          errCode === "format_unsupported" ||
          errCode === "url_invalid";
        outcome = isPermanent ? "rejected" : "failed";
        extraReason = errCode;
        return {
          ackStatus: isPermanent ? 2 : 1,
          ackMessage: encodeAckMessage(outcome, deploymentId, {
            reason: errCode,
          }),
          outcome,
        };
      }

      const downloadResult = downloadResp.result || {};
      servedBy =
        typeof downloadResult.servedBy === "string" && downloadResult.servedBy
          ? downloadResult.servedBy
          : undefined;
      const stagingPath = String(downloadResult.stagingPath || "");
      if (!stagingPath) {
        outcome = "failed";
        extraReason = "download_no_staging_path";
        return {
          ackStatus: 2,
          ackMessage: encodeAckMessage(outcome, deploymentId, {
            reason: extraReason,
          }),
          outcome,
        };
      }

      ctx.logger?.info?.("[sdp.install] download ok", {
        jobId,
        packageId: snapshot.id,
        stagingPath,
        durationMs: Date.now() - downloadStart,
      });

      // ── Signature gate (Authenticode / OS trust) ────────────────
      // When the package requires a signature, verify the DOWNLOADED bytes with
      // the OS (WinVerifyTrust in the privsvc): full digest + chain to the Windows
      // trust store + revocation. This closes the "staple a signature onto other
      // bytes" gap the backend's cert-presence/chain check can't — at the point of
      // execution. Fail-closed: anything but an explicit trusted verdict blocks.
      if (snapshot.signingRequired) {
        const verifyResp = await ctx.priv.call({
          v: 1,
          id: `sdp-verify-${jobId}-${Date.now()}`,
          method: "sdp.verifySignature",
          params: { stagingPath, format: snapshot.format, packageId: snapshot.id },
          meta: {
            tenantId: ctx.enrollment.tenantId,
            deviceId: ctx.enrollment.deviceId,
          },
        });
        const decision = evaluateSignatureGate(true, normalizeVerifyResponse(verifyResp));
        if (!decision.proceed) {
          outcome = decision.outcome!; // "signature_invalid"
          extraReason = decision.reason;
          ctx.logger?.warn?.("[sdp.install] signature gate blocked install", {
            jobId,
            packageId: snapshot.id,
            reason: decision.reason,
          });
          return {
            ackStatus: 2,
            ackMessage: encodeAckMessage(outcome, deploymentId, { reason: decision.reason }),
            outcome,
          };
        }
        ctx.logger?.info?.("[sdp.install] signature verified (OS trust)", {
          jobId,
          packageId: snapshot.id,
        });
      }

      // ── Early ACK for self-installs ─────────────────────────────
      // We are about to hand our own MSI to msiexec, which stops AgentCore.
      // The ACK for sdp.install would die with the process, leaving the job
      // in `sent` until the orchestrator's retry closes it half an hour later.
      //
      // Everything verifiable HAS been verified at this point: bytes match the
      // catalog sha256 and the signature gate passed. The exit code is the only
      // thing we cannot know, so the message carries no `exit=` — see
      // SELF_INSTALL_ACK_REASON. The device reporting its new version is what
      // actually confirms the install.
      //
      // Best-effort: if the ACK cannot be sent we simply proceed and fall back
      // to today's retry behaviour. Failing the install because a status
      // message did not go out would be worse than the delay it avoids.
      //
      // The normal ACK below is still sent when we survive the install. That is
      // deliberate: on the happy path the backend ignores it (the result row is
      // already terminal and idempotent), and on the unhappy path — installer
      // failed but did not replace us — it is the only way the operator hears
      // about the failure at all. Better a job that disagrees with its result
      // row than a silent success.
      if (sendEarlyAck && isSelfPackage(snapshot)) {
        const earlyMessage = encodeAckMessage("success", deploymentId, {
          reason: SELF_INSTALL_ACK_REASON,
          // `src` is the key the backend parses into served_by — same one the
          // final ACK uses. Naming it servedBy here would ship a field nobody
          // reads.
          ...(servedBy ? { src: servedBy } : {}),
        });
        try {
          await sendEarlyAck(earlyMessage);
          ctx.logger?.info?.("[sdp.install] self-install: acked before handing off to the installer", {
            jobId,
            deploymentId,
            version: snapshot.version,
          });
        } catch (err: any) {
          ctx.logger?.warn?.("[sdp.install] early ack failed; falling back to the orchestrator retry", {
            jobId,
            error: err?.message || String(err),
          });
        }
      }

      // ── Install ─────────────────────────────────────────────────
      // Hand off to privsvc. Timeout is bounded server-side via the
      // job's timeout_seconds (default 1800s = 30 min); we pass a
      // shorter privsvc-side timeout so we still return a clean ACK
      // even if the runner hangs (rather than waiting for the gRPC
      // job timeout to fire).
      runResp = await ctx.priv.call({
        v: 1,
        id: `sdp-install-${jobId}-${Date.now()}`,
        method: "sdp.install",
        params: {
          stagingPath,
          format: snapshot.format,
          // Mode-aware args: silentInstallArgs for install/reinstall.
          args: argsForMode(mode, snapshot),
          mode,
          expectedExitCodes,
          // Privsvc-side hard ceiling — leave 60s headroom under the
          // orchestrator job timeout so we surface the timeout
          // ourselves with a real outcome string.
          timeoutSeconds: 1740,
          packageId: snapshot.id,
        },
        meta: {
          tenantId: ctx.enrollment.tenantId,
          deviceId: ctx.enrollment.deviceId,
        },
      });

      if (!runResp?.ok) {
        const errCode = (runResp as any)?.error?.code || "install_failed";
        // Distinguish runner-side timeouts so the backend can decide
        // whether to retry (Phase 1 we don't auto-retry; future:
        // the retry-engine can read this).
        outcome = errCode === "install_timeout" ? "timed_out" : "failed";
        extraReason = errCode;
        return {
          ackStatus: outcome === "timed_out" ? 1 : 2,
          ackMessage: encodeAckMessage(outcome, deploymentId, {
            reason: errCode,
          }),
          outcome,
        };
      }
    }

    const installResult = runResp.result || {};
    exitCode = Number(installResult.exitCode);
    const stderrExcerpt = trimStderr(installResult.stderrExcerpt);
    durationMs = Number(installResult.durationMs ?? Date.now() - installStart);
    const isExpected = Number.isFinite(exitCode) && expectedExitCodes.includes(exitCode);
    const isReboot = exitCode === 3010;

    if (!isExpected) {
      // Installer ran to completion but exit code says it failed.
      outcome = "failed";
      extraReason = stderrExcerpt
        ? `unexpected_exit_${exitCode}:${stderrExcerpt.slice(0, 80)}`
        : `unexpected_exit_${exitCode}`;
      return {
        ackStatus: 2,
        ackMessage: encodeAckMessage(outcome, deploymentId, {
          exit: exitCode,
          duration: durationMs,
          reason: extraReason,
          src: servedBy,
        }),
        outcome,
      };
    }

    // ── Post-run detection (silent-fail catch) ──────────────────
    // Some Windows installers exit 0 but didn't actually do the work
    // (group policy, antivirus quarantine, partial). Re-evaluate the
    // rule and check it against the mode's EXPECTATION:
    //   install/reinstall → rule must MATCH (software present).
    //   uninstall         → rule must NOT match (software gone).
    // A violation is a failure regardless of exit code.
    if (rule) {
      const postDetect = await evaluate(ctx, rule, jobId);
      postDetectEval = postDetect;
      if (!postDetect.skipped && postDetectIsFailure(mode, postDetect.matched)) {
        outcome = "failed";
        extraReason = postDetectFailureReason(mode);
        return {
          ackStatus: 2,
          ackMessage: encodeAckMessage(
            outcome,
            deploymentId,
            {
              exit: exitCode,
              duration: durationMs,
              reason: extraReason,
              src: servedBy,
            },
            buildForensics()
          ),
          outcome,
        };
      }
    }

    // ── Success path ────────────────────────────────────────────
    outcome = isReboot ? "reboot_required" : "success";
    return {
      ackStatus: 0,
      ackMessage: encodeAckMessage(
        outcome,
        deploymentId,
        {
          exit: exitCode,
          duration: durationMs,
          src: servedBy,
        },
        buildForensics()
      ),
      outcome,
    };
  } catch (err: any) {
    // Defensive: anything thrown above (e.g. priv.call rejected
    // unexpectedly, the privsvc IPC socket is down). Map to a
    // transient failure so the orchestrator can retry — the next
    // attempt will short-circuit via pre-detect if the install
    // already happened.
    outcome = "failed";
    extraReason = `exception:${(err?.message || "unknown").slice(0, 120)}`;
    ctx.logger?.error?.("[sdp.install] unhandled exception", {
      jobId,
      error: err?.message || String(err),
    });
    return {
      ackStatus: 1,
      ackMessage: encodeAckMessage(outcome, deploymentId, {
        reason: extraReason,
      }),
      outcome,
    };
  } finally {
    finishInstall(outcome, exitCode);
  }
}
