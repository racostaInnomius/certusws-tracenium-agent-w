/**
 * vCenter Connector — the Infrastructure Gateway's job handlers.
 *
 * NOT a plugin. Fleet plugins (amp/pmp/sdp/…) are enabled per-tenant and act on
 * the endpoint they run on; this runs on exactly ONE host per site and brokers
 * to a third party (vCenter) on the site's behalf. Its enablement is the
 * PRESENCE of `policy.gateway.vcenter` in that device's policy override, so a
 * job aimed at any other endpoint finds no config and is rejected outright.
 * See ADR-0001 (A).
 *
 * Six job types, all additive over the existing generic RunJob/Ack contract —
 * no proto change:
 *   vcenter_credential_provision — open a sealed credential envelope (PrivSvc
 *                      holds the only key that can) and store it, then verify.
 *   vcenter_credential_remove — forget it again when the gateway is removed.
 *   vcenter_verify   — self-check ladder; the only way to validate a credential
 *                      the control plane cannot read.
 *   vcenter_snapshot — correlate an endpoint to its VM and snapshot it.
 *   vcenter_snapshot_remove — reclaim expired snapshots (retention sweep).
 *   vcenter_snapshot_revert — roll a VM back. Operator-initiated only.
 */

import { VimClient, PinMismatchError, VimFault } from "./vim-client";
import { runVerification, REQUIRED_PRIVILEGES, type VerifyReport, type VerifyDeps } from "./verify";
import {
  buildVerifyAck,
  buildSnapshotAck,
  buildProvisionAck,
  decodeReport,
  ACK_OK,
  ACK_REJECTED,
  type SnapshotOutcome,
} from "./ack";
import { buildMatchCandidates, type EndpointVmFacts } from "./uuid-match";
import type { GatewayConfig } from "./gateway-config";

export interface VCenterCredential {
  username: string;
  password: string;
}

/** Everything the handlers need from the agent, injected so they stay testable. */
export interface ConnectorDeps {
  /** Validated gateway config, or null when this device is not a gateway. */
  gatewayConfig(): GatewayConfig | null;
  /**
   * Fetch the vCenter credential from the OS credential store via PrivSvc.
   * The secret exists in this process only for the duration of one operation.
   */
  getCredential(ref: string): Promise<VCenterCredential>;
  /**
   * Hand a sealed envelope to PrivSvc, which opens it with the enrollment
   * private key and writes the credential to the OS credential store. Rejects
   * with a coded error (`stale_envelope`, `decrypt_failed`, …) so the caller can
   * tell "re-enter it" from "try again later". Optional: a build without the
   * PrivSvc primitive reports store_unavailable instead of crashing.
   */
  provisionCredential?(ref: string, envelope: unknown): Promise<void>;
  /** Delete a stored credential. Idempotent: a missing ref is success. */
  removeCredential?(ref: string): Promise<void>;
  makeClient(cfg: GatewayConfig): VimClient;
  now(): Date;
  logger?: { info?: (m: string, x?: any) => void; warn?: (m: string, x?: any) => void; error?: (m: string, x?: any) => void };
}

export interface JobResult {
  status: number;
  message: string;
}

/**
 * Build the connector's dependencies from a live AgentContext.
 *
 * Kept here rather than in the transport layer so grpc-stream stays a thin
 * dispatcher and the handlers remain unit-testable with plain fakes.
 */
export function makeConnectorDeps(ctx: any): ConnectorDeps {
  return {
    gatewayConfig: () => ctx.policyRuntime?.gatewayConfig?.() ?? null,
    getCredential: async (ref: string) => {
      const res = await ctx.priv.call({
        v: 1,
        id: `cred-${Date.now()}`,
        method: "credential.retrieve",
        params: { ref },
      });
      const cred = res?.result ?? res;
      if (!cred || typeof cred.username !== "string" || typeof cred.password !== "string") {
        const err: any = new Error("no vcenter credential stored on this gateway");
        err.code = res?.error?.code === "stale_envelope" ? "stale_envelope" : "not_found";
        throw err;
      }
      return { username: cred.username, password: cred.password };
    },
    provisionCredential: async (ref: string, envelope: unknown) => {
      const res = await ctx.priv.call({
        v: 1,
        id: `cred-prov-${Date.now()}`,
        method: "credential.provision",
        params: { ref, envelope },
      });
      // PrivSvc reports failure via an error envelope, not a throw — surface it
      // as a coded exception so the classifier can tell "re-enter it" from
      // "try again later".
      if (res?.error) {
        const err: any = new Error(res.error.message || "credential.provision failed");
        err.code = res.error.code;
        throw err;
      }
    },
    removeCredential: async (ref: string) => {
      const res = await ctx.priv.call({
        v: 1,
        id: `cred-rm-${Date.now()}`,
        method: "credential.remove",
        params: { ref },
      });
      if (res?.error && res.error.code !== "not_found") {
        const err: any = new Error(res.error.message || "credential.remove failed");
        err.code = res.error.code;
        throw err;
      }
    },
    makeClient: (cfg: GatewayConfig) =>
      new VimClient({
        host: cfg.vcenter.host,
        port: cfg.vcenter.port,
        tlsThumbprintSha256: cfg.vcenter.tlsThumbprintSha256,
        requestTimeoutMs: cfg.snapshot.perVmTimeoutSec * 1000,
        logger: ctx.logger,
      }),
    now: () => new Date(),
    logger: ctx.logger,
  };
}

const NOT_A_GATEWAY: JobResult = {
  status: ACK_REJECTED,
  message: "vcenter_verify:failed;stage=config;classify=not_a_gateway",
};

/** Build VerifyDeps around a live client + credential. */
function verifyDepsFor(
  client: VimClient,
  cred: VCenterCredential,
  cfg: GatewayConfig,
  now: () => Date
): VerifyDeps {
  let rootFolder = "group-d1";
  return {
    probeReachability: async () => {
      const t0 = Date.now();
      await client.fetchServerFingerprint();
      return Date.now() - t0;
    },
    serverFingerprint: () => client.fetchServerFingerprint(),
    login: async () => {
      const svc = await client.retrieveServiceContent();
      rootFolder = svc.rootFolder;
      return client.login(cred.username, cred.password);
    },
    listPrivileges: () => client.listPrivileges(),
    checkPrivileges: (sessionKey, privIds) =>
      client.hasPrivilegeOnEntity(sessionKey, privIds, { moref: rootFolder, type: "Folder" }),
    countVmsInScope: () => client.countVms(),
    logout: () => client.logout(),
    now,
  };
}

/**
 * `vcenter_verify` — run the ladder and report a structured diagnostic.
 *
 * Never throws: the report IS the product. A control plane that cannot read the
 * credential still needs to know exactly which rung broke and whether a retry
 * is safe.
 */
export async function runVcenterVerify(deps: ConnectorDeps): Promise<JobResult> {
  const cfg = deps.gatewayConfig();
  if (!cfg) return NOT_A_GATEWAY;

  let cred: VCenterCredential;
  try {
    cred = await deps.getCredential(cfg.vcenter.credentialRef);
  } catch (e: any) {
    // No stored credential yet, or the envelope could not be opened. Terminal:
    // retrying cannot conjure a credential, and must not touch vCenter at all.
    return {
      status: ACK_REJECTED,
      message: `vcenter_verify:failed;stage=credential;classify=${
        e?.code === "stale_envelope" ? "stale_envelope" : "no_credential"
      }`,
    };
  }

  const client = deps.makeClient(cfg);
  let report: VerifyReport;
  try {
    report = await runVerification(
      verifyDepsFor(client, cred, cfg, deps.now),
      {
        host: cfg.vcenter.host,
        port: cfg.vcenter.port,
        tlsThumbprintSha256: cfg.vcenter.tlsThumbprintSha256,
      }
    );
  } finally {
    // Drop the secret as soon as the operation is over.
    cred.password = "";
  }

  deps.logger?.info?.("vcenter_verify completed", {
    ok: report.ok,
    stage: report.failedStage,
    classify: report.classify,
  });
  return buildVerifyAck(report);
}

export interface CredentialProvisionPayload {
  /** Key into the OS credential store. */
  ref?: string;
  /** Sealed envelope — opaque to the control plane, openable only by PrivSvc. */
  envelope?: unknown;
}

/**
 * `vcenter_credential_provision` — store a sealed credential, then prove it works.
 *
 * PrivSvc owns the enrollment private key, so it is the only component that can
 * open the envelope; this handler is a thin, well-classified relay. On success
 * it immediately runs the verification ladder so the ACK answers the question
 * the admin actually asked — "does this credential work?" — rather than merely
 * "the bytes arrived".
 *
 * Deliberately does NOT require gateway config to be present: the policy
 * override carrying `gateway.vcenter` and this job travel independently and may
 * arrive in either order. Storing a credential on a device that never becomes a
 * gateway is inert — nobody else can open the envelope anyway.
 */
export async function runVcenterCredentialProvision(
  deps: ConnectorDeps,
  payload: CredentialProvisionPayload
): Promise<JobResult> {
  const ref = String(payload?.ref || "vcenter/default");
  if (!payload?.envelope || typeof payload.envelope !== "object") {
    return buildProvisionAck("malformed", { reason: "envelope missing" });
  }

  const provision = deps.provisionCredential?.bind(deps);
  if (!provision) {
    return buildProvisionAck("store_unavailable", { reason: "privsvc unavailable" });
  }

  try {
    await provision(ref, payload.envelope);
  } catch (e: any) {
    const code = String(e?.code || "");
    switch (code) {
      case "stale_envelope":
        return buildProvisionAck("stale_envelope", {
          reason: "sealed against a rotated certificate; re-enter the credential",
        });
      case "decrypt_failed":
        return buildProvisionAck("decrypt_failed");
      case "unsupported_version":
        return buildProvisionAck("unsupported_version");
      case "malformed":
        return buildProvisionAck("malformed");
      case "store_unavailable":
        return buildProvisionAck("store_unavailable", { reason: "os credential store unavailable" });
      default:
        // Unknown failure: terminal, not retryable. Re-attempting an
        // unexplained provisioning error cannot help and may mask the cause.
        return buildProvisionAck("rejected", { reason: code || "unexpected" });
    }
  }

  // Stored. Now answer the real question.
  let verify: VerifyReport | null = null;
  try {
    const ack = await runVcenterVerify(deps);
    verify = decodeReport<VerifyReport>(ack.message);
  } catch {
    // The credential IS stored; a verification hiccup must not turn that into a
    // failure the admin would "fix" by re-entering a perfectly good password.
    verify = null;
  }

  deps.logger?.info?.("vcenter credential provisioned", { ref, verified: verify?.ok ?? null });
  return buildProvisionAck("stored", { verify });
}

/**
 * `vcenter_credential_remove` — forget the stored vCenter credential.
 *
 * Sent when a gateway is de-registered. Idempotent by contract: removing a ref
 * that isn't there succeeds, so a repeat delivery (or a device that already
 * forgot) is not an error. A secret that outlives its purpose is a liability,
 * so this is best-effort but never silently skipped.
 */
export async function runVcenterCredentialRemove(
  deps: ConnectorDeps,
  payload: { ref?: string }
): Promise<JobResult> {
  const ref = String(payload?.ref || "vcenter/default");
  const remove = deps.removeCredential?.bind(deps);
  if (!remove) {
    return { status: ACK_OK, message: "vcenter_credential_remove:noop;reason=unsupported" };
  }
  try {
    await remove(ref);
    return { status: ACK_OK, message: "vcenter_credential_remove:removed" };
  } catch (e: any) {
    const code = String(e?.code || "");
    if (code === "not_found") {
      // Already gone is the desired end state.
      return { status: ACK_OK, message: "vcenter_credential_remove:removed;reason=not_found" };
    }
    return {
      status: 1, // transient: the store may come back
      message: `vcenter_credential_remove:failed;reason=${code || "unexpected"}`,
    };
  }
}

export interface SnapshotRemovePayload {
  snapshots?: Array<{
    snapshotResultId?: number;
    deploymentId?: number;
    targetDeviceId?: string;
    snapshotMoref?: string;
  }>;
}

/**
 * `vcenter_snapshot_remove` — reclaim expired pre-patch snapshots.
 *
 * Batched per gateway, but each snapshot succeeds or fails INDEPENDENTLY: one
 * VM that is busy or already-deleted must not strand the rest of the batch,
 * because everything left behind keeps growing against the datastore.
 *
 * Concurrency is bounded by the gateway's own config — deleting dozens of
 * snapshots at once is exactly the kind of storm that stuns the datastore this
 * cleanup exists to protect.
 */
export async function runVcenterSnapshotRemove(
  deps: ConnectorDeps,
  payload: SnapshotRemovePayload
): Promise<JobResult> {
  const cfg = deps.gatewayConfig();
  if (!cfg) {
    return { status: ACK_REJECTED, message: "vcenter_snapshot_remove:rejected;reason=not_a_gateway" };
  }
  const items = (payload?.snapshots ?? []).filter((s) => s?.snapshotMoref);
  if (!items.length) {
    return { status: ACK_OK, message: "vcenter_snapshot_remove:noop;removed=0" };
  }

  let cred: VCenterCredential | null = null;
  const client = deps.makeClient(cfg);
  const removed: number[] = [];
  const failed: Array<{ id: number; reason: string }> = [];

  try {
    await client.assertPinnedCertificate();
    cred = await deps.getCredential(cfg.vcenter.credentialRef);
    await client.retrieveServiceContent();
    await client.login(cred.username, cred.password);

    const limit = Math.max(1, cfg.snapshot.maxConcurrent);
    for (let i = 0; i < items.length; i += limit) {
      const slice = items.slice(i, i + limit);
      const results = await Promise.all(
        slice.map(async (s) => {
          try {
            const task = await client.removeSnapshot(String(s.snapshotMoref), false);
            await client.waitForTask(task, { timeoutMs: cfg.snapshot.perVmTimeoutSec * 1000 });
            return { id: Number(s.snapshotResultId) || 0, ok: true, reason: "" };
          } catch (e: any) {
            const msg = String(e?.message ?? e);
            // A snapshot vCenter no longer knows about IS the desired end
            // state — report it cleaned rather than retrying forever.
            const gone = /not found|has already been deleted|managed object.*not exist/i.test(msg);
            return {
              id: Number(s.snapshotResultId) || 0,
              ok: gone,
              reason: gone ? "already_gone" : msg.slice(0, 80),
            };
          }
        })
      );
      for (const r of results) {
        if (r.ok) removed.push(r.id);
        else failed.push({ id: r.id, reason: r.reason });
      }
    }
  } catch (e: any) {
    // Session-level failure: nothing in this batch was processed.
    const { retryable, reason } = classifySnapshotError(e);
    return {
      status: retryable ? 1 : ACK_REJECTED,
      message: `vcenter_snapshot_remove:failed;removed=0;reason=${reason}`,
    };
  } finally {
    if (cred) cred.password = "";
    await client.logout().catch(() => {});
  }

  // Partial success is still success for the ones that worked — the backend
  // marks exactly those rows cleaned, and retries only what is left.
  const outcome = failed.length === 0 ? "removed" : "partial";
  return {
    status: failed.length === 0 ? ACK_OK : 1,
    message:
      `vcenter_snapshot_remove:${outcome};removed=${removed.length};failed=${failed.length}` +
      (removed.length ? `;ids=${removed.join(",")}` : "") +
      (failed.length ? `;failedIds=${failed.map((f) => f.id).join(",")}` : ""),
  };
}

export interface SnapshotRevertPayload {
  snapshotResultId?: number;
  snapshotMoref?: string;
}

/**
 * `vcenter_snapshot_revert` — roll a VM back to its pre-patch snapshot.
 *
 * Never automatic. This runs only when an operator explicitly asks, because a
 * revert discards EVERYTHING written since the snapshot — user data, other
 * applications' state, unrelated changes. That is a human decision, and the
 * control plane treats it as one (admin-gated endpoint, no scheduler path).
 */
export async function runVcenterSnapshotRevert(
  deps: ConnectorDeps,
  payload: SnapshotRevertPayload
): Promise<JobResult> {
  const cfg = deps.gatewayConfig();
  if (!cfg) {
    return { status: ACK_REJECTED, message: "vcenter_snapshot_revert:rejected;reason=not_a_gateway" };
  }
  const moref = String(payload?.snapshotMoref || "");
  if (!moref) {
    return { status: ACK_REJECTED, message: "vcenter_snapshot_revert:rejected;reason=no_snapshot" };
  }

  let cred: VCenterCredential | null = null;
  const client = deps.makeClient(cfg);
  const started = Date.now();
  try {
    await client.assertPinnedCertificate();
    cred = await deps.getCredential(cfg.vcenter.credentialRef);
    await client.retrieveServiceContent();
    await client.login(cred.username, cred.password);

    const task = await client.revertToSnapshot(moref);
    await client.waitForTask(task, { timeoutMs: cfg.snapshot.perVmTimeoutSec * 1000 });

    return {
      status: ACK_OK,
      message:
        `vcenter_snapshot_revert:reverted;snapshotId=${moref};duration=${Date.now() - started}` +
        (payload?.snapshotResultId ? `;snapshotResultId=${payload.snapshotResultId}` : ""),
    };
  } catch (e: any) {
    const { retryable, reason } = classifySnapshotError(e);
    return {
      status: retryable ? 1 : ACK_REJECTED,
      message: `vcenter_snapshot_revert:failed;snapshotId=${moref};reason=${reason}`,
    };
  } finally {
    if (cred) cred.password = "";
    await client.logout().catch(() => {});
  }
}

export interface SnapshotJobPayload {
  deploymentId?: number;
  /** Facts identifying the endpoint whose VM must be snapshotted. */
  target?: EndpointVmFacts;
  /** Snapshot name; the gateway prefixes/derives one when absent. */
  name?: string;
  description?: string;
}

/**
 * `vcenter_snapshot` — correlate the endpoint to its vCenter VM and snapshot it.
 *
 * Correlation is fail-closed: when no candidate matches we return
 * `not_correlated` and take NO snapshot, rather than guessing at a VM. A wrong
 * guess would snapshot — and later potentially roll back — the wrong machine.
 */
export async function runVcenterSnapshot(
  deps: ConnectorDeps,
  payload: SnapshotJobPayload
): Promise<JobResult> {
  const cfg = deps.gatewayConfig();
  if (!cfg) {
    return {
      status: ACK_REJECTED,
      message: `vcenter_snapshot:rejected;deploymentId=${payload?.deploymentId ?? 0};reason=not_a_gateway`,
    };
  }

  const candidates = buildMatchCandidates(payload?.target ?? {});
  if (!candidates.length) {
    return buildSnapshotAck({
      outcome: "not_correlated",
      deploymentId: payload?.deploymentId,
      reason: "endpoint is not a vm or reports no usable identifiers",
    });
  }

  const started = Date.now();
  let cred: VCenterCredential | null = null;
  const client = deps.makeClient(cfg);

  try {
    await client.assertPinnedCertificate();
    cred = await deps.getCredential(cfg.vcenter.credentialRef);
    await client.retrieveServiceContent();
    await client.login(cred.username, cred.password);

    let vmMoref: string | null = null;
    let matchedBy = "";
    let matchedUuid = "";
    for (const c of candidates) {
      vmMoref = await client.findVmByUuid(c.uuid, false);
      if (vmMoref) {
        matchedBy = c.source;
        matchedUuid = c.uuid;
        break;
      }
    }
    if (!vmMoref) {
      return buildSnapshotAck({
        outcome: "not_correlated",
        deploymentId: payload?.deploymentId,
        vmUuid: candidates[0].uuid,
        reason: "no vcenter vm matched any correlation key",
      });
    }

    const name = payload?.name || `tracenium-prepatch-${payload?.deploymentId ?? 0}`;
    const description =
      payload?.description || `Tracenium pre-patch snapshot (deployment ${payload?.deploymentId ?? 0})`;

    const task = await client.createSnapshot(
      vmMoref,
      name,
      description,
      cfg.snapshot.memory,
      cfg.snapshot.quiesce
    );
    await client.waitForTask(task, { timeoutMs: cfg.snapshot.perVmTimeoutSec * 1000 });

    const snapshotId = (await client.currentSnapshot(vmMoref)) ?? "";

    return buildSnapshotAck({
      outcome: "created",
      deploymentId: payload?.deploymentId,
      vmUuid: matchedUuid,
      vmMoref,
      snapshotId,
      matchedBy,
      durationMs: Date.now() - started,
    });
  } catch (e: any) {
    const { outcome, retryable, reason } = classifySnapshotError(e);
    deps.logger?.warn?.("vcenter_snapshot failed", { reason, retryable });
    return buildSnapshotAck({
      outcome,
      deploymentId: payload?.deploymentId,
      durationMs: Date.now() - started,
      reason,
      retryable,
    });
  } finally {
    if (cred) cred.password = "";
    await client.logout().catch(() => {});
  }
}

/**
 * Map a failure onto an ACK outcome + retry decision.
 *
 * Retry only what a retry can actually fix. Anything touching authentication is
 * terminal so the orchestrator cannot hammer vSphere into locking the account.
 */
export function classifySnapshotError(e: any): {
  outcome: SnapshotOutcome;
  retryable: boolean;
  reason: string;
} {
  const msg = String(e?.message ?? e);
  if (e instanceof PinMismatchError) {
    return { outcome: "rejected", retryable: false, reason: "tls_pin_mismatch" };
  }
  if (/timed out|timeout/i.test(msg)) {
    return { outcome: "timed_out", retryable: true, reason: "task_timeout" };
  }
  if (/incorrect user name or password|invalidlogin|cannot complete login/i.test(msg)) {
    return { outcome: "rejected", retryable: false, reason: "bad_credentials" };
  }
  if (/permission|not authorized|authorize/i.test(msg)) {
    return { outcome: "rejected", retryable: false, reason: "insufficient_privileges" };
  }
  if (/econnrefused|ehostunreach|enotfound|socket hang up|network/i.test(msg)) {
    return { outcome: "failed", retryable: true, reason: "network" };
  }
  if (e instanceof VimFault) {
    // A vCenter-side operational failure (no datastore space, VM busy, …).
    // Worth one retry; the orchestrator's attempt budget bounds it.
    return { outcome: "failed", retryable: true, reason: "vcenter_fault" };
  }
  return { outcome: "failed", retryable: false, reason: "unexpected" };
}
