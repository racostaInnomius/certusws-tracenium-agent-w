/**
 * Structured ACK encoding for gateway jobs.
 *
 * PURE. The gateway is the only party that can decrypt the vCenter credential,
 * so it is also the only party that can find out whether the credential works.
 * The RESULT is not secret, so it travels back to the control plane over the
 * existing Ack channel — no proto change: the same
 * `<jobType>:<outcome>;k=v;…;report=<base64url json>` shape SDP already uses for
 * detectBefore/detectAfter. See ADR-0001 (C-bis).
 */

import type { VerifyReport } from "./verify";

/** Mirrors the proto AckStatus enum. */
export const ACK_OK = 0;
export const ACK_RETRY = 1;
export const ACK_REJECTED = 2;

export type SnapshotOutcome =
  | "created"
  | "removed"
  | "not_correlated"
  | "rejected"
  | "failed"
  | "timed_out";

/** Keep an ACK comfortably inside any per-message limit. */
const MAX_REPORT_BYTES = 8192;

function encodeReport(report: unknown): string {
  const json = JSON.stringify(report);
  const b64 = Buffer.from(json, "utf8").toString("base64url");
  if (b64.length <= MAX_REPORT_BYTES) return b64;
  // Never truncate base64 (it would decode to garbage). Fall back to a minimal
  // envelope that still tells the operator where to look.
  const r = report as Partial<VerifyReport>;
  return Buffer.from(
    JSON.stringify({
      ok: r?.ok ?? false,
      failedStage: r?.failedStage ?? null,
      classify: r?.classify ?? null,
      truncated: true,
    }),
    "utf8"
  ).toString("base64url");
}

/** `k=v` pairs, skipping empty values, with separators stripped from input. */
function kv(pairs: Record<string, string | number | boolean | null | undefined>): string {
  return Object.entries(pairs)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${k}=${String(v).replace(/[;=]/g, "_")}`)
    .join(";");
}

/**
 * ACK for `vcenter_verify`.
 *
 * Status mapping is the lockout guard: only a transport-level failure is
 * retryable. A bad password or a missing privilege comes back REJECTED so the
 * orchestrator stops, because vSphere locks accounts after repeated failed
 * logins — an automatic retry would turn a typo into a locked service account.
 */
export function buildVerifyAck(report: VerifyReport): { status: number; message: string } {
  const status = report.ok ? ACK_OK : report.retryable ? ACK_RETRY : ACK_REJECTED;
  const message =
    `vcenter_verify:${report.ok ? "ok" : "failed"};` +
    kv({
      stage: report.failedStage ?? undefined,
      classify: report.classify ?? undefined,
      retryable: report.ok ? undefined : report.retryable,
    }) +
    (report.ok ? "" : ";") +
    `report=${encodeReport(report)}`;
  return { status, message };
}

export interface SnapshotAckFields {
  outcome: SnapshotOutcome;
  deploymentId?: number;
  vmUuid?: string;
  vmMoref?: string;
  snapshotId?: string;
  /** Which correlation key actually matched — feeds the fleet-wide preview. */
  matchedBy?: string;
  durationMs?: number;
  reason?: string;
  retryable?: boolean;
}

/** ACK for `vcenter_snapshot`. */
export function buildSnapshotAck(f: SnapshotAckFields): { status: number; message: string } {
  const ok = f.outcome === "created" || f.outcome === "removed";
  const status = ok ? ACK_OK : f.retryable ? ACK_RETRY : ACK_REJECTED;
  const body = kv({
    deploymentId: f.deploymentId,
    vmUuid: f.vmUuid,
    moref: f.vmMoref,
    snapshotId: f.snapshotId,
    matchedBy: f.matchedBy,
    duration: f.durationMs,
    reason: f.reason,
  });
  return {
    status,
    message: `vcenter_snapshot:${f.outcome}${body ? ";" + body : ""}`,
  };
}

export type ProvisionOutcome =
  | "stored"
  | "stale_envelope"
  | "decrypt_failed"
  | "malformed"
  | "unsupported_version"
  | "store_unavailable"
  | "rejected";

/**
 * ACK for `vcenter_credential_provision`.
 *
 * Only `store_unavailable` is retryable. Everything else is a property of the
 * envelope itself, and no number of retries will change it — while retrying
 * would just re-attempt a decryption that cannot succeed.
 *
 * When the credential stored cleanly the gateway immediately self-verifies, and
 * that report rides along here. The admin therefore gets a real answer to "does
 * this credential work?" from the single action of saving it, instead of an
 * optimistic "saved" followed by a surprise at patch time.
 */
export function buildProvisionAck(
  outcome: ProvisionOutcome,
  opts: { verify?: VerifyReport | null; reason?: string } = {}
): { status: number; message: string } {
  const stored = outcome === "stored";
  const status = stored ? ACK_OK : outcome === "store_unavailable" ? ACK_RETRY : ACK_REJECTED;
  const parts = [`vcenter_credential_provision:${outcome}`];
  const body = kv({
    reason: opts.reason,
    verified: opts.verify ? String(opts.verify.ok) : undefined,
    stage: opts.verify && !opts.verify.ok ? (opts.verify.failedStage ?? undefined) : undefined,
    classify: opts.verify && !opts.verify.ok ? (opts.verify.classify ?? undefined) : undefined,
  });
  if (body) parts.push(body);
  if (opts.verify) parts.push(`report=${encodeReport(opts.verify)}`);
  return { status, message: parts.join(";") };
}

/** Decode a report emitted by buildVerifyAck — used by tests and the backend. */
export function decodeReport<T = VerifyReport>(ackMessage: string): T | null {
  const m = ackMessage.match(/;report=([A-Za-z0-9_-]+)/);
  if (!m) return null;
  try {
    return JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}
