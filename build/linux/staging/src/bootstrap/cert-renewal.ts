import crypto from "crypto";
import fs from "fs";
import path from "path";
import { EnrollmentState } from "./enrollment-state";
import { EnrollmentStore } from "./enrollment-store";
import { config } from "./config";
import type { IPrivSvcClient } from "../core/agent-context";

/**
 * Write a file atomically: write to `<path>.tmp-<pid>-<rand>` with the
 * desired permissions, fsync, then rename into place. On POSIX, rename is
 * atomic, so a reader either sees the old file or the new file — never a
 * partially-written one. This matters for mTLS material: if the process
 * crashes mid-write, the daemon on next start would load a truncated PEM
 * and fail to reconnect to gRPC, bricking the agent until manual recovery.
 */
function atomicWriteFileSync(targetPath: string, data: string, mode = 0o600) {
  const dir = path.dirname(targetPath);
  const tmp = path.join(
    dir,
    `.${path.basename(targetPath)}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`
  );

  let fd: number | null = null;
  try {
    fd = fs.openSync(tmp, "w", mode);
    fs.writeFileSync(fd, data, "utf8");
    try {
      fs.fsyncSync(fd);
    } catch {
      // fsync may fail on some filesystems (tmpfs); the rename still gives
      // us atomicity within the filesystem journal, so don't abort.
    }
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch {}
    }
  }

  try {
    fs.renameSync(tmp, targetPath);
  } catch (err) {
    // Best-effort cleanup of the tmp file if rename failed.
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }

  // Make sure the permissions are what we asked for even if umask
  // interfered during openSync.
  try { fs.chmodSync(targetPath, mode); } catch {}
}

const DEFAULT_RENEWAL_THRESHOLD_DAYS = 30;

function getRenewalThresholdDays(): number {
  const value = Number(process.env.CERT_RENEWAL_THRESHOLD_DAYS || DEFAULT_RENEWAL_THRESHOLD_DAYS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_RENEWAL_THRESHOLD_DAYS;
}

function readClientCertNotAfter(state: EnrollmentState): Date | null {
  try {
    if (!state.mtls?.clientCertPath || !fs.existsSync(state.mtls.clientCertPath)) {
      return null;
    }

    const pem = fs.readFileSync(state.mtls.clientCertPath, "utf8");
    const cert = new crypto.X509Certificate(pem);
    return cert.validTo ? new Date(cert.validTo) : null;
  } catch {
    return null;
  }
}

function shouldRenew(notAfter: Date | null): boolean {
  if (!notAfter) return false;
  const thresholdMs = getRenewalThresholdDays() * 24 * 60 * 60 * 1000;
  return notAfter.getTime() - Date.now() <= thresholdMs;
}

export async function maybeRenewClientCertificate(input: {
  enrollment: EnrollmentState;
  store: EnrollmentStore;
  priv: IPrivSvcClient;
  logger: any;
}): Promise<EnrollmentState> {
  const { enrollment, store, priv, logger } = input;
  const notAfter = readClientCertNotAfter(enrollment);

  if (!shouldRenew(notAfter)) {
    logger?.info?.("[cert-renewal] certificate renewal not needed", {
      notAfter: notAfter?.toISOString?.() ?? null,
      thresholdDays: getRenewalThresholdDays()
    });
    return enrollment;
  }

  const clientCertThumbprint = enrollment.mtls?.clientCertThumbprint;

  if (!clientCertThumbprint) {
    logger?.warn?.("[cert-renewal] skipping renewal: missing client cert thumbprint");
    return enrollment;
  }

  logger?.info?.("[cert-renewal] starting certificate renewal", {
    deviceId: enrollment.deviceId,
    notAfter: notAfter?.toISOString?.() ?? null
  });

  const response = await priv.call({
    v: 1,
    id: `cert_renew_${Date.now()}`,
    method: "crypto.cert.renew",
    params: {
      serverBaseUrl: config.certRenewalBaseUrl || config.serverBaseUrl,
      tenantId: enrollment.tenantId,
      deviceId: enrollment.deviceId,
      clientCertThumbprint
    },
    meta: {
      tenantId: enrollment.tenantId,
      deviceId: enrollment.deviceId
    }
  });

  if (!response?.ok) {
    throw new Error(response?.error?.message || response?.error || "Certificate renewal failed");
  }

  const result = response.result || {};
  const nextThumbprint = String(result.clientCertThumbprint || "");

  if (!nextThumbprint) {
    throw new Error("Certificate renewal response missing clientCertThumbprint");
  }

  const nextState: EnrollmentState = {
    ...enrollment,
    lastRenewedAtUtc: new Date().toISOString(),
    mtls: {
      ...enrollment.mtls,
      clientCertThumbprint: nextThumbprint,
      issuingCaThumbprint: result.issuingCaThumbprint
        ? String(result.issuingCaThumbprint)
        : enrollment.mtls.issuingCaThumbprint,
      clientCertNotAfter: result.notAfter ? String(result.notAfter) : undefined
    }
  };

  if (typeof result.clientCertPem === "string" && result.clientCertPem.includes("BEGIN CERTIFICATE")) {
    atomicWriteFileSync(enrollment.mtls.clientCertPath, result.clientCertPem, 0o600);
  }

  if (typeof result.caBundlePem === "string" && result.caBundlePem.includes("BEGIN CERTIFICATE")) {
    // CA bundle is public trust material, but keep it 0600 anyway — only
    // root reads it, and we don't want tampering.
    atomicWriteFileSync(enrollment.mtls.caBundlePath, result.caBundlePem, 0o600);
  }

  store.save(nextState);
  logger?.info?.("[cert-renewal] certificate renewal completed", {
    deviceId: nextState.deviceId,
    clientCertThumbprint: nextThumbprint,
    status: result.status || "pending"
  });

  return nextState;
}
