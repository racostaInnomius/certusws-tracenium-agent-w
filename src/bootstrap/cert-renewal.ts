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

/**
 * Las CA emisoras que el equipo acepta TRAS una renovación: la UNIÓN de las
 * que aceptaba antes y las que trae la renovación. Nunca menos.
 *
 * 🔴 EL INCIDENTE (14-sep, MSIG-VEEAM-PC): el privsvc de Windows no reenviaba
 * la lista al renovar, y este módulo conservaba la del enrolamiento — que en un
 * equipo enrolado en agosto NO EXISTÍA. `grpc-client.ts` caía entonces a la
 * huella singular, que tras rotar era la de la G2. El certificado del servidor
 * gRPC sigue emitido por la Issuing vieja, así que el agente rechazó al
 * servidor y se quedó a oscuras sin forma remota de arreglarlo.
 *
 * Por qué UNIÓN y no «la lista nueva»: aceptar menos CAs después de renovar
 * sólo puede desconectar. Quién firma al SERVIDOR no depende de a qué CA rotó
 * este equipo, y durante una transición conviven las dos. Dejar de confiar en
 * una CA es una operación deliberada (re-enrolar), no un efecto lateral.
 *
 * Se deduplica sin distinguir mayúsculas ni separadores (Windows usa SHA-1 en
 * mayúsculas; macOS/Linux SHA-256 en minúsculas) pero se conserva el texto
 * original: cada privsvc compara con su propio formato.
 */
export function mergeIssuingCaThumbprints(
  previous: { issuingCaThumbprint?: string; issuingCaThumbprints?: string[] },
  renewed: { issuingCaThumbprint?: unknown; issuingCaThumbprints?: unknown }
): { issuingCaThumbprint?: string; issuingCaThumbprints: string[] } {
  const renewedList = Array.isArray(renewed.issuingCaThumbprints) ? renewed.issuingCaThumbprints : [];
  const candidates = [
    ...renewedList,
    renewed.issuingCaThumbprint,
    ...(previous.issuingCaThumbprints ?? []),
    previous.issuingCaThumbprint,
  ];
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const c of candidates) {
    const text = typeof c === "string" ? c.trim() : "";
    const key = text.replace(/[^0-9a-z]/gi, "").toUpperCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    merged.push(text);
  }
  const renewedSingular =
    typeof renewed.issuingCaThumbprint === "string" && renewed.issuingCaThumbprint.trim()
      ? renewed.issuingCaThumbprint.trim()
      : undefined;
  return {
    issuingCaThumbprint: renewedSingular ?? previous.issuingCaThumbprint,
    issuingCaThumbprints: merged,
  };
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

/**
 * Read the SHA-256 thumbprint of the client cert currently on disk. Returns
 * null if the file is missing or unreadable. Reuses the same guarded-read +
 * X509Certificate parse as readClientCertNotAfter so both derive from the
 * exact bytes on disk. Used to detect a TOCTOU race: another process (e.g.
 * the gRPC rotateCert path) may replace the cert during the privsvc await.
 */
function readClientCertThumbprintOnDisk(clientCertPath?: string): string | null {
  try {
    if (!clientCertPath || !fs.existsSync(clientCertPath)) {
      return null;
    }

    const pem = fs.readFileSync(clientCertPath, "utf8");
    return new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, "");
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
  /**
   * ADR-0015 — la FORMA que el control plane pide para la identidad
   * reemitida. Viaja en `RotateCert`; vacío o ausente = clásico.
   *
   * ⚠️ Se pasa TAL CUAL al privsvc en vez de interpretarlo aquí. Un
   * valor desconocido tiene que fallar ruidosamente en el handler —que
   * es quien sabe qué algoritmos soporta esa plataforma— y no
   * convertirse en silencio en otra cosa por el camino: producir un
   * algoritmo distinto del pedido sin decirlo es lo que rompió el
   * enrolamiento de Windows en su día.
   */
  altKeyAlgorithm?: string;
  /**
   * ADR-0015 — saltarse el umbral de 30 días.
   *
   * Lo usa el gatillo remoto `RotateCert`: una rotación de CA o una
   * migración a certificados híbridos tiene que reemitir certificados
   * que están perfectamente vigentes, que es justo el caso que el
   * umbral existe para NO hacer. Sin esto el gatillo llegaba al agente
   * y no producía nada, porque `shouldRenew` decía que no tocaba.
   *
   * ⚠️ Salta el umbral, no las demás condiciones: sin huella del
   * certificado actual sigue sin renovar, porque la petición al backend
   * se hace contra esa huella.
   */
  force?: boolean;
}): Promise<EnrollmentState> {
  const { enrollment, store, priv, logger, force , altKeyAlgorithm } = input;
  const notAfter = readClientCertNotAfter(enrollment);

  if (!force && !shouldRenew(notAfter)) {
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

  // Snapshot the thumbprint of the cert on disk BEFORE the privsvc round-trip.
  // We re-read it after the await to detect if another process rotated the
  // cert during the window (TOCTOU). We ask the CA to renew against this same
  // thumbprint, so if disk changes underneath us the response is stale.
  const clientCertPath = enrollment.mtls?.clientCertPath;
  const preRenewalDiskThumbprint = readClientCertThumbprintOnDisk(clientCertPath);

  logger?.info?.("[cert-renewal] starting certificate renewal", {
    deviceId: enrollment.deviceId,
    notAfter: notAfter?.toISOString?.() ?? null,
    // Deja escrito en el log del equipo si la reemisión la pidió el
    // control plane o si tocaba por calendario. Sin esto, una rotación
    // de flota y una renovación rutinaria son indistinguibles al mirar
    // un endpoint concreto.
    forced: force === true
  });

  const response = await priv.call({
    v: 1,
    id: `cert_renew_${Date.now()}`,
    method: "crypto.cert.renew",
    params: {
      serverBaseUrl: config.certRenewalBaseUrl || config.serverBaseUrl,
      tenantId: enrollment.tenantId,
      deviceId: enrollment.deviceId,
      clientCertThumbprint,
      // ⚠️ Sólo se manda si el control plane dijo algo. AUSENTE y CADENA
      // VACÍA no son lo mismo para el handler: ausente significa
      // «conserva la forma que ya tienes» —lo que hace que una
      // renovación por calendario no degrade a un equipo híbrido a
      // clásico— y vacía significa «clásico, explícitamente».
      ...(altKeyAlgorithm ? { altKeyAlgorithm } : {})
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
      // ⚠️ UNIÓN de lo que se aceptaba y lo que trae la renovación — ver
      // mergeIssuingCaThumbprints. Quedarse sólo con la nueva dejó a oscuras
      // a MSIG-VEEAM-PC el 14-sep.
      ...mergeIssuingCaThumbprints(enrollment.mtls, result as any),
      clientCertNotAfter: result.notAfter ? String(result.notAfter) : undefined
    }
  };

  // BUG A4: the response must carry a structurally valid client cert PEM
  // before we persist ANY state. Previously the BEGIN-CERTIFICATE gate only
  // guarded the file write, but store.save() ran regardless — leaving the
  // store pointing at a new thumbprint while the disk kept the old cert.
  // Abort the whole renewal (no file write, no store.save) if the PEM is
  // absent, lacks the BEGIN CERTIFICATE marker, or fails to parse as X.509.
  const clientCertPem = result.clientCertPem;
  if (typeof clientCertPem !== "string" || !clientCertPem.includes("BEGIN CERTIFICATE")) {
    throw new Error("Certificate renewal response missing or malformed clientCertPem");
  }
  try {
    // eslint-disable-next-line no-new
    new crypto.X509Certificate(clientCertPem);
  } catch (err: any) {
    throw new Error(
      `Certificate renewal response clientCertPem failed to parse as X.509: ${err?.message || err}`
    );
  }

  // BUG A1 (TOCTOU): re-verify the cert on disk is still the one we renewed
  // against. If another process (e.g. gRPC rotateCert) replaced it during the
  // await, that cert is newer than what the CA just issued for our stale
  // thumbprint — abort without overwriting so we don't clobber it. The
  // caller's in-memory guard (service.ts armCertRenewal) only protects the
  // enrollment reference; the disk overwrite has to be prevented here.
  const postRenewalDiskThumbprint = readClientCertThumbprintOnDisk(clientCertPath);
  if (postRenewalDiskThumbprint !== preRenewalDiskThumbprint) {
    logger?.warn?.(
      "[cert-renewal] client cert on disk changed during renewal, aborting to avoid clobbering newer cert",
      {
        deviceId: enrollment.deviceId,
        preRenewalDiskThumbprint,
        postRenewalDiskThumbprint
      }
    );
    return enrollment;
  }

  atomicWriteFileSync(enrollment.mtls.clientCertPath, clientCertPem, 0o600);

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
