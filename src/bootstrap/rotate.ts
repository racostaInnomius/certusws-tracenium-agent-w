// src/bootstrap/rotate.ts
import fs from "fs";
import { EnrollmentStore } from "./enrollment-store";
import { EnrollmentState } from "./enrollment-state";

/**
 * Aplica nuevos PEMs y actualiza enrollment state.
 * (v2: CSR flow — private key stays in Windows CNG via PrivSvc)
 */
export function applyMtlsRotation(params: {
  clientCertPem: string;
  caBundlePem: string;
}) {
  const store = new EnrollmentStore();
  const state = store.load();
  if (!state) throw new Error("Not enrolled");

  const paths = store.getPaths();
  fs.writeFileSync(paths.clientCert, params.clientCertPem, "utf8");
  fs.writeFileSync(paths.caBundle, params.caBundlePem, "utf8");

  const next: EnrollmentState = {
    ...state,
    lastRenewedAtUtc: new Date().toISOString(),
    mtls: {
      clientCertPath: paths.clientCert,
      caBundlePath: paths.caBundle
    }
  };

  store.save(next);
  return next;
}

/**
 * Re-enroll completo: borra state local y forzará ensureEnrolled() en siguiente arranque.
 * Útil si el backend revocó deviceId o tenant mapping.
 */
export function forceReEnroll() {
  const store = new EnrollmentStore();
  store.clear();
}