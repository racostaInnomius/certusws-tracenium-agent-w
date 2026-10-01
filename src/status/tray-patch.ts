// src/status/tray-patch.ts
//
// Las filas «Patch status / Patch last scan / Patch error» de la bandeja, a
// partir del ESCANEO de parches. PURO.
//
// 🔴 1-oct-2026, JPR-MacBookPro: la bandeja decía «Patch status: failed» y
// «Patch error: patch_install failed» con macOS 27.0.1 ya instalada por MDM y
// el escaneo a cero. El bloque sólo se escribía al ARRANCAR el agente, desde
// pmp-state.json —el resultado de la última instalación, que el escaneo nunca
// corrige—, y «Patch last scan» no se rellenaba nunca.
//
// Ahora lo escribe cada escaneo: cómo está el equipo según ese escaneo, y el
// error de la última instalación sólo mientras quede algo pendiente — si no
// queda nada, lo que falló ya está puesto por otra vía (la misma regla que la
// columna «Last patch job» del portal, campaign-status.ts).

import type { PmpNamespace } from "../domain/pmp-types";
import type { TrayPatchStatus } from "./tray-status-types";

const plural = (n: number) => `${n} update${n === 1 ? "" : "s"} available`;

/**
 * Los escaneos que terminaron y contaron — la misma lista permitida que el
 * backend (isUsableScanStatus). `inventory_only` con 0 elementos NO es «al
 * día»: es un escaneo que no dijo nada (T111, 12 servidores así).
 */
const COUNTED = new Set(["healthy", "updates_available", "reboot_required"]);

export function trayPatchFromScan(ns: PmpNamespace): TrayPatchStatus {
  const scan = ns.scan;
  const remediation = ns.remediation;
  const lastScanAtUtc = scan?.scannedAtUtc;
  // El reinicio EN VIVO del escaneo; sin él (PrivSvc anterior), la marca de la
  // última instalación.
  const rebootRequired = scan?.rebootPending ?? remediation?.rebootRequired === true;

  if (remediation?.status === "in_progress") {
    return { status: "Installing updates", lastScanAtUtc, rebootRequired, lastError: undefined };
  }

  if (!scan || !COUNTED.has(ns.overall?.status)) {
    return {
      status: ns.overall?.status === "error" || !scan ? "Scan failed" : "Scan incomplete",
      lastScanAtUtc,
      rebootRequired,
      lastError: scan?.note || remediation?.lastError || undefined,
    };
  }

  const pending = Array.isArray(scan.items) ? scan.items.length : 0;
  return {
    status: pending === 0 ? "Up to date" : plural(pending),
    lastScanAtUtc,
    rebootRequired,
    lastError: pending > 0 && remediation?.status === "failed" ? remediation.lastError || "Last install failed" : undefined,
  };
}
