// src/plugins/pmp/os-update-action.ts
//
// La acción para el usuario `os.update` (ADR-0036 D1): instalar una
// actualización de macOS que el agente no puede instalar —en Apple silicon
// pide la contraseña de un propietario del volumen, job e4689371—.
//
// «Hecho» se OBSERVA: tras cada escaneo de macOS, lo que `softwareupdate
// --list` ya no lista está instalado y la acción se cierra. Un escaneo que
// falló no cierra nada. (Era plugins/pmp/os-update-nudge.ts, 4fb0f20; la
// caducidad «30 días pasada la fecha» la fija ahora el servidor en
// `expiresUtc`.)

import type { PmpNamespace } from "../../domain/pmp-types";
import { reconcileKind, type UserAction } from "../../user-actions/user-actions";

/** Las etiquetas de un escaneo de macOS que salió bien, o null. */
export function labelsFromScan(ns: PmpNamespace | null | undefined): string[] | null {
  if (!ns || ns.overall?.status === "error") return null;
  const items = Array.isArray(ns.scan?.items) ? ns.scan.items : [];
  return items.map((i) => i?.hotFixId).filter((v): v is string => typeof v === "string" && v.length > 0);
}

/** ¿Sigue pendiente esta `os.update` según el escaneo? null = escaneo no fiable. */
export function osUpdateStillPending(labels: string[] | null): ((a: UserAction) => boolean) | null {
  if (!labels) return null;
  const present = new Set(labels);
  return (a) => present.has(String(a.params.label ?? ""));
}

/**
 * Tras cada escaneo de macOS (el programado y el del job): cierra las
 * `os.update` instaladas. Un fallo aquí no puede tirar el escaneo.
 */
export function refreshOsUpdateActionsAfterScan(
  ctx: Parameters<typeof reconcileKind>[0],
  ns: PmpNamespace | null | undefined,
  now: Date = new Date(),
): void {
  reconcileKind(ctx, "os.update", osUpdateStillPending(labelsFromScan(ns)), now);
}
