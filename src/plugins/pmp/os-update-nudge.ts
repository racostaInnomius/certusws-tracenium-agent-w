// src/plugins/pmp/os-update-nudge.ts
//
// Pedirle al usuario de un Mac que instale una actualización de macOS antes de
// una fecha (job `os_update_nudge`, 29-sep).
//
// 🔴 Por qué existe. En Apple silicon el agente NO puede instalar una
// actualización del sistema: `softwareupdate --install` pide la contraseña de
// un propietario del volumen aunque corra como root (job e4689371, 28-sep, una
// hora colgado). Sin MDM, lo que queda es que la persona la instale desde
// Ajustes; esto hace que se entere y que no se le olvide.
//
// Reparto:
//   · el agente GUARDA la petición (state/os-update-nudges.json), la publica en
//     tray-status.json como `osUpdateRequest` y la BORRA cuando el escaneo ya
//     no lista la etiqueta — es decir, cuando está instalada;
//   · la bandeja decide CUÁNDO recordarlo (OsUpdateReminder.swift): el ritmo
//     depende de cuándo lo vio la persona, y eso sólo lo sabe su sesión.
//
// Nada de esto instala ni reinicia nada.

import fs from "fs";
import path from "path";
import type { AgentContext } from "../../core/agent-context";
import type { PmpNamespace } from "../../domain/pmp-types";
import type { TrayOsUpdateRequest } from "../../status/tray-status-types";

export type OsUpdateNudge = {
  jobId: string;
  label: string;
  title?: string;
  deadlineUtc: string;
  requestedAtUtc: string;
};

/** Pasados estos días desde la fecha límite sin que se instale, se deja de insistir. */
export const NUDGE_STALE_AFTER_DAYS = 30;

const DAY_MS = 24 * 3600 * 1000;

/** El payload validado, o el motivo del rechazo. Mismas reglas que el backend. */
export function parseNudgePayload(
  payload: unknown,
  jobId: string,
  now: Date = new Date()
): { ok: true; nudge: OsUpdateNudge } | { ok: false; error: string } {
  const p = payload as any;
  if (!p || typeof p !== "object" || Array.isArray(p)) return { ok: false, error: "invalid_os_update_nudge_payload" };
  const label = typeof p.label === "string" ? p.label.trim() : "";
  if (!label || label.length > 200) return { ok: false, error: "invalid_os_update_nudge_payload" };
  if (p.title != null && (typeof p.title !== "string" || p.title.length > 200)) {
    return { ok: false, error: "invalid_os_update_nudge_payload" };
  }
  const deadline = typeof p.deadlineUtc === "string" ? Date.parse(p.deadlineUtc) : NaN;
  if (!Number.isFinite(deadline)) return { ok: false, error: "invalid_os_update_nudge_payload" };
  // El backend ya exigió una fecha futura; aquí puede llegar vencida si el
  // equipo estuvo días apagado. Se guarda igual: el aviso sale ya como vencido,
  // que es la verdad.
  return {
    ok: true,
    nudge: {
      jobId,
      label,
      ...(typeof p.title === "string" && p.title.trim() ? { title: p.title.trim() } : {}),
      deadlineUtc: new Date(deadline).toISOString(),
      requestedAtUtc: now.toISOString()
    }
  };
}

/** Una petición nueva sobre la misma etiqueta sustituye a la anterior (otra fecha). */
export function upsertNudge(list: OsUpdateNudge[], nudge: OsUpdateNudge): OsUpdateNudge[] {
  return [...list.filter((n) => n.label !== nudge.label), nudge];
}

/**
 * Lo que sigue pendiente tras un escaneo. `currentLabels` null = el escaneo no
 * dijo nada fiable (falló): se conserva todo, porque borrar una petición por un
 * escaneo roto sería dar por instalada una actualización que no lo está.
 */
export function reconcileNudges(
  list: OsUpdateNudge[],
  currentLabels: string[] | null,
  now: Date = new Date()
): OsUpdateNudge[] {
  const stale = (n: OsUpdateNudge) => Date.parse(n.deadlineUtc) + NUDGE_STALE_AFTER_DAYS * DAY_MS < now.getTime();
  if (!currentLabels) return list.filter((n) => !stale(n));
  const present = new Set(currentLabels);
  return list.filter((n) => present.has(n.label) && !stale(n));
}

/** La que enseña la bandeja: la de fecha más cercana. */
export function trayRequestFrom(list: OsUpdateNudge[]): TrayOsUpdateRequest | undefined {
  const next = [...list].sort((a, b) => Date.parse(a.deadlineUtc) - Date.parse(b.deadlineUtc))[0];
  if (!next) return undefined;
  return {
    label: next.label,
    title: next.title ?? next.label,
    deadlineUtc: next.deadlineUtc,
    pendingCount: list.length
  };
}

/** Las etiquetas de un escaneo de macOS que salió bien, o null. */
export function labelsFromScan(ns: PmpNamespace | null | undefined): string[] | null {
  if (!ns || ns.overall?.status === "error") return null;
  const items = Array.isArray(ns.scan?.items) ? ns.scan.items : [];
  return items.map((i) => i?.hotFixId).filter((v): v is string => typeof v === "string" && v.length > 0);
}

// ── Fichero de estado ────────────────────────────────────────────────

function statePath(): string {
  const base = process.platform === "darwin" ? "/Library/Application Support/Tracenium" : "/var/lib/tracenium";
  const dir = process.env.TRACENIUM_STATE_DIR || path.join(base, "state");
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, "os-update-nudges.json");
}

export function loadNudges(): OsUpdateNudge[] {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath(), "utf8"));
    return Array.isArray(parsed) ? parsed.filter((n) => n && typeof n.label === "string" && typeof n.deadlineUtc === "string") : [];
  } catch {
    return [];
  }
}

export function saveNudges(list: OsUpdateNudge[]): void {
  const file = statePath();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

/** Guarda la petición del job y la publica a la bandeja. */
export function acceptNudge(ctx: Pick<AgentContext, "trayStatus">, nudge: OsUpdateNudge): OsUpdateNudge[] {
  const next = upsertNudge(loadNudges(), nudge);
  saveNudges(next);
  ctx.trayStatus.setOsUpdateRequest(trayRequestFrom(next) ?? null);
  return next;
}

/**
 * Tras cada escaneo de macOS: lo que ya no sale en `softwareupdate --list` está
 * instalado, y deja de recordarse. Sólo escribe si algo cambió.
 */
export function refreshNudgesAfterScan(ctx: Pick<AgentContext, "trayStatus">, ns: PmpNamespace | null | undefined, now: Date = new Date()): void {
  const current = loadNudges();
  if (current.length === 0) return;
  const next = reconcileNudges(current, labelsFromScan(ns), now);
  if (next.length === current.length) return;
  saveNudges(next);
  ctx.trayStatus.setOsUpdateRequest(trayRequestFrom(next) ?? null);
}
