// src/user-actions/user-actions.ts
//
// «Acciones para el usuario» (ADR-0036 D1, 29-sep): lo que en este equipo sólo
// puede hacer la persona que lo usa, aunque el agente sea root. Primer caso,
// `os.update`: en Apple silicon `softwareupdate --install` pide la contraseña
// de un propietario del volumen (job e4689371, 28-sep, una hora colgado).
//
// Reparto:
//   · el agente GUARDA la acción (state/user-actions.json), la publica a la
//     bandeja (tray-status.json → `userActions`) y la CIERRA cuando OBSERVA el
//     estado pedido — cada `kind` sabe cómo (os.update: el escaneo PMP ya no
//     lista la etiqueta, plugins/pmp/os-update-action.ts);
//   · la bandeja decide CUÁNDO recordarla (UserActionReminder.swift) y deja
//     sus eventos —enseñada, abrió Ajustes, más tarde— en un sink que el agente
//     recoge (user-action-events-watcher.ts). Son TELEMETRÍA: nunca cierran
//     una acción, porque pulsar «Abrir Ajustes» no instala nada.
//
// Sustituye a plugins/pmp/os-update-nudge.ts (4fb0f20, sin desplegar).

import fs from "fs";
import path from "path";
import type { TrayUserAction } from "../status/tray-status-types";

export const USER_ACTION_KINDS = ["os.update"] as const;
export type UserActionKind = (typeof USER_ACTION_KINDS)[number];

export type UserAction = {
  actionId: string;
  kind: UserActionKind;
  params: Record<string, unknown>;
  deadlineUtc?: string;
  expiresUtc: string;
  jobId: string;
  requestedAtUtc: string;
  // ── Telemetría de la bandeja (sink). Nunca decide el cierre. ──
  shownCount?: number;
  lastShownAtUtc?: string;
  snoozedCount?: number;
  dismissedCount?: number;
  openedAtUtc?: string;
};

export type UserActionEvent = {
  actionId: string;
  event: "shown" | "opened" | "snoozed" | "dismissed";
  atUtc: string;
};

const ACTION_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

// ── Payload del job ──────────────────────────────────────────────────

export type ParsedUserActionJob =
  | { ok: true; op: "request"; action: UserAction }
  | { ok: true; op: "cancel"; actionId: string }
  | { ok: false; error: string };

function validParams(kind: UserActionKind, params: any): Record<string, unknown> | null {
  if (!params || typeof params !== "object" || Array.isArray(params)) return null;
  if (kind === "os.update") {
    const label = typeof params.label === "string" ? params.label.trim() : "";
    if (!label || label.length > 200) return null;
    if (params.title != null && (typeof params.title !== "string" || params.title.length > 200)) return null;
    return { label, ...(typeof params.title === "string" && params.title.trim() ? { title: params.title.trim() } : {}) };
  }
  return null;
}

/**
 * El payload validado. Mismas reglas que el backend (job-types.ts,
 * validateUserActionPayload) salvo una: aquí una fecha límite pasada se
 * acepta —el equipo pudo estar días apagado— y el aviso sale ya como
 * vencido, que es la verdad. Una acción ya caducada no se guarda.
 */
export function parseUserActionPayload(payload: unknown, jobId: string, now: Date = new Date()): ParsedUserActionJob {
  const p = payload as any;
  if (!p || typeof p !== "object" || Array.isArray(p)) return { ok: false, error: "invalid_user_action_payload" };
  if (typeof p.actionId !== "string" || !ACTION_ID_RE.test(p.actionId)) return { ok: false, error: "invalid_user_action_payload" };
  if (p.op === "cancel") return { ok: true, op: "cancel", actionId: p.actionId };
  if (p.op !== "request") return { ok: false, error: "invalid_user_action_payload" };
  if (!(USER_ACTION_KINDS as readonly string[]).includes(p.kind)) return { ok: false, error: "unsupported_user_action_kind" };
  const kind = p.kind as UserActionKind;
  const params = validParams(kind, p.params);
  if (!params) return { ok: false, error: "invalid_user_action_params" };

  let deadlineUtc: string | undefined;
  if (p.deadlineUtc != null) {
    const d = typeof p.deadlineUtc === "string" ? Date.parse(p.deadlineUtc) : NaN;
    if (!Number.isFinite(d)) return { ok: false, error: "invalid_user_action_payload" };
    deadlineUtc = new Date(d).toISOString();
  } else if (kind === "os.update") {
    return { ok: false, error: "user_action_deadline_required" };
  }
  const e = typeof p.expiresUtc === "string" ? Date.parse(p.expiresUtc) : NaN;
  if (!Number.isFinite(e)) return { ok: false, error: "invalid_user_action_payload" };
  if (e <= now.getTime()) return { ok: false, error: "user_action_expired" };

  return {
    ok: true,
    op: "request",
    action: {
      actionId: p.actionId,
      kind,
      params,
      ...(deadlineUtc ? { deadlineUtc } : {}),
      expiresUtc: new Date(e).toISOString(),
      jobId,
      requestedAtUtc: now.toISOString(),
    },
  };
}

// ── Operaciones puras sobre la lista ─────────────────────────────────

/**
 * La clave natural de una acción: dos peticiones con la misma son LA MISMA
 * cosa pedida otra vez (p. ej. otra fecha para la misma actualización).
 */
export function naturalKey(a: Pick<UserAction, "kind" | "params" | "actionId">): string {
  if (a.kind === "os.update") return `os.update:${String(a.params.label ?? "")}`;
  return `${a.kind}:${a.actionId}`;
}

/** Una petición nueva sustituye a la anterior con el mismo id o la misma clave natural. */
export function upsertAction(list: UserAction[], action: UserAction): UserAction[] {
  const key = naturalKey(action);
  return [...list.filter((a) => a.actionId !== action.actionId && naturalKey(a) !== key), action];
}

export function cancelAction(list: UserAction[], actionId: string): UserAction[] {
  return list.filter((a) => a.actionId !== actionId);
}

export function isExpired(a: UserAction, now: Date = new Date()): boolean {
  return Date.parse(a.expiresUtc) <= now.getTime();
}

/** Separa lo caducado: deja de recordarse y se informa `expired`, no desaparece sin más. */
export function partitionExpired(list: UserAction[], now: Date = new Date()): { live: UserAction[]; expired: UserAction[] } {
  const live: UserAction[] = [];
  const expired: UserAction[] = [];
  for (const a of list) (isExpired(a, now) ? expired : live).push(a);
  return { live, expired };
}

/** Suma los eventos de la bandeja a sus acciones. Los de acciones que ya no existen se ignoran. */
export function applyEvents(list: UserAction[], events: UserActionEvent[]): UserAction[] {
  const byId = new Map(list.map((a) => [a.actionId, { ...a }]));
  for (const e of events) {
    const a = byId.get(e.actionId);
    if (!a) continue;
    if (e.event === "shown") {
      a.shownCount = (a.shownCount ?? 0) + 1;
      a.lastShownAtUtc = e.atUtc;
    } else if (e.event === "snoozed") {
      a.snoozedCount = (a.snoozedCount ?? 0) + 1;
    } else if (e.event === "dismissed") {
      a.dismissedCount = (a.dismissedCount ?? 0) + 1;
    } else if (e.event === "opened") {
      a.openedAtUtc = e.atUtc;
    }
  }
  return list.map((a) => byId.get(a.actionId) ?? a);
}

/**
 * Lo que ve la bandeja: todas las vivas, de la más urgente a la menos —
 * vencidas, después por fecha más cercana, después las sin fecha.
 */
export function trayActionsFrom(list: UserAction[], now: Date = new Date()): TrayUserAction[] {
  const rank = (a: UserAction) => (a.deadlineUtc ? Date.parse(a.deadlineUtc) : Number.POSITIVE_INFINITY);
  return list
    .filter((a) => !isExpired(a, now))
    .sort((a, b) => rank(a) - rank(b))
    .map((a) => ({
      actionId: a.actionId,
      kind: a.kind,
      title: titleOf(a),
      ...(a.deadlineUtc ? { deadlineUtc: a.deadlineUtc } : {}),
      expiresUtc: a.expiresUtc,
      params: a.params,
    }));
}

function titleOf(a: UserAction): string {
  if (a.kind === "os.update") return String(a.params.title ?? a.params.label ?? "");
  return a.kind;
}

// ── Fichero de estado ────────────────────────────────────────────────

function statePath(): string {
  const base = process.platform === "darwin" ? "/Library/Application Support/Tracenium" : "/var/lib/tracenium";
  const dir = process.env.TRACENIUM_STATE_DIR || path.join(base, "state");
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, "user-actions.json");
}

export function loadUserActions(): UserAction[] {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath(), "utf8"));
    return Array.isArray(parsed)
      ? parsed.filter(
          (a) =>
            a &&
            typeof a.actionId === "string" &&
            (USER_ACTION_KINDS as readonly string[]).includes(a.kind) &&
            typeof a.expiresUtc === "string",
        )
      : [];
  } catch {
    return [];
  }
}

export function saveUserActions(list: UserAction[]): void {
  const file = statePath();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

// ── Con efectos: guardar y publicar ──────────────────────────────────

type TrayPublisher = { trayStatus: { setUserActions(list: TrayUserAction[] | null): unknown } };
type MaybeLogger = { logger?: { info?: (...a: any[]) => void; warn?: (...a: any[]) => void } };

/**
 * Guarda `next` y la publica. Lo caducado se retira aquí, en un solo sitio,
 * y se deja en el log como `expired` (el portal lo recibirá cuando exista el
 * registro de acciones, ADR-0036 F2).
 */
export function commitUserActions(ctx: TrayPublisher & MaybeLogger, next: UserAction[], now: Date = new Date()): UserAction[] {
  const { live, expired } = partitionExpired(next, now);
  for (const a of expired) {
    ctx.logger?.info?.("user action expired without being done", {
      actionId: a.actionId,
      kind: a.kind,
      shownCount: a.shownCount ?? 0,
      snoozedCount: a.snoozedCount ?? 0,
      openedAtUtc: a.openedAtUtc ?? null,
    });
  }
  saveUserActions(live);
  const tray = trayActionsFrom(live, now);
  ctx.trayStatus.setUserActions(tray.length ? tray : null);
  return live;
}

/** Aplica el job `user_action`: alta (o sustitución) o cancelación. */
export function acceptUserActionJob(
  ctx: TrayPublisher & MaybeLogger,
  parsed: Extract<ParsedUserActionJob, { ok: true }>,
  now: Date = new Date(),
): UserAction[] {
  const current = loadUserActions();
  const next = parsed.op === "request" ? upsertAction(current, parsed.action) : cancelAction(current, parsed.actionId);
  return commitUserActions(ctx, next, now);
}

/**
 * Lo que queda tras observar un `kind`: sólo se cierran las de ESE kind que
 * ya no están pendientes; con `stillPending` null (observación no fiable) no
 * se cierra nada. Puro.
 */
export function closeObserved(
  list: UserAction[],
  kind: UserActionKind,
  stillPending: ((a: UserAction) => boolean) | null,
): UserAction[] {
  if (!stillPending) return list;
  return list.filter((a) => a.kind !== kind || stillPending(a));
}

/**
 * Cierra las acciones de un `kind` según lo OBSERVADO. `stillPending` devuelve
 * null cuando la observación no es fiable (un escaneo que falló): entonces no
 * se cierra NADA — cerrar por un escaneo roto sería dar por hecho lo que no lo
 * está. Sólo escribe si algo cambió.
 */
export function reconcileKind(
  ctx: TrayPublisher & MaybeLogger,
  kind: UserActionKind,
  stillPending: ((a: UserAction) => boolean) | null,
  now: Date = new Date(),
): UserAction[] {
  const current = loadUserActions();
  if (current.length === 0) return current;
  const next = closeObserved(current, kind, stillPending);
  for (const a of current) {
    if (!next.includes(a)) {
      ctx.logger?.info?.("user action done (observed)", { actionId: a.actionId, kind: a.kind, shownCount: a.shownCount ?? 0 });
    }
  }
  const changed = next.length !== current.length || current.some((a) => isExpired(a, now));
  return changed ? commitUserActions(ctx, next, now) : current;
}
