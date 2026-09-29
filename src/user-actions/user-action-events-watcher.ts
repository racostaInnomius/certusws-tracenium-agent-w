// src/user-actions/user-action-events-watcher.ts
//
// Bandeja → agente: lo que la persona hizo con una acción (ADR-0036 D1). La
// bandeja no tiene credenciales ni red; deja sus eventos en su PROPIA carpeta
// (~/Library/Application Support/Tracenium/user-action-events.json, 0600) y
// este módulo —el agente corre como root— los recoge. Mismo patrón que
// catalog-install-request-watcher.ts.
//
// Son TELEMETRÍA: cuántas veces se enseñó, si pospuso, si abrió Ajustes. No
// cierran ninguna acción; eso lo decide la observación del estado
// (user-actions.ts, reconcileKind).
//
// Consumo único: se borra el fichero al leerlo. Si la bandeja escribe justo
// entre la lectura y el borrado se pierde ese evento — aceptable para un
// contador, y mejor que contar dos veces.

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { parseConsoleUser, resolveHomeDirectory } from "../plugins/amp/providers/geo";
import type { UserActionEvent } from "./user-actions";

const execFileAsync = promisify(execFile);

export const USER_ACTION_EVENTS_FILE = "user-action-events.json";
const EVENTS = new Set(["shown", "opened", "snoozed", "dismissed"]);
/** Tope defensivo: la bandeja escribe un puñado al día. */
const MAX_EVENTS = 200;

async function resolveEventsFilePath(): Promise<string | null> {
  if (process.platform !== "darwin") return null;
  try {
    const { stdout } = await execFileAsync("/usr/bin/stat", ["-f%Su", "/dev/console"], { timeout: 5_000 });
    const user = parseConsoleUser(stdout);
    if (!user) return null;
    const home = await resolveHomeDirectory(user);
    return path.join(home, "Library/Application Support/Tracenium", USER_ACTION_EVENTS_FILE);
  } catch {
    return null;
  }
}

/** Los eventos válidos de un contenido; lo malformado se descarta sin tirar el resto. */
export function parseUserActionEvents(raw: string): UserActionEvent[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed
    .filter(
      (e: any) =>
        e &&
        typeof e.actionId === "string" &&
        EVENTS.has(e.event) &&
        typeof e.atUtc === "string" &&
        Number.isFinite(Date.parse(e.atUtc)),
    )
    .slice(-MAX_EVENTS)
    .map((e: any) => ({ actionId: e.actionId, event: e.event, atUtc: new Date(Date.parse(e.atUtc)).toISOString() }));
}

/** Recoge (y borra) los eventos que dejó la bandeja. [] si no hay nada. */
export async function consumeUserActionEvents(resolvePath: () => Promise<string | null> = resolveEventsFilePath): Promise<UserActionEvent[]> {
  const filePath = await resolvePath();
  if (!filePath) return [];
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  try {
    fs.unlinkSync(filePath);
  } catch {
    // Si no se puede borrar, mejor no aplicarlo: se contaría otra vez en el siguiente tick.
    return [];
  }
  return parseUserActionEvents(raw);
}
