// privsvc/macos/src/mdm-state.ts
//
// Observación del estado MDM en macOS. SOLO LECTURA — este módulo no
// escribe nada, por diseño (ADR-0002, "Construir ahora solo lo que
// sobrevive"): cuando el MDM propio entregue perfiles, el SO impone la
// configuración y cualquier escritura del agente sería redundante y,
// peor, conflictiva.
//
// Cubre dos cosas que el control plane necesita antes incluso de que
// exista servidor MDM:
//
//   1. `mdm.enrollment_state` — ¿el equipo está enrolado? ¿en qué MDM?
//      Es la telemetría que alimenta la vista de cobertura y la
//      DETECCIÓN DE TAMPER: si el usuario elimina el perfil MDM, la
//      política se evapora y hay que enterarse. En el segmento no
//      supervisado el perfil es removible, así que esto no es un extra:
//      es la contramedida.
//
//   2. `mdm.observe_settings` — valor efectivo de los ajustes del
//      catálogo de intención Y, crucialmente, si están GOBERNADOS POR UN
//      PERFIL. Eso último es la entrada del arbitraje de canal: si una
//      clave está forzada por un perfil, el agente cede y solo reporta.
//
// Cómo se detecta "forzado por perfil": macOS materializa las
// preferencias gestionadas en /Library/Managed Preferences. Si el dominio
// aparece ahí con la clave, el valor lo manda un perfil y el usuario no
// puede cambiarlo de forma persistente. Es la señal observable sin
// depender de APIs privadas.

import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

// `profiles` puede tardar más que las herramientas de posture porque
// consulta el subsistema de gestión; 10s cubre con margen.
const CMD_TIMEOUT_MS = 10_000;

const MANAGED_PREFS_DIR = "/Library/Managed Preferences";

type CmdResult = { stdout: string; stderr: string; code: number };

async function runCmd(bin: string, args: string[]): Promise<CmdResult> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, { timeout: CMD_TIMEOUT_MS });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err: any) {
    const isTimeout = err?.killed === true && err?.signal === "SIGTERM";
    return {
      stdout: err?.stdout || "",
      stderr: err?.stderr || String(err?.message || err),
      code: isTimeout ? 124 : typeof err?.code === "number" ? err.code : 1,
    };
  }
}

// ── 1. Estado de enrolamiento ────────────────────────────────────────

export type MdmEnrollmentState = {
  /** true = hay un perfil de enrolamiento MDM instalado. */
  enrolled: boolean;
  /** true = el enrolamiento fue aprobado por el usuario (UAMDM). */
  userApproved: boolean | null;
  /** true = el equipo está supervisado (ABM/ADE). */
  supervised: boolean | null;
  /**
   * null = no se pudo determinar (comando ausente o sin permisos). Se
   * distingue de false a propósito: "no lo sé" y "no está enrolado" son
   * estados distintos y confundirlos produciría falsos positivos de
   * tamper.
   */
  determined: boolean;
  raw?: string;
};

/**
 * Parsea la salida de `profiles status -type enrollment`.
 *
 * Formato típico:
 *   Enrolled via DEP: No
 *   MDM enrollment: Yes (User Approved)
 *
 * Se parsea de forma tolerante — el texto exacto ha cambiado entre
 * versiones de macOS, así que se buscan señales, no líneas literales.
 */
export function parseEnrollmentStatus(stdout: string): Omit<MdmEnrollmentState, "raw"> {
  const text = String(stdout || "");
  if (!text.trim()) {
    return { enrolled: false, userApproved: null, supervised: null, determined: false };
  }

  const mdmLine = /MDM enrollment:\s*(.+)/i.exec(text)?.[1] ?? "";
  const depLine = /Enrolled via DEP:\s*(.+)/i.exec(text)?.[1] ?? "";

  // Si no aparece ninguna de las dos líneas, no reconocemos el formato:
  // mejor declararlo indeterminado que inventar un "no enrolado".
  if (!mdmLine && !depLine) {
    return { enrolled: false, userApproved: null, supervised: null, determined: false };
  }

  const enrolled = /\byes\b/i.test(mdmLine);
  const userApproved = enrolled ? /user\s*approved/i.test(mdmLine) : null;
  // DEP ⇒ supervisado. Sin DEP no podemos afirmar lo contrario con
  // certeza desde aquí, pero para el caso que nos importa (parque
  // existente enrolado a mano) DEP=No implica no supervisado.
  const supervised = depLine ? /\byes\b/i.test(depLine) : null;

  return { enrolled, userApproved, supervised, determined: true };
}

async function readEnrollmentState(): Promise<MdmEnrollmentState> {
  const res = await runCmd("/usr/bin/profiles", ["status", "-type", "enrollment"]);
  if (res.code !== 0 && !res.stdout.trim()) {
    return { enrolled: false, userApproved: null, supervised: null, determined: false };
  }
  return { ...parseEnrollmentStatus(res.stdout), raw: res.stdout.trim() || undefined };
}

// ── 2. Ajustes observables + arbitraje ───────────────────────────────

/**
 * Ajustes del catálogo de intención que el agente puede observar en
 * macOS. Las claves son las MISMAS que las del catálogo del backend
 * (`modules/policies/mdm-catalog.ts`) — es lo que permite comparar
 * deseado vs efectivo sin traducir dos veces.
 *
 * `domain`/`pref` es dónde vive el valor; `scope` distingue las
 * preferencias de sistema de las de sesión de usuario.
 */
const OBSERVABLE: Array<{
  key: string;
  domain: string;
  pref: string;
  scope: "system" | "user";
}> = [
  { key: "macos.desktop.wallpaperImagePath", domain: "com.apple.desktop", pref: "override-picture-path", scope: "system" },
  { key: "macos.desktop.allowWallpaperChange", domain: "com.apple.applicationaccess", pref: "allowWallpaperModification", scope: "system" },
  { key: "macos.screen.idleTimeoutSeconds", domain: "com.apple.screensaver", pref: "idleTime", scope: "user" },
  { key: "macos.screen.requirePasswordAfterIdle", domain: "com.apple.screensaver", pref: "askForPassword", scope: "user" },
];

export type ObservedSetting = {
  key: string;
  /** Valor efectivo leído del sistema; null si no está definido. */
  value: unknown;
  /**
   * true = un perfil de configuración gobierna esta clave. Cuando es
   * true el agente NO debe escribirla nunca (arbitraje de canal).
   */
  managedByProfile: boolean;
};

/** Lee un plist de Managed Preferences y devuelve su contenido plano. */
function readManagedPlist(domain: string): Record<string, unknown> | null {
  // Se leen los plists directamente en lugar de `defaults read`: el
  // directorio de Managed Preferences es la materialización de los
  // perfiles, y su sola presencia ya responde "¿lo gobierna un perfil?".
  const candidates = [path.join(MANAGED_PREFS_DIR, `${domain}.plist`)];
  try {
    for (const entry of fs.readdirSync(MANAGED_PREFS_DIR, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        candidates.push(path.join(MANAGED_PREFS_DIR, entry.name, `${domain}.plist`));
      }
    }
  } catch {
    // Directorio ausente = ningún perfil ha materializado preferencias.
    return null;
  }
  for (const p of candidates) {
    if (fs.existsSync(p)) return { __path: p };
  }
  return null;
}

async function readPrefValue(
  domain: string,
  pref: string,
  scope: "system" | "user"
): Promise<unknown> {
  // `defaults read` devuelve el valor EFECTIVO (managed gana sobre
  // usuario), que es exactamente lo que queremos reportar como estado
  // real del equipo.
  const args =
    scope === "system"
      ? [`/Library/Preferences/${domain}`, pref]
      : ["-currentHost", domain, pref];
  const res = await runCmd("/usr/bin/defaults", ["read", ...args]);
  if (res.code !== 0) return null;
  const raw = res.stdout.trim();
  if (!raw) return null;
  if (/^-?\d+$/.test(raw)) return Number(raw);
  if (raw === "1" || raw === "0") return raw === "1";
  return raw;
}

async function observeSettings(): Promise<ObservedSetting[]> {
  const out: ObservedSetting[] = [];
  for (const item of OBSERVABLE) {
    let value: unknown = null;
    try {
      value = await readPrefValue(item.domain, item.pref, item.scope);
    } catch (err: any) {
      logger.info("mdm_observe_read_failed", { key: item.key, error: err?.message });
    }
    out.push({
      key: item.key,
      value,
      managedByProfile: readManagedPlist(item.domain) !== null,
    });
  }
  return out;
}

// ── Handlers IPC ─────────────────────────────────────────────────────

export async function handleMdmEnrollmentState(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const state = await readEnrollmentState();
    return success(req.id, state);
  } catch (err: any) {
    logger.error("mdm_enrollment_state_failed", { error: err?.message || String(err) });
    return fail(req.id, "mdm_state_failed", err?.message || String(err));
  }
}

export async function handleMdmObserveSettings(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const settings = await observeSettings();
    return success(req.id, { settings, observedAtUtc: new Date().toISOString() });
  } catch (err: any) {
    logger.error("mdm_observe_settings_failed", { error: err?.message || String(err) });
    return fail(req.id, "mdm_observe_failed", err?.message || String(err));
  }
}
