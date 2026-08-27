// src/bootstrap/token-source.ts
//
// Dónde vive el token de enrollment, y —esto es lo nuevo— QUÉ pasó cuando no
// se encontró.
//
// ⚠️ Por qué se reescribió. Un equipo de campo (DANIELA-PC) arrancó 3722 veces
// en cinco días y murió cada vez con "Missing enrollment token", mientras el
// regedit de esa misma máquina mostraba el token ahí, presente, legible. Los
// 18610 renglones de log no permitían distinguir entre las causas posibles
// —clave ausente, vista de 32 bits, reg.exe bloqueado por el EDR, ComSpec
// roto— porque la lectura del registro tenía `catch {}` vacío y mandaba stderr
// a /dev/null. El dato que faltaba no era el token: era el motivo.
//
// Tres cambios, todos en esa dirección:
//
//   1. Cada fuente deja constancia de su intento (`TokenAttempt`), y el motivo
//      llega al log en una sola línea legible por una persona que está parada
//      frente al equipo.
//   2. El registro se consulta en las DOS vistas (64 y 32 bits) de forma
//      explícita. La redirección WOW64 es silenciosa por diseño: un proceso de
//      32 bits que lee HKLM\Software\X ve HKLM\Software\WOW6432Node\X y recibe
//      exactamente el mismo "no existe" que si la clave no estuviera. Preguntar
//      por las dos elimina esa hipótesis del tablero para siempre.
//   3. Windows gana una ruta de archivo, como macOS y Linux ya tenían. Es la
//      vía de remediación que no exige reinstalar: alguien deja el token en un
//      archivo y el agente lo toma.

import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { agentDataDir } from "./paths";

const REGISTRY_KEY = "HKLM\\Software\\CertusWS\\Tracenium";
const REGISTRY_VALUE = "ENROLLMENT_TOKEN";

/**
 * Tope para reg.exe.
 *
 * Sin timeout, un reg.exe colgado —un EDR inspeccionando el proceso hijo, un
 * hive corrupto— deja el arranque del agente detenido para siempre, sin log y
 * sin que el gestor de servicios lo note: el proceso sigue vivo.
 */
const REG_TIMEOUT_MS = 10_000;

export type TokenSourceName =
  | "env"
  | "file"
  | "registry:64"
  | "registry:32";

export interface TokenAttempt {
  source: TokenSourceName;
  /** Dónde se buscó, tal cual, para poder repetirlo a mano. */
  location: string;
  found: boolean;
  /** Por qué no se encontró. Vacío cuando `found`. */
  detail?: string;
}

export interface TokenLookup {
  token: string | null;
  attempts: TokenAttempt[];
}

function enrollmentTokenFilePath(): string | null {
  if (process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE) {
    return process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE;
  }

  if (os.platform() === "darwin") {
    return "/Library/Application Support/Tracenium/Agent/enrollment.token";
  }

  if (os.platform() === "linux") {
    return "/var/lib/tracenium/enrollment.token";
  }

  if (os.platform() === "win32") {
    // Windows no tenía ruta de archivo: el registro era la ÚNICA fuente en
    // producción, así que cualquier falla al leerlo dejaba al equipo sin
    // ninguna alternativa que no fuera reinstalar el MSI.
    return path.join(agentDataDir(), "enrollment.token");
  }

  return null;
}

/**
 * Saca el dato de una salida de `reg query … /v NOMBRE`.
 *
 * ⚠️ La versión anterior hacía `out.split("REG_SZ")[1].trim()`. Eso devuelve
 * basura en silencio en cuanto la salida cambia de forma —otra vista, otro
 * tipo de valor, un idioma distinto— en vez de devolver null, que es la
 * respuesta correcta cuando no se pudo leer.
 */
export function parseRegQueryValue(name: string, stdout: unknown): string | null {
  if (typeof stdout !== "string" || !stdout.trim()) return null;

  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // El dato es el resto del renglón: un REG_SZ puede contener espacios.
  const re = new RegExp(`^\\s*${escaped}\\s+REG_(?:SZ|EXPAND_SZ)\\s+(.+)$`, "im");
  const m = re.exec(stdout);
  if (!m) return null;

  const value = m[1].trim();
  return value.length > 0 ? value : null;
}

/**
 * Traduce el fallo de reg.exe a algo que oriente a quien lo lee.
 *
 * ⚠️ Deliberadamente NO se clasifica por el texto de stderr. reg.exe escribe
 * sus errores en el idioma del sistema ("El sistema no puede encontrar la
 * clave…"), así que emparejar contra cadenas en inglés funciona en el
 * laboratorio y falla justo en el equipo del cliente. Se clasifica por lo que
 * es estable —hubo proceso o no, terminó o lo matamos, con qué código— y el
 * texto crudo se adjunta para que un humano lo lea.
 */
export function describeRegFailure(err: any): string {
  if (!err) return "unknown failure";

  if (err.code === "ETIMEDOUT" || err.killed === true) {
    return `reg.exe did not answer in ${REG_TIMEOUT_MS / 1000}s and was killed`;
  }

  // Sin `status` no llegó a correr: reg.exe ausente del PATH, o el spawn
  // bloqueado (un EDR con reglas sobre procesos hijos de un servicio hace
  // exactamente esto).
  if (err.status === undefined || err.status === null) {
    return `could not run reg.exe (${err.code || err.message || "spawn failed"})`;
  }

  const stderr = String(err.stderr || "").trim().split(/\r?\n/)[0] || "";
  return stderr
    ? `reg.exe exited ${err.status}: ${stderr}`
    : `reg.exe exited ${err.status}`;
}

function queryRegistry(view: "64" | "32"): { value: string | null; detail?: string } {
  try {
    // execFileSync y no execSync: la versión anterior pasaba por cmd.exe, que
    // agrega un proceso intermedio y un nivel de comillas para nada. Aquí se
    // invoca reg.exe directo.
    const out = execFileSync(
      "reg.exe",
      ["query", REGISTRY_KEY, "/v", REGISTRY_VALUE, `/reg:${view}`],
      {
        encoding: "utf8",
        timeout: REG_TIMEOUT_MS,
        windowsHide: true,
        // stderr capturado, NO descartado: era el renglón que explicaba el
        // fallo y se estaba tirando a la basura.
        stdio: ["ignore", "pipe", "pipe"],
      }
    );

    const value = parseRegQueryValue(REGISTRY_VALUE, out);
    return value
      ? { value }
      : { value: null, detail: "value present in output but empty or unparseable" };
  } catch (err: any) {
    return { value: null, detail: describeRegFailure(err) };
  }
}

/**
 * Busca el token en todas las fuentes y cuenta qué pasó en cada una.
 *
 * Recorre TODAS aunque una acierte antes: el costo es despreciable y el
 * registro completo de intentos es lo que permite decir "el registro no
 * respondió pero el archivo sí" en vez de sólo "arrancó".
 */
export function resolveEnrollmentToken(): TokenLookup {
  const attempts: TokenAttempt[] = [];
  let token: string | null = null;

  const envToken = (process.env.ENROLLMENT_TOKEN || "").trim();
  attempts.push({
    source: "env",
    location: "ENROLLMENT_TOKEN",
    found: envToken.length > 0,
    detail: envToken.length > 0 ? undefined : "not set",
  });
  if (envToken) token = envToken;

  const file = enrollmentTokenFilePath();
  if (file) {
    let fileToken: string | null = null;
    let detail: string | undefined;
    try {
      if (!fs.existsSync(file)) {
        detail = "does not exist";
      } else {
        const raw = fs.readFileSync(file, "utf8").trim();
        if (raw.length > 0) fileToken = raw;
        else detail = "file is empty";
      }
    } catch (err: any) {
      detail = `unreadable (${err?.code || err?.message || "error"})`;
    }
    attempts.push({ source: "file", location: file, found: !!fileToken, detail });
    if (!token && fileToken) token = fileToken;
  }

  if (os.platform() === "win32") {
    // Las dos vistas, siempre. Ver el encabezado: la redirección WOW64 es
    // indistinguible de "no existe" si sólo se pregunta una vez.
    for (const view of ["64", "32"] as const) {
      const r = queryRegistry(view);
      attempts.push({
        source: `registry:${view}`,
        location: `${REGISTRY_KEY}\\${REGISTRY_VALUE} (${view}-bit view)`,
        found: !!r.value,
        detail: r.value ? undefined : r.detail,
      });
      if (!token && r.value) token = r.value;
    }
  }

  return { token, attempts };
}

/**
 * El diagnóstico que ve una persona, no un desarrollador.
 *
 * ⚠️ Nunca incluye el valor del token: es una credencial al portador y estos
 * logs se copian por correo para pedir ayuda.
 */
export function describeTokenLookup(lookup: TokenLookup): string {
  const lines = lookup.attempts.map((a) => {
    const status = a.found ? "FOUND" : a.detail || "not found";
    return `  ${a.source.padEnd(12)} ${a.location} — ${status}`;
  });

  const remedy = enrollmentTokenFilePath();
  const tail = remedy
    ? `\nTo fix this without reinstalling: write the enrollment token into\n  ${remedy}\nThe agent picks it up on its own — no service restart needed.`
    : "";

  return `Enrollment token sources tried:\n${lines.join("\n")}${tail}`;
}

export function readEnrollmentToken(): string | null {
  return resolveEnrollmentToken().token;
}

/**
 * Securely clear the enrollment token file.
 *
 * A plain `rm` just unlinks the directory entry — the original bytes stay
 * on disk until the filesystem reuses them, so a short-lived enrollment
 * token remains recoverable via disk forensics (or just `grep` on a raw
 * block device) long after enrollment completes. This matters because
 * enrollment tokens are bearer credentials: anyone who recovers one can
 * register a rogue device against the tenant until the token is revoked
 * server-side.
 *
 * Strategy: open the file for read+write, overwrite its contents with
 * cryptographic-random bytes of the same length, fsync to force the write
 * through the page cache, THEN unlink. This is a best-effort shred — on
 * copy-on-write filesystems (APFS, btrfs, ZFS) and SSDs with wear
 * leveling the original blocks may still exist. But for the common case
 * (HFS+, ext4, directly-attached SSD with TRIM) it substantially raises
 * the bar for recovery, and it's free: we do it once, at enrollment.
 */
export function clearEnrollmentTokenFile(): void {
  const file = enrollmentTokenFilePath();
  if (!file) return;

  try {
    if (!fs.existsSync(file)) return;

    // Overwrite with random bytes before unlinking. We do two passes:
    // once with random bytes, once with zeros — covers both "forensic
    // pattern detection" and "uninitialized memory read" recovery paths.
    let fd: number | null = null;
    try {
      const stat = fs.statSync(file);
      const size = stat.size;

      if (size > 0) {
        fd = fs.openSync(file, "r+");

        const rand = crypto.randomBytes(size);
        fs.writeSync(fd, rand, 0, size, 0);
        try { fs.fsyncSync(fd); } catch {}

        const zeros = Buffer.alloc(size, 0);
        fs.writeSync(fd, zeros, 0, size, 0);
        try { fs.fsyncSync(fd); } catch {}
      }
    } catch {
      // Fall through to unlink even if the shred failed — a plain
      // unlink is still better than leaving the token on disk.
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch {}
      }
    }

    try {
      fs.rmSync(file, { force: true });
    } catch {}
  } catch {}
}
