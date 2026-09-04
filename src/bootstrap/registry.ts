// src/bootstrap/registry.ts
//
// Leer un valor del registro de Windows de la única forma que sobrevive a un
// servicio.
//
// POR QUÉ ESTO ES UN MÓDULO Y NO TRES COPIAS
//
// El agente lee el registro en tres sitios (el token de enrolamiento, la URL
// del backend, el DeviceId). `token-source.ts` ya había aprendido a hacerlo
// bien —execFileSync, vista explícita, stderr capturado— y los otros dos
// seguían con `execSync('reg query …')`. Esa es la forma que falló en campo.
//
// LO QUE FALLA CON `execSync`
//
// `execSync` en Windows no ejecuta el comando: ejecuta `cmd.exe /d /s /c "…"`.
// Eso mete dos dependencias que una consola interactiva siempre tiene y el
// entorno de un servicio no necesariamente:
//
//   - `ComSpec` y `PATH` en el bloque de entorno del servicio, para encontrar
//     primero cmd.exe y luego reg.exe.
//   - permiso para que un servicio genere procesos hijo. Un EDR con reglas
//     sobre eso bloquea justamente esto, y `cmd.exe` colgando de un servicio
//     es un patrón mucho más sospechoso para un EDR que `reg.exe` a secas.
//
// Visto en campo (DanielA-PC, tenant 111, sep-2026): la llave existía y
// `reg query` desde una consola devolvía `https://api.tracenium.com`, mientras
// el agente caía al fallback en cada arranque. El valor estaba; la lectura no
// llegaba.
//
// LA VISTA DEL REGISTRO
//
// Un proceso de 32 bits que lee `HKLM\Software\…` es redirigido en silencio a
// `HKLM\Software\WOW6432Node\…`, donde el instalador de 64 bits nunca escribió
// nada. `/reg:64` fija la vista sin depender de la arquitectura del proceso, y
// se prueba `/reg:32` después por si un instalador viejo escribió allí.

import { execFileSync } from "child_process";

/** reg.exe responde en milisegundos; 10 s es "está colgado", no "es lento". */
export const REG_TIMEOUT_MS = 10_000;

export interface RegistryRead {
  /** El valor leído, o null si no se pudo. */
  value: string | null;
  /** Por qué no se pudo. Vacío cuando `value` no es null. */
  detail?: string;
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

/** Una sola vista del registro. Nunca lanza. */
export function readRegistryValueInView(key: string, name: string, view: "64" | "32"): RegistryRead {
  try {
    // execFileSync y no execSync: se invoca reg.exe directo, sin cmd.exe de
    // por medio. Ver la cabecera — esa diferencia es el arreglo.
    const out = execFileSync(
      "reg.exe",
      ["query", key, "/v", name, `/reg:${view}`],
      {
        encoding: "utf8",
        timeout: REG_TIMEOUT_MS,
        windowsHide: true,
        // stderr capturado, NO descartado: era el renglón que explicaba el
        // fallo y se estaba tirando a la basura.
        stdio: ["ignore", "pipe", "pipe"],
      }
    );

    const value = parseRegQueryValue(name, out);
    return value
      ? { value }
      : { value: null, detail: `[reg:${view}] value present in output but empty or unparseable` };
  } catch (err: any) {
    return { value: null, detail: `[reg:${view}] ${describeRegFailure(err)}` };
  }
}

/**
 * Lee `key\name` del registro, probando la vista de 64 y luego la de 32.
 *
 * ⚠️ Devuelve SIEMPRE un `detail` cuando falla, y quien llama tiene que
 * registrarlo. El `catch {}` mudo que esto reemplaza es la razón de que un
 * equipo estuviera semanas hablando con `localhost` sin que nada lo dijera.
 *
 * Fuera de Windows no hay registro: devuelve null con un detail que lo dice,
 * en vez de intentar un spawn que no puede funcionar.
 */
export function readRegistryValue(key: string, name: string): RegistryRead {
  if (process.platform !== "win32") {
    return { value: null, detail: "not windows" };
  }

  const wide = readRegistryValueInView(key, name, "64");
  if (wide.value) return wide;

  const narrow = readRegistryValueInView(key, name, "32");
  if (narrow.value) return narrow;

  return { value: null, detail: `${wide.detail}; ${narrow.detail}` };
}
