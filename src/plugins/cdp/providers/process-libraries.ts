// src/plugins/cdp/providers/process-libraries.ts
//
// Ola 1.5 de CDP-VS-KEYFACTOR-2026-09.md — libreria criptografica POR
// PROCESO.
//
// Hoy la hoja de ruta de agilidad sabe que versiones de OpenSSL hay
// instaladas (inventario de software de AMP) y que JVMs hay (por la ruta
// de sus `cacerts`). Con eso, la respuesta a «que actualizo para
// desbloquear la migracion» es una lista de PAQUETES. El operador
// necesita una lista de SERVICIOS: nadie reinicia «openssl», se reinicia
// nginx, y el paquete no dice cuales de sus 40 procesos lo cargan de
// verdad.
//
// Esto lo cierra: que binario tiene cargada que libreria, con su ruta
// REAL y su version. El veredicto de bloqueo sigue siendo del control
// plane (agility.service ya tiene los umbrales escritos y citados); aqui
// solo se reportan hechos.
//
// ── Alcance: NO es un barrido de `ps` ───────────────────────────────
//
// Leer los mapas de memoria de cada proceso de una maquina ocupada es
// caro y ademas inutil: un `cat` que carga libcrypto no termina TLS de
// nadie. Se miran EXCLUSIVAMENTE los procesos que tienen un puerto TCP a
// la escucha — el resolutor puerto→proceso ya existe para los listeners
// (process-owner.ts) y esos son, por definicion, los servicios de larga
// vida cuyo upgrade tiene radio de impacto. Con tope y con presupuesto,
// como el recorrido de ficheros de la ola 1.1.
//
// ── Nunca se ejecuta lo que se encuentra ────────────────────────────
//
// La version NO se saca invocando el binario (`openssl version`): eso
// seria ejecutar un ejecutable que el agente acaba de descubrir en una
// ruta del cliente, desde un proceso root/SYSTEM. Sale de la soname
// (`libssl.so.3`), de la ruta (`.../openssl@3/3.5.0/lib/...`) o de la
// cadena de version que la propia libreria lleva dentro, leyendo el
// fichero como datos.

import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import type { CdpProcessLibraries, CdpProcessLibrary } from "../../../domain/cdp-types";
import { listListeningPorts } from "../listening-ports";
import { resolveListenerOwners, type ProcessOwner } from "../process-owner";

const execFileAsync = promisify(execFile);

const CMD_TIMEOUT_MS = 15000;
const CMD_MAX_BUFFER = 16 * 1024 * 1024;
/** Procesos a mirar. Un servidor con mas de 64 servicios a la escucha no existe. */
export const MAX_PROCESSES = 64;
/** Librerias por proceso. Un proceso carga una o dos, no veinte. */
export const MAX_LIBS_PER_PROCESS = 8;
/** Presupuesto de pared, como el recorrido de ficheros (que usa 45 s). */
export const LIBS_TIME_BUDGET_MS = 30_000;
/** Cuanto se lee de una libreria buscando su cadena de version. */
const VERSION_SCAN_BYTES = 12 * 1024 * 1024;

/**
 * Las librerias que importan, y por que estas y no mas:
 * las cuatro pilas TLS/criptograficas que un servicio puede cargar y que
 * deciden si ese servicio puede hacer ML-KEM. `gcrypt` no hace TLS pero
 * es la que usan libgnutls y systemd, y saber donde esta ahorra la
 * siguiente pregunta.
 */
const LIBRARY_PATTERNS: Array<{ re: RegExp; library: string }> = [
  { re: /\blibssl[.\-]/i, library: "openssl" },
  { re: /\blibcrypto[.\-]/i, library: "openssl" },
  { re: /\blibgnutls[.\-]/i, library: "gnutls" },
  { re: /\blibnss3[.\-]|\blibsoftokn3[.\-]|\bnss3\.dll/i, library: "nss" },
  { re: /\blibgcrypt[.\-]/i, library: "gcrypt" },
  // Windows: la pila del SISTEMA. Un servicio que carga bcrypt/ncrypt
  // hereda la capacidad de SChannel, que ya se mide aparte
  // (os-tls-capability) — aqui solo se dice quien depende de ella.
  { re: /\b(bcrypt|ncrypt|schannel)\.dll/i, library: "schannel" },
  // macOS: LibreSSL del sistema y Security.framework.
  { re: /\blibssl\.\d+\.\d+\.dylib|\blibcrypto\.\d+\.\d+\.dylib/i, library: "libressl" },
  { re: /Security\.framework\/Versions\/[A-Z]\/Security$/, library: "security-framework" }
];

export function classifyLibraryPath(p: string): string | null {
  const base = path.basename(p);
  for (const { re, library } of LIBRARY_PATTERNS) {
    if (re.test(base) || re.test(p)) return library;
  }
  return null;
}

/**
 * Version a partir del NOMBRE: soname (`libssl.so.3`, `libssl.so.1.1`),
 * dylib (`libssl.3.dylib`) o la ruta de la instalacion
 * (`/opt/homebrew/Cellar/openssl@3/3.5.0/lib/libssl.dylib`).
 *
 * ⚠️ Una soname NO es la version completa: `libssl.so.3` puede ser
 * 3.0.2 o 3.6.2, y ahi esta justo el umbral de ML-KEM (3.5). Por eso se
 * devuelve con su procedencia y el llamador prefiere la del fichero.
 */
export function versionFromPath(p: string): { version: string; source: "soname" | "path" } | null {
  const full = String(p ?? "");
  // La ruta de instalacion es la mas concreta cuando existe.
  const cellar = /(?:openssl|libressl|gnutls|nss)[@-]?\d*\/(\d+\.\d+(?:\.\d+)?[a-z]?)\//i.exec(full);
  if (cellar) return { version: cellar[1], source: "path" };
  const base = path.basename(full);
  const so = /\.so\.(\d+(?:\.\d+)*)$/.exec(base);
  if (so) return { version: so[1], source: "soname" };
  const dylib = /\.(\d+(?:\.\d+)*)\.dylib$/.exec(base);
  if (dylib) return { version: dylib[1], source: "soname" };
  return null;
}

/**
 * Version leyendo la libreria como DATOS (nunca ejecutandola).
 *
 * OpenSSL, LibreSSL y GnuTLS llevan su version en una cadena dentro del
 * binario; es la unica forma de distinguir un 3.0.2 de un 3.6.2 cuando
 * los dos son `libssl.so.3`, y esa distincion ES el umbral de ML-KEM.
 */
export function versionFromBinary(buf: Buffer): string | null {
  const text = buf.toString("latin1");
  const openssl = /OpenSSL (\d+\.\d+\.\d+[a-z]?)/.exec(text);
  if (openssl) return openssl[1];
  const libressl = /LibreSSL (\d+\.\d+\.\d+)/.exec(text);
  if (libressl) return libressl[1];
  const gnutls = /GnuTLS[ /](\d+\.\d+\.\d+)/.exec(text);
  if (gnutls) return gnutls[1];
  const nss = /NSS (\d+\.\d+(?:\.\d+)?)/.exec(text);
  if (nss) return nss[1];
  return null;
}

function readVersionFromFile(file: string): string | null {
  let fd: number | null = null;
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size === 0) return null;
    const len = Math.min(st.size, VERSION_SCAN_BYTES);
    const buf = Buffer.alloc(len);
    fd = fs.openSync(file, "r");
    fs.readSync(fd, buf, 0, len, 0);
    return versionFromBinary(buf);
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ya cerrado */
      }
    }
  }
}

// ── Linux ───────────────────────────────────────────────────────────

/** Rutas de librerias mapeadas por un proceso, de /proc/<pid>/maps. */
export function parseProcMaps(content: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of String(content).split("\n")) {
    const idx = line.indexOf("/");
    if (idx < 0) continue;
    const p = line.slice(idx).trim();
    if (!p || seen.has(p)) continue;
    // Solo lo que esta MAPEADO como codigo; un fichero de datos abierto
    // no es una libreria cargada.
    if (!/\.(so|so\.\d[\d.]*)$/.test(p) && !/\.so\./.test(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
}

/** systemd pone el nombre de la unidad en el cgroup del proceso. */
export function serviceFromCgroup(content: string): string | null {
  const m = /([A-Za-z0-9@._\\-]+)\.service/.exec(String(content));
  return m ? `${m[1]}.service` : null;
}

// ── macOS ───────────────────────────────────────────────────────────

/** `lsof -p a,b,c` → pid → rutas de dylibs/frameworks cargados. */
export function parseLsofLibraries(output: string): Map<number, string[]> {
  const out = new Map<number, string[]>();
  for (const line of String(output).split("\n")) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 9) continue;
    const pid = Number(cols[1]);
    if (!Number.isInteger(pid)) continue;
    // FD `txt` = imagen ejecutable o libreria mapeada.
    if (cols[3] !== "txt") continue;
    const p = line.slice(line.indexOf("/"));
    if (!p.startsWith("/")) continue;
    const list = out.get(pid) ?? [];
    if (!list.includes(p.trim())) list.push(p.trim());
    out.set(pid, list);
  }
  return out;
}

// ── Windows ─────────────────────────────────────────────────────────

/**
 * Salida JSON de `Get-Process -Module` → pid → [ruta, version del fichero].
 *
 * En Windows la version la da el propio recurso VERSIONINFO del modulo,
 * que es mas fiable que cualquier heuristica de nombre.
 */
export function parseWindowsModules(json: string): Map<number, Array<{ path: string; version?: string }>> {
  const out = new Map<number, Array<{ path: string; version?: string }>>();
  let parsed: any;
  try {
    parsed = JSON.parse(String(json || "[]"));
  } catch {
    return out;
  }
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  for (const r of rows) {
    const pid = Number(r?.Pid ?? r?.pid);
    const p = typeof r?.FileName === "string" ? r.FileName : typeof r?.fileName === "string" ? r.fileName : null;
    if (!Number.isInteger(pid) || !p) continue;
    const version = typeof r?.FileVersion === "string" && r.FileVersion ? r.FileVersion : undefined;
    const list = out.get(pid) ?? [];
    list.push({ path: p, ...(version ? { version } : {}) });
    out.set(pid, list);
  }
  return out;
}

type Options = {
  platform?: NodeJS.Platform;
  /** Semilla de test: procesos a mirar. */
  processes?: Array<ProcessOwner & { ports: number[] }>;
  /** Semilla de test: pid → rutas de librerias. */
  libraries?: Map<number, Array<{ path: string; version?: string }>>;
  serviceFor?: (pid: number) => string | null;
  readVersion?: (file: string) => string | null;
  realpath?: (file: string) => string;
  now?: () => number;
};

/** Los procesos con un puerto TCP a la escucha, deduplicados por pid. */
async function listeningProcesses(platform: NodeJS.Platform): Promise<Array<ProcessOwner & { ports: number[] }>> {
  const ports = await listListeningPorts();
  if (ports.length === 0) return [];
  const owners = await resolveListenerOwners(ports, platform);
  const byPid = new Map<number, ProcessOwner & { ports: number[] }>();
  for (const [port, owner] of owners) {
    const existing = byPid.get(owner.pid);
    if (existing) {
      if (!existing.ports.includes(port)) existing.ports.push(port);
      continue;
    }
    byPid.set(owner.pid, { ...owner, ports: [port] });
  }
  return [...byPid.values()].slice(0, MAX_PROCESSES);
}

async function loadedLibraries(
  platform: NodeJS.Platform,
  pids: number[]
): Promise<Map<number, Array<{ path: string; version?: string }>>> {
  const out = new Map<number, Array<{ path: string; version?: string }>>();
  if (pids.length === 0) return out;

  if (platform === "linux") {
    for (const pid of pids) {
      try {
        const maps = fs.readFileSync(`/proc/${pid}/maps`, "utf8");
        out.set(
          pid,
          parseProcMaps(maps).map((p) => ({ path: p }))
        );
      } catch {
        // Un proceso que muere entre listar y leer, o de otro usuario si
        // el agente no corre como root. No es un fallo del colector.
      }
    }
    return out;
  }

  if (platform === "darwin") {
    const { stdout } = await execFileAsync("lsof", ["-p", pids.join(","), "-Fn", "-w"], {
      timeout: CMD_TIMEOUT_MS,
      maxBuffer: CMD_MAX_BUFFER
    }).catch(() => ({ stdout: "" }));
    // `-Fn` da un formato por lineas etiquetadas; se pide tambien el
    // formato clasico por si el sistema no lo soporta.
    if (stdout.trim()) {
      let pid = 0;
      for (const line of stdout.split("\n")) {
        if (line.startsWith("p")) pid = Number(line.slice(1)) || 0;
        else if (line.startsWith("n") && pid) {
          const p = line.slice(1).trim();
          if (!p.startsWith("/")) continue;
          const list = out.get(pid) ?? [];
          if (!list.some((l) => l.path === p)) list.push({ path: p });
          out.set(pid, list);
        }
      }
    }
    return out;
  }

  if (platform === "win32") {
    // Una sola llamada para todos los pids: una por proceso en un
    // servidor con 40 servicios son 40 arranques de PowerShell.
    const script =
      `$ids=@(${pids.join(",")}); $out=@(); foreach($i in $ids){ try { ` +
      `Get-Process -Id $i -ErrorAction Stop | Select-Object -ExpandProperty Modules | ` +
      `ForEach-Object { $out += [pscustomobject]@{Pid=$i;FileName=$_.FileName;FileVersion=$_.FileVersionInfo.FileVersion} } } catch {} }; ` +
      `$out | ConvertTo-Json -Compress -Depth 3`;
    const { stdout } = await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { timeout: CMD_TIMEOUT_MS, maxBuffer: CMD_MAX_BUFFER }
    ).catch(() => ({ stdout: "" }));
    return parseWindowsModules(stdout);
  }

  return out;
}

function defaultServiceFor(platform: NodeJS.Platform): (pid: number) => string | null {
  if (platform !== "linux") return () => null;
  return (pid: number) => {
    try {
      return serviceFromCgroup(fs.readFileSync(`/proc/${pid}/cgroup`, "utf8"));
    } catch {
      return null;
    }
  };
}

export async function collectProcessLibraries(options: Options = {}): Promise<CdpProcessLibraries> {
  const platform = options.platform ?? os.platform();
  const now = options.now ?? Date.now;
  const started = now();
  const deadline = started + LIBS_TIME_BUDGET_MS;
  const result: CdpProcessLibraries = { processes: 0, libraries: [], truncated: false };

  if (platform !== "linux" && platform !== "darwin" && platform !== "win32") {
    // Decirlo, en vez de devolver una lista vacia que se lee como «este
    // equipo no carga ninguna libreria criptografica».
    result.unsupported = `platform:${platform}`;
    return result;
  }

  const processes = options.processes ?? (await listeningProcesses(platform));
  result.processes = processes.length;
  if (processes.length === 0) return result;

  const libs = options.libraries ?? (await loadedLibraries(platform, processes.map((p) => p.pid)));
  const serviceFor = options.serviceFor ?? defaultServiceFor(platform);
  const readVersion = options.readVersion ?? readVersionFromFile;
  const realpath =
    options.realpath ??
    ((f: string) => {
      try {
        return fs.realpathSync(f);
      } catch {
        return f;
      }
    });

  // La version de un mismo fichero se lee UNA vez aunque la carguen 20
  // procesos: es un escaneo de megabytes por libreria.
  const versionCache = new Map<string, string | null>();

  for (const proc of processes) {
    if (now() >= deadline) {
      result.truncated = true;
      break;
    }
    const loaded = libs.get(proc.pid) ?? [];
    const service = serviceFor(proc.pid) ?? undefined;
    let perProcess = 0;
    const seen = new Set<string>();

    for (const entry of loaded) {
      if (perProcess >= MAX_LIBS_PER_PROCESS) {
        result.truncated = true;
        break;
      }
      const library = classifyLibraryPath(entry.path);
      if (!library) continue;
      // La ruta REAL: en Linux `libssl.so.3` casi siempre es un enlace a
      // `libssl.so.3.0.2`, y el destino es el que dice la version.
      const real = realpath(entry.path);
      if (seen.has(real)) continue;
      seen.add(real);
      perProcess += 1;

      let version = entry.version;
      let versionSource: CdpProcessLibrary["versionSource"] = entry.version ? "module" : undefined;
      if (!version) {
        if (!versionCache.has(real)) versionCache.set(real, readVersion(real));
        const fromFile = versionCache.get(real) ?? null;
        if (fromFile) {
          version = fromFile;
          versionSource = "file";
        } else {
          const fromPath = versionFromPath(real) ?? versionFromPath(entry.path);
          if (fromPath) {
            version = fromPath.version;
            versionSource = fromPath.source;
          }
        }
      }

      result.libraries.push({
        pid: proc.pid,
        process: proc.name ?? "",
        ...(proc.path ? { imagePath: proc.path } : {}),
        ...(service ? { service } : {}),
        ports: proc.ports.slice().sort((a, b) => a - b),
        library,
        libraryPath: real.slice(0, 1024),
        ...(version ? { version } : {}),
        ...(versionSource ? { versionSource } : {})
      });
    }
  }

  return result;
}
