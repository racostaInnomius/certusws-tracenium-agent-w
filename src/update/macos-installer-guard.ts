// src/update/macos-installer-guard.ts
//
// Nuestros `/usr/sbin/installer` que siguen vivos de un intento anterior.
//
// 🔴 iMac-de-iMac-2 (T1, macOS 12.7.6), 30-sep: tres `installer -pkg
// …Tracenium-Agent-1.1.87-x64.pkg` vivos a la vez (8 h 40 min, 2 h 42 min y
// 47 min), los tres parados en `IFPKInstallElement`. La cola de PackageKit
// (installd) se había atascado a las 23:34, justo cuando macOS encoló en
// segundo plano sus datos de XProtect; desde entonces no instalaba nada, ni lo
// de Apple ni lo nuestro. El agente no lo veía: en cada intento lanzaba OTRO
// installer, contestaba `update_started`, a los 10 min daba el intento por
// caducado y volvía a empezar.
//
// Ahora, antes de lanzar uno:
//   - si hay uno nuestro reciente, se espera: "reintentar", con su pid;
//   - si alguno lleva más de INSTALLER_STALL_SEC, la cola está atascada: se
//     matan los nuestros y el intento FALLA diciendo por qué. Lanzar otro solo
//     añadiría uno más a la cola.

import { spawnSync } from "child_process";

/** Un installer nuestro más viejo que esto no va a terminar solo. */
export const INSTALLER_STALL_SEC = 30 * 60;

/** Prefijo del `skipped` cuando ya hay un installer nuestro en marcha. */
export const UPDATE_INSTALLER_RUNNING_PREFIX = "installer_running:";

export type RunningInstaller = { pid: number; elapsedSec: number };

export type InstallerGuard =
  | { action: "none" }
  | { action: "wait"; pid: number; elapsedSec: number }
  | { action: "stalled"; pids: number[]; oldestSec: number };

/** `etime` de ps: `[[dd-]hh:]mm:ss` → segundos. NaN si no lo reconoce. */
export function parseEtime(s: string): number {
  const m = String(s).trim().match(/^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$/);
  if (!m) return NaN;
  const [, d, h, min, sec] = m;
  return Number(d ?? 0) * 86400 + Number(h ?? 0) * 3600 + Number(min) * 60 + Number(sec);
}

/**
 * Los installer que instalan NUESTRO paquete, de la salida de
 * `ps -axo pid=,etime=,command=`. Sólo `/usr/sbin/installer` con un
 * `Tracenium-Agent-*.pkg`: nunca uno que el usuario o MDM lanzó para otra cosa.
 */
export function ourInstallersIn(psOutput: string): RunningInstaller[] {
  const out: RunningInstaller[] = [];
  for (const line of psOutput.split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(\S+)\s+(.*)$/);
    if (!m) continue;
    const cmd = m[3];
    if (!/^\/usr\/sbin\/installer\s/.test(cmd)) continue;
    if (!/\s-pkg\s.*\/Tracenium-Agent-[^/]*\.pkg(\s|$)/.test(cmd)) continue;
    const elapsedSec = parseEtime(m[2]);
    if (!Number.isFinite(elapsedSec)) continue;
    out.push({ pid: Number(m[1]), elapsedSec });
  }
  return out;
}

/** Qué hacer con los que haya. */
export function decideInstallerGuard(running: RunningInstaller[], stallSec = INSTALLER_STALL_SEC): InstallerGuard {
  if (!running.length) return { action: "none" };
  const oldest = running.reduce((a, b) => (b.elapsedSec > a.elapsedSec ? b : a));
  if (oldest.elapsedSec >= stallSec) {
    // Todos a la vez: los jóvenes esperan en la misma cola que el viejo.
    return { action: "stalled", pids: running.map((r) => r.pid), oldestSec: oldest.elapsedSec };
  }
  const newest = running.reduce((a, b) => (b.elapsedSec < a.elapsedSec ? b : a));
  return { action: "wait", pid: newest.pid, elapsedSec: newest.elapsedSec };
}

/** Los installer nuestros vivos ahora mismo. Si `ps` falla, ninguno: no se bloquea el update por no poder mirar. */
export function findRunningInstallers(): RunningInstaller[] {
  try {
    const res = spawnSync("/bin/ps", ["-axo", "pid=,etime=,command="], { encoding: "utf8", timeout: 10_000 });
    if (res.error || res.status !== 0) return [];
    return ourInstallersIn(String(res.stdout || ""));
  } catch {
    return [];
  }
}

/** SIGTERM y, si en 5 s sigue ahí, SIGKILL. */
export function killInstaller(pid: number): void {
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    return; // ya no existe
  }
  const t = setTimeout(() => {
    try {
      process.kill(pid, 0);
      process.kill(pid, "SIGKILL");
    } catch {
      /* salió con el TERM */
    }
  }, 5_000);
  t.unref();
}

/** «8 h 40 min» — lo que se lee en el ACK y en el log. */
export function formatElapsed(sec: number): string {
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
}
