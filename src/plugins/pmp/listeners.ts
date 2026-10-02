// src/plugins/pmp/listeners.ts
//
// ADR-0038 F2 (D4) — qué escucha este equipo y quién lo abre. Es la base de las
// SUGERENCIAS de comprobaciones post-cambio: «este servidor escucha en 1433
// (sqlservr.exe, servicio MSSQLSERVER): ¿comprobarlo tras parchear?».
//
// Se mide en la foto previa de un cambio (cuando el equipo aún está sano) y bajo
// demanda (job `verify_discover`). Reutiliza los lectores de CDP: puertos en
// escucha (netstat / /proc/net/tcp) y su proceso dueño. Sin PowerShell (un EDR
// lo vigila) y sin texto traducible: `tasklist /svc /FO CSV /NH` para el
// servicio de cada PID en Windows; el cgroup del PID en Linux.
//
// Es un enriquecimiento: nunca lanza, y «no pude» vuelve con el motivo.

import { listListeningPorts } from "../cdp/listening-ports";
import { resolveListenerOwners, type ProcessOwner } from "../cdp/process-owner";
import type { ProbeDeps } from "../live-query/probes";

export const MAX_LISTENERS = 64;

export interface ObservedListener {
  port: number;
  /** Ejecutable dueño del socket, si se supo. */
  process?: string;
  /** Servicio(s) del sistema de ese proceso: nombre de servicio de Windows o unidad systemd. */
  services?: string[];
}

export type ListenerObservation =
  | { ok: true; listeners: ObservedListener[] }
  | { ok: false; reason: string };

/** PID → servicios, de `tasklist /svc /FO CSV /NH` ("img","pid","svc1,svc2"). PURO. */
export function parseTasklistPidServices(out: string): Map<number, string[]> {
  const map = new Map<number, string[]>();
  for (const line of out.split(/\r?\n/)) {
    const cols = [...line.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    if (cols.length < 3) continue;
    const pid = Number(cols[1]);
    if (!Number.isInteger(pid) || pid <= 0) continue;
    const names = cols[2]
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s && !/^n\/a$/i.test(s) && !/\s/.test(s));
    if (names.length) map.set(pid, names);
  }
  return map;
}

/** La unidad systemd de un PID, de `/proc/<pid>/cgroup`. PURO. */
export function unitFromCgroup(content: string): string | null {
  for (const line of content.split(/\r?\n/)) {
    // cgroup v2: «0::/system.slice/nginx.service»; v1: «1:name=systemd:/system.slice/…»
    const m = /\/([^/]+\.service)(?:\/|$)/.exec(line.trim());
    if (m) return m[1];
  }
  return null;
}

export interface ListenerIo {
  listPorts: (platform: NodeJS.Platform) => Promise<number[]>;
  owners: (ports: number[], platform: NodeJS.Platform) => Promise<Map<number, ProcessOwner>>;
}

const defaultIo: ListenerIo = {
  listPorts: (p) => listListeningPorts(p),
  owners: (ports, p) => resolveListenerOwners(ports, p),
};

export async function observeListeners(d: ProbeDeps, io: ListenerIo = defaultIo): Promise<ListenerObservation> {
  try {
    const ports = (await io.listPorts(d.platform)).slice(0, MAX_LISTENERS);
    if (ports.length === 0) return { ok: true, listeners: [] };
    const owners = await io.owners(ports, d.platform).catch(() => new Map<number, ProcessOwner>());

    let servicesOf: (pid: number) => Promise<string[] | undefined> = async () => undefined;
    if (d.platform === "win32") {
      const tl = await d.exec("tasklist", ["/svc", "/FO", "CSV", "/NH"], { timeoutMs: 30_000 }).catch(() => null);
      const byPid = tl && tl.code === 0 ? parseTasklistPidServices(tl.stdout) : new Map<number, string[]>();
      servicesOf = async (pid) => byPid.get(pid);
    } else if (d.platform === "linux") {
      servicesOf = async (pid) => {
        const unit = unitFromCgroup(await d.readFile(`/proc/${pid}/cgroup`).catch(() => ""));
        return unit ? [unit] : undefined;
      };
    }

    const listeners: ObservedListener[] = [];
    for (const port of ports) {
      const o = owners.get(port);
      const services = o ? await servicesOf(o.pid) : undefined;
      listeners.push({
        port,
        ...(o?.name ? { process: o.name } : {}),
        ...(services?.length ? { services: services.slice(0, 5) } : {}),
      });
    }
    return { ok: true, listeners };
  } catch (err: any) {
    return { ok: false, reason: err?.message || String(err) };
  }
}
