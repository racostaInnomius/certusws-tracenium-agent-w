// privsvc/linux/src/cdp-process-maps.ts
//
// CDP ola 1.5 — `cdp.process.maps`: qué proceso escucha en cada puerto y qué
// librerías compartidas tiene mapeadas. SÓLO LECTURA de /proc.
//
// POR QUÉ VA AQUÍ Y NO EN EL AGENTE
// ---------------------------------------------------------------------------
// El agente de Linux corre como `tracenium`, sin privilegios. Sin root no
// puede leer `/proc/<pid>/fd` ni `/proc/<pid>/maps` de procesos de otros
// usuarios —nginx, sshd, postgres: justo los servicios que importan—, así que
// ni sabía quién escuchaba en cada puerto ni qué libcrypto cargaba. El
// colector lo tragaba en silencio: medido el 27-sep, CERO librerías de Linux
// en toda la flota, contra cientos de Windows.
//
// Qué NO hace, a propósito: no acepta rutas ni pids del llamante. Sólo
// PUERTOS, y sólo devuelve los procesos que tienen uno de esos puertos a la
// escucha y las rutas `.so` que mapean (ni argumentos, ni entorno, ni
// memoria). Topes por puertos, procesos y librerías.
//
// Gemelo de las funciones puras del agente (`parseProcNetTcpInodes`,
// `parseProcMaps`, `serviceFromCgroup` en src/plugins/cdp): se repiten aquí
// porque el PrivSvc no importa código del agente. Si cambia una, cambian las dos.

import fs from "fs";

const MAX_PORTS = 256;
const MAX_PROCESSES = 64;
const MAX_LIBS = 256;
const MAX_PIDS_SCANNED = 5000;

export type ProcessMaps = {
  pid: number;
  name?: string;
  path?: string;
  service?: string;
  ports: number[];
  libs: string[];
};

type Fs = Pick<typeof fs, "readFileSync" | "readdirSync" | "readlinkSync">;

/** port → inodo del socket a la escucha (estado 0A), de /proc/net/tcp{,6}. */
export function parseProcNetTcpInodes(content: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const line of String(content).split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 10 || cols[3] !== "0A") continue;
    const port = parseInt(String(cols[1]).split(":")[1] ?? "", 16);
    const inode = cols[9];
    if (!Number.isInteger(port) || port <= 0 || !inode || inode === "0") continue;
    if (!out.has(port)) out.set(port, inode);
  }
  return out;
}

/** Rutas de librerías compartidas mapeadas, de /proc/<pid>/maps. */
export function parseProcMaps(content: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of String(content).split("\n")) {
    const idx = line.indexOf("/");
    if (idx < 0) continue;
    const p = line.slice(idx).replace(/ \(deleted\)$/, "").trim();
    if (!p || seen.has(p)) continue;
    if (!/\.so(\.\d[\d.]*)?$/.test(p) && !/\.so\./.test(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
}

export function serviceFromCgroup(content: string): string | null {
  const m = /([A-Za-z0-9@._\\-]+)\.service/.exec(String(content));
  return m ? `${m[1]}.service` : null;
}

/** `withLibs: false` = sólo dueños (nombrar un listener no necesita leer mapas de memoria). */
/**
 * Cuántos /proc/<pid>/fd se DENEGARON (EACCES/EPERM) mientras quedaban puertos
 * sin dueño. Distingue «nadie escucha» de «AppArmor/permisos no me dejaron
 * mirar» — medido el 27-sep: sin `ptrace (read)` en el perfil, 0 de 30
 * puertos con dueño y ni un error visible.
 */
export function lastDeniedCount(): number {
  return lastDenied;
}
let lastDenied = 0;

export function collectProcessMaps(portsIn: unknown, fsImpl: Fs = fs, opts: { withLibs?: boolean } = {}): ProcessMaps[] {
  lastDenied = 0;
  const ports = (Array.isArray(portsIn) ? portsIn : [])
    .map(Number)
    .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
    .slice(0, MAX_PORTS);
  if (ports.length === 0) return [];

  const inodeToPort = new Map<string, number>();
  for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    try {
      for (const [port, inode] of parseProcNetTcpInodes(String(fsImpl.readFileSync(table, "utf8")))) {
        if (ports.includes(port) && ![...inodeToPort.values()].includes(port)) inodeToPort.set(`socket:[${inode}]`, port);
      }
    } catch {
      // tabla ausente (sin IPv6): no es un error
    }
  }
  if (inodeToPort.size === 0) return [];

  const byPid = new Map<number, ProcessMaps>();
  let pids: string[] = [];
  try {
    pids = (fsImpl.readdirSync("/proc") as unknown as string[]).filter((e) => /^\d+$/.test(e));
  } catch {
    return [];
  }
  for (const pid of pids.slice(0, MAX_PIDS_SCANNED)) {
    if (inodeToPort.size === 0 || byPid.size >= MAX_PROCESSES) break;
    let fds: string[];
    try {
      fds = fsImpl.readdirSync(`/proc/${pid}/fd`) as unknown as string[];
    } catch (err: any) {
      if (err?.code === "EACCES" || err?.code === "EPERM") lastDenied += 1;
      continue; // o el proceso terminó entre medias
    }
    for (const fd of fds) {
      let link: string;
      try {
        link = String(fsImpl.readlinkSync(`/proc/${pid}/fd/${fd}`));
      } catch {
        continue;
      }
      const port = inodeToPort.get(link);
      if (port === undefined) continue;
      inodeToPort.delete(link);
      const n = Number(pid);
      const entry = byPid.get(n) ?? { pid: n, ports: [], libs: [] };
      entry.ports.push(port);
      byPid.set(n, entry);
    }
  }

  for (const entry of byPid.values()) {
    const read = (p: string) => {
      try {
        return String(fsImpl.readFileSync(p, "utf8")).trim() || undefined;
      } catch {
        return undefined;
      }
    };
    entry.name = read(`/proc/${entry.pid}/comm`);
    try {
      entry.path = String(fsImpl.readlinkSync(`/proc/${entry.pid}/exe`));
    } catch {
      // kernel threads o procesos que terminaron
    }
    const cg = read(`/proc/${entry.pid}/cgroup`);
    const service = cg ? serviceFromCgroup(cg) : null;
    if (service) entry.service = service;
    const maps = opts.withLibs === false ? undefined : read(`/proc/${entry.pid}/maps`);
    entry.libs = maps ? parseProcMaps(maps).slice(0, MAX_LIBS) : [];
    entry.ports.sort((a, b) => a - b);
  }
  return [...byPid.values()];
}
