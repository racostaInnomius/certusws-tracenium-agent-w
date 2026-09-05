// src/plugins/cdp/providers/outbound-tls.ts
//
// Descubrimiento de objetivos para el rol Probe (analisis de madurez de
// CDP 2026-09, §5.2).
//
// Hasta ahora la sonda remota solo cubria lo que el operador escribia a
// mano en la policy. Pero cada equipo YA sabe con que servicios TLS
// internos habla: son sus conexiones salientes establecidas. Aqui se
// recogen como CANDIDATOS —ip:puerto, cuantas conexiones, que proceso—
// y el control plane los agrega por tenant para que el operador los
// promueva a objetivos con un clic. Nunca se sondea nada por descubrirlo:
// «nothing is discovered — only what you list is probed» sigue siendo
// verdad para la sonda; esto solo alimenta la lista.
//
// Filtros, a proposito estrechos:
//   - solo destinos PRIVADOS (RFC 1918, 100.64/10, fc00::/7). Lo publico
//     (SaaS, CDN) es de otro y no es un objetivo interno que migrar.
//   - solo puertos que hablan TLS (implicito o StartTLS).
//   - nada de loopback ni de lo que escucha este mismo equipo.

import net from "net";

export type OutboundTlsCandidate = {
  host: string;
  port: number;
  connections: number;
  process?: string;
};

export const CANDIDATE_PORTS = new Set([443, 8443, 4443, 9443, 6443, 10250, 636, 3269, 5986, 8006, 465, 587, 993, 995, 25, 110, 143, 389, 5432, 3306]);
const MAX_CANDIDATES = 200;

export function isPrivateAddress(ip: string): boolean {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (v === 6) {
    const low = ip.toLowerCase();
    if (low.startsWith("::ffff:")) return isPrivateAddress(low.slice(7));
    return /^f[cd]/.test(low);
  }
  return false;
}

export function isLoopback(ip: string): boolean {
  const low = ip.toLowerCase();
  return low.startsWith("127.") || low === "::1" || low.startsWith("::ffff:127.");
}

type ConnRow = { protocol?: string; peerAddress?: string; peerPort?: string | number; state?: string; process?: string };

/** Puro: de las conexiones a candidatos agregados. */
export function candidatesFromConnections(rows: ConnRow[], localListening: number[] = []): OutboundTlsCandidate[] {
  const byKey = new Map<string, OutboundTlsCandidate>();
  for (const r of rows) {
    if (!/^tcp/i.test(String(r.protocol || ""))) continue;
    if (String(r.state || "").toUpperCase() !== "ESTABLISHED") continue;
    const host = String(r.peerAddress || "").replace(/^\[|\]$/g, "").toLowerCase();
    const port = Number(r.peerPort);
    if (!host || !Number.isInteger(port) || port <= 0) continue;
    if (!CANDIDATE_PORTS.has(port)) continue;
    if (isLoopback(host) || !isPrivateAddress(host)) continue;
    // Una conexion a un servicio que escucha AQUI mismo, aunque sea por la
    // IP de la interfaz, ya la cubre el colector de listeners.
    if (localListening.includes(port) && r.peerAddress && isLocalPeer(host)) continue;
    const key = `${host}:${port}`;
    const cur = byKey.get(key) ?? { host, port, connections: 0 };
    cur.connections += 1;
    if (!cur.process && r.process) cur.process = String(r.process).slice(0, 64);
    byKey.set(key, cur);
  }
  return [...byKey.values()].sort((a, b) => b.connections - a.connections || a.host.localeCompare(b.host) || a.port - b.port).slice(0, MAX_CANDIDATES);
}

let localAddrs: Set<string> | null = null;
function isLocalPeer(host: string): boolean {
  if (!localAddrs) {
    localAddrs = new Set<string>();
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const os = require("os") as typeof import("os");
      for (const list of Object.values(os.networkInterfaces())) for (const i of list ?? []) localAddrs.add(String(i.address).toLowerCase());
    } catch {
      /* sin interfaces conocidas no se filtra nada */
    }
  }
  return localAddrs.has(host);
}

export async function collectOutboundTlsCandidates(opts: { connections?: ConnRow[]; localListening?: number[] } = {}): Promise<OutboundTlsCandidate[]> {
  let rows = opts.connections;
  if (!rows) {
    const si = await import("systeminformation");
    rows = (await si.networkConnections()) as ConnRow[];
  }
  return candidatesFromConnections(rows, opts.localListening ?? []);
}
