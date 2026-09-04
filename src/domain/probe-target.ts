// src/domain/probe-target.ts
//
// `host:port` → objetivo de sonda TLS, o null. Compartido por la policy
// (que lo sanea al recibirla) y por el colector (que lo usa). Un unico
// parser evita que la policy acepte lo que el colector rechaza, o al
// reves — la clase de desajuste que deja una capacidad a oscuras.
//
// Rechaza loopback: el colector de listeners ya cubre el propio equipo,
// y con mas informacion (proceso propietario).

export type ProbeTarget = { host: string; port: number };

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|localhost|::1|0\.0\.0\.0)$/i;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpv4(host: string): boolean {
  return IPV4.test(host);
}

export function parseProbeTarget(raw: unknown): ProbeTarget | null {
  const s = String(raw ?? "").trim();
  if (!s || s.length > 260) return null;
  let host: string;
  let portStr: string;
  const v6 = /^\[([0-9a-f:]+)\]:(\d+)$/i.exec(s);
  if (v6) {
    host = v6[1];
    portStr = v6[2];
  } else {
    const idx = s.lastIndexOf(":");
    if (idx <= 0) return null;
    host = s.slice(0, idx);
    portStr = s.slice(idx + 1);
  }
  if (!/^\d+$/.test(portStr)) return null;
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (LOOPBACK.test(host)) return null;
  if (!/^[a-z0-9.:\-]+$/i.test(host)) return null;
  if (IPV4.test(host) && host.split(".").some((o) => Number(o) > 255)) return null;
  return { host: host.toLowerCase(), port };
}

/** Formato canonico, para deduplicar y para el id del almacen. */
export function probeTargetKey(t: ProbeTarget): string {
  return t.host.includes(":") ? `[${t.host}]:${t.port}` : `${t.host}:${t.port}`;
}
