// src/domain/probe-range.ts
//
// Ola 1.2 — rangos de red que el rol Probe BARRE, frente a los
// `host:port` sueltos de `cdp.probeTargets`.
//
// Un unico parser compartido por la policy (que lo sanea al recibirla) y
// por el colector (que lo recorre), por la misma razon que
// domain/probe-target.ts: si la policy acepta lo que el colector
// rechaza, la capacidad queda a oscuras y nadie se entera.
//
// ── Por que los limites son DUROS y viven aqui ──────────────────────
//
// Barrer una red es la unica cosa que hace el agente que un IDS puede
// leer como un escaneo de puertos. Los topes no son una optimizacion:
// son la diferencia entre inventariar y disparar una alerta de
// seguridad en casa del cliente. Estan en el parser —no en el
// colector— para que la policy los aplique al GUARDAR: un rango
// imposible se rechaza cuando el operador lo escribe, no en silencio
// tres horas despues en un equipo cualquiera.
//
//   · /22 (1024 direcciones) por entrada. Un /16 son 65.536 handshakes:
//     eso no es descubrimiento, es una prueba de carga.
//   · 8 puertos por entrada. La lista tipica es 443/8443/9443.
//   · 16 entradas. Mas que eso es un inventario de red, y ese lo tiene
//     el cliente en su IPAM, no aqui.
//
// Solo IPv4 a proposito: un rango IPv6 «pequeno» (/64) tiene 1,8e19
// direcciones y barrerlo no significa nada. Para IPv6 estan los
// objetivos explicitos de `probeTargets`.

/** Entrada tal como viaja en la policy, ya canonizada. */
export type CdpProbeRangeEntry = {
  /** `10.0.0.0/24` o `10.0.0.10-10.0.0.60`. */
  range: string;
  ports: number[];
  /**
   * Nombre a mandar como SNI para TODA la entrada (un rango de VIPs que
   * sirve un wildcard). Sin el, el colector intenta la resolucion
   * inversa de cada direccion que conteste.
   */
  sni?: string;
};

/** Entrada ya resuelta a numeros, lista para recorrer. */
export type ProbeRange = {
  /** El texto original, para el log y para decir de donde salio cada hallazgo. */
  raw: string;
  /** Primera y ultima direccion, como enteros sin signo. */
  start: number;
  end: number;
  ports: number[];
  sni?: string;
};

export const PROBE_RANGE_MAX_PREFIX = 22;
export const PROBE_RANGE_MAX_ADDRESSES = 1024;
export const PROBE_RANGE_MAX_PORTS = 8;
export const PROBE_RANGES_MAX = 16;

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
/** Nombre DNS para el SNI: lo mismo que acepta un certificado. */
const SNI_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/i;

export function ipv4ToInt(s: string): number | null {
  const m = IPV4.exec(String(s ?? "").trim());
  if (!m) return null;
  let out = 0;
  for (let i = 1; i <= 4; i += 1) {
    const o = Number(m[i]);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    out = out * 256 + o;
  }
  return out >>> 0;
}

export function intToIpv4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

/**
 * Loopback, enlace local, multicast y broadcast NUNCA se barren.
 *
 * Loopback lo cubre el colector de listeners, con atribucion a proceso.
 * 169.254/16 es la direccion que se pone una interfaz sin DHCP: barrerla
 * es hablar con uno mismo. Y 224/4 y 240/4 no son destinos unicast: un
 * SYN ahi es ruido puro.
 */
function isSkippableAddress(n: number): boolean {
  const a = (n >>> 24) & 255;
  const b = (n >>> 16) & 255;
  if (a === 0 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a >= 224) return true;
  return false;
}

function parsePorts(raw: unknown): number[] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const out: number[] = [];
  for (const p of raw) {
    const port = Number(p);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    if (out.includes(port)) continue;
    if (out.length >= PROBE_RANGE_MAX_PORTS) return null;
    out.push(port);
  }
  return out.length > 0 ? out : null;
}

function parseSni(raw: unknown): string | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  const s = String(raw).trim().toLowerCase();
  if (s.length > 253 || !SNI_RE.test(s)) return undefined;
  return s;
}

/**
 * `10.0.0.0/24` o `10.0.0.10-10.0.0.60` → [start, end], o null.
 *
 * En un CIDR se barre la red ENTERA incluidas la direccion de red y la
 * de broadcast: en /31 y /32 no existen como tales, y en el resto un SYN
 * a .0 o .255 no contesta y cuesta un intento del presupuesto. Recortar
 * dos direcciones no vale la rama extra de codigo que habria que
 * mantener correcta.
 */
export function parseRangeBounds(raw: string): { start: number; end: number } | null {
  const s = String(raw ?? "").trim();
  if (!s || s.length > 64) return null;

  const slash = s.indexOf("/");
  if (slash > 0) {
    const base = ipv4ToInt(s.slice(0, slash));
    const prefixStr = s.slice(slash + 1);
    if (base === null || !/^\d{1,2}$/.test(prefixStr)) return null;
    const prefix = Number(prefixStr);
    if (prefix < PROBE_RANGE_MAX_PREFIX || prefix > 32) return null;
    const size = prefix === 32 ? 1 : 2 ** (32 - prefix);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const start = (base & mask) >>> 0;
    return { start, end: (start + size - 1) >>> 0 };
  }

  const dash = s.indexOf("-");
  if (dash > 0) {
    const start = ipv4ToInt(s.slice(0, dash));
    const end = ipv4ToInt(s.slice(dash + 1));
    if (start === null || end === null) return null;
    if (end < start) return null;
    if (end - start + 1 > PROBE_RANGE_MAX_ADDRESSES) return null;
    return { start, end };
  }

  return null;
}

/** Entrada de policy → rango recorrible, o null si no cumple la forma o los topes. */
export function parseProbeRange(raw: unknown): ProbeRange | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const e = raw as Record<string, unknown>;
  const rangeText = typeof e.range === "string" ? e.range.trim() : "";
  const bounds = parseRangeBounds(rangeText);
  if (!bounds) return null;
  if (bounds.end - bounds.start + 1 > PROBE_RANGE_MAX_ADDRESSES) return null;
  const ports = parsePorts(e.ports);
  if (!ports) return null;
  const sni = parseSni(e.sni);
  return { raw: rangeText, start: bounds.start, end: bounds.end, ports, ...(sni ? { sni } : {}) };
}

/** Forma canonica para guardar en la policy (y para deduplicar). */
export function probeRangeEntry(r: ProbeRange): CdpProbeRangeEntry {
  return { range: r.raw, ports: r.ports.slice(), ...(r.sni ? { sni: r.sni } : {}) };
}

/** Clave de deduplicacion de una entrada. */
export function probeRangeKey(r: ProbeRange): string {
  return `${r.start}-${r.end}|${r.ports.join(",")}|${r.sni ?? ""}`;
}

/** Direcciones unicast del rango, en orden y sin las que nunca se barren. */
export function* rangeAddresses(r: ProbeRange): Generator<string> {
  for (let n = r.start; n <= r.end; n += 1) {
    if (isSkippableAddress(n)) continue;
    yield intToIpv4(n);
  }
}
