// src/plugins/cdp/providers/tls-range-sweep.ts
//
// Ola 1.2 de CDP-VS-KEYFACTOR-2026-09.md — barrido por rangos.
//
// Hasta ahora el rol Probe solo miraba los `host:port` que el operador
// escribia uno a uno (`cdp.probeTargets`). Keyfactor Command barre
// rangos enteros repartidos entre sus orquestadores, y esa es la
// diferencia entre «inventaria lo que ya sabias» y «te dice lo que hay».
//
// Lo que se anade es SOLO la generacion de objetivos: el handshake, el
// STARTTLS, la segunda sonda de ML-KEM y el parseo del certificado son
// exactamente los mismos de tls-probes.ts, asi que una direccion barrida
// produce las MISMAS filas (`cdp_tls_endpoints`, certificado con
// `source=probe` y `scope=network`) que una escrita a mano. Si fueran
// dos caminos distintos, acabarian midiendo cosas distintas.
//
// ── Esto no puede parecer un escaneo de puertos ─────────────────────
//
// Es la restriccion de diseno, no un detalle de implementacion. Un
// agente nuestro disparando el IDS del cliente es un incidente para el
// cliente y una llamada de soporte para nosotros. De ahi:
//
//   · Solo desde los equipos de `cdp.probeHosts` (igual que las sondas
//     sueltas): barre UNO, no los 54.
//   · Concurrencia baja y un hueco minimo entre intentos — un limite de
//     RITMO, que es lo que miran las firmas de escaneo, no solo de
//     paralelismo.
//   · Presupuesto de pared y de intentos por ejecucion: el barrido se
//     corta y lo DICE (`truncated`), en vez de alargarse sin fin.
//   · Nada por defecto: sin `cdp.probeRanges` no se abre un socket.
//
// ── Por que hay una comprobacion TCP antes del TLS ──────────────────
//
// Un /24 tiene 254 direcciones y la mayoria no existe. Con el timeout de
// handshake (3 s) el presupuesto se lo comerian los huecos y no
// llegariamos a los servicios reales. La puerta TCP con un timeout corto
// separa «no hay nadie» de «hay algo» a una fraccion del coste; solo lo
// que acepta la conexion pasa por la ruta de sonda completa.

import net from "net";
import dns from "dns";
import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpProbeSweepStats, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";
import { probeTlsWithKem, type TlsProbeResult } from "./tls-listeners";
import { probeTargetKey } from "../../../domain/probe-target";
import { rangeAddresses, type ProbeRange } from "../../../domain/probe-range";

/** Direcciones consideradas en TOTAL por ejecucion, sumando entradas. */
export const SWEEP_MAX_ADDRESSES = 4096;
/** Conexiones TCP abiertas en TOTAL por ejecucion (direcciones x puertos). */
export const SWEEP_MAX_ATTEMPTS = 4096;
/** Presupuesto de pared. El barrido se corta y lo dice. */
export const SWEEP_TIME_BUDGET_MS = 120_000;
/** Hueco minimo entre intentos: 25 conexiones por segundo como techo. */
export const SWEEP_MIN_GAP_MS = 40;
export const SWEEP_TCP_CONCURRENCY = 8;
export const SWEEP_TLS_CONCURRENCY = 4;
/** Un puerto vivo acepta en milisegundos; uno filtrado no acepta nunca. */
export const SWEEP_TCP_TIMEOUT_MS = 1000;
/** Tope de certificados que un barrido puede anadir al payload. */
export const SWEEP_MAX_ITEMS = 500;
/** Resoluciones inversas por ejecucion. Solo de lo que ya contesto. */
const SWEEP_MAX_REVERSE = 256;
const REVERSE_TIMEOUT_MS = 1500;

export type RangeSweepResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  stats: CdpProbeSweepStats;
};

type Unit = { address: string; port: number; range: string; sni?: string };

type Options = {
  /** Semillas de test. */
  ranges?: ProbeRange[];
  skip?: Set<string>;
  tcpCheck?: (host: string, port: number) => Promise<boolean>;
  probe?: (host: string, port: number, servername: string) => Promise<TlsProbeResult | null>;
  reverse?: (host: string) => Promise<string | null>;
  now?: () => number;
  /** Sin espera real en los tests. */
  gapMs?: number;
};

/** ¿Acepta el puerto una conexion? Ni un byte de protocolo se escribe. */
export function tcpAccepts(host: string, port: number, timeoutMs = SWEEP_TCP_TIMEOUT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: boolean) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ya cerrado */
      }
      resolve(value);
    };
    const socket = net.connect({ host, port });
    socket.setTimeout(timeoutMs, () => done(false));
    socket.on("connect", () => done(true));
    socket.on("error", () => done(false));
    socket.on("close", () => done(false));
  });
}

async function reverseLookup(host: string): Promise<string | null> {
  try {
    const names = await Promise.race([
      dns.promises.reverse(host),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error("timeout")), REVERSE_TIMEOUT_MS))
    ]);
    const first = Array.isArray(names) ? names.find((n) => typeof n === "string" && n.length > 0) : undefined;
    return first ? first.replace(/\.$/, "").toLowerCase() : null;
  } catch {
    return null;
  }
}

/**
 * Planifica el trabajo: direcciones x puertos, sin lo que ya cubren los
 * objetivos explicitos y dentro de los topes globales.
 *
 * Se recorre por PUERTO dentro de cada direccion y las entradas en
 * orden, para que un corte por presupuesto deje rangos enteros sin mirar
 * en vez de medio rango a medias en todos: lo primero se cuenta bien
 * («estas dos entradas no se miraron»), lo segundo no se cuenta de
 * ninguna manera honesta.
 */
export function planSweep(
  ranges: ProbeRange[],
  skip: Set<string>
): { units: Unit[]; addresses: number; skipped: number; truncated: CdpProbeSweepStats["truncated"] } {
  const units: Unit[] = [];
  let addresses = 0;
  let skipped = 0;
  let truncated: CdpProbeSweepStats["truncated"] = null;

  for (const range of ranges) {
    for (const address of rangeAddresses(range)) {
      if (addresses >= SWEEP_MAX_ADDRESSES) {
        truncated = "addresses";
        return { units, addresses, skipped, truncated };
      }
      addresses += 1;
      for (const port of range.ports) {
        // Lo que el operador ya sondea explicitamente no se barre: el
        // objetivo suelto manda (lleva el nombre que el escribio, y ese
        // nombre es el SNI correcto) y barrerlo seria una segunda
        // conexion al mismo servicio en cada ciclo.
        if (skip.has(probeTargetKey({ host: address, port }))) {
          skipped += 1;
          continue;
        }
        if (units.length >= SWEEP_MAX_ATTEMPTS) {
          truncated = "attempts";
          return { units, addresses, skipped, truncated };
        }
        units.push({ address, port, range: range.raw, ...(range.sni ? { sni: range.sni } : {}) });
      }
    }
  }
  return { units, addresses, skipped, truncated };
}

/** Limitador de ritmo: garantiza `gapMs` entre el inicio de dos intentos. */
function rateGate(gapMs: number, now: () => number) {
  let next = 0;
  return async () => {
    if (gapMs <= 0) return;
    const t = now();
    const wait = Math.max(0, next - t);
    next = Math.max(t, next) + gapMs;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  };
}

async function runLimited<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      await fn(items[index]);
    }
  });
  await Promise.all(workers);
}

export async function collectRangeSweep(ctx: AgentContext, options: Options = {}): Promise<RangeSweepResult> {
  const now = options.now ?? Date.now;
  const started = now();
  const ranges = options.ranges ?? ctx.policyRuntime.getCdpProbeRanges?.() ?? [];
  const skip =
    options.skip ?? new Set((ctx.policyRuntime.getCdpProbeTargets?.() ?? []).map((t) => probeTargetKey(t)));

  const stats: CdpProbeSweepStats = {
    ranges: ranges.length,
    addresses: 0,
    attempts: 0,
    accepted: 0,
    answered: 0,
    skippedExisting: 0,
    sniAttempts: 0,
    sniDistinct: 0,
    elapsedMs: 0,
    truncated: null
  };
  const result: RangeSweepResult = { items: [], stores: [], parseFailures: 0, stats };
  if (ranges.length === 0) return result;

  const plan = planSweep(ranges, skip);
  stats.addresses = plan.addresses;
  stats.skippedExisting = plan.skipped;
  stats.truncated = plan.truncated;

  const deadline = started + SWEEP_TIME_BUDGET_MS;
  const gate = rateGate(options.gapMs ?? SWEEP_MIN_GAP_MS, now);
  const tcpCheck = options.tcpCheck ?? ((h: string, p: number) => tcpAccepts(h, p));
  const probe = options.probe ?? probeTlsWithKem;
  const reverse = options.reverse ?? reverseLookup;

  // ── Fase 1: ¿hay alguien? ────────────────────────────────────────
  const open: Unit[] = [];
  await runLimited(plan.units, SWEEP_TCP_CONCURRENCY, async (unit) => {
    if (now() >= deadline) {
      stats.truncated = stats.truncated ?? "time";
      return;
    }
    await gate();
    if (now() >= deadline) {
      stats.truncated = stats.truncated ?? "time";
      return;
    }
    stats.attempts += 1;
    const accepts = await tcpCheck(unit.address, unit.port).catch(() => false);
    if (accepts) {
      stats.accepted += 1;
      open.push(unit);
    }
  });

  // ── Resolucion inversa, SOLO de lo que contesto ──────────────────
  //
  // Un PTR por direccion viva, no por direccion planificada: preguntar
  // al DNS por 1024 nombres que no existen es otra firma que un
  // analista reconoce, y no aporta nada.
  const names = new Map<string, string>();
  const needReverse = [...new Set(open.filter((u) => !u.sni).map((u) => u.address))].slice(0, SWEEP_MAX_REVERSE);
  for (const address of needReverse) {
    if (now() >= deadline) {
      stats.truncated = stats.truncated ?? "time";
      break;
    }
    const name = await reverse(address).catch(() => null);
    if (name) names.set(address, name);
  }

  // ── Fase 2: el handshake de siempre ──────────────────────────────
  await runLimited(open, SWEEP_TLS_CONCURRENCY, async (unit) => {
    if (now() >= deadline) {
      stats.truncated = stats.truncated ?? "time";
      return;
    }
    await gate();
    // Sin SNI: lo que la DIRECCION sirve por defecto. Es el hecho sobre
    // el equipo que hay ahi, y el unico que se puede afirmar de una IP.
    const plain = await probe(unit.address, unit.port, "").catch(() => null);

    // Con SNI: lo que un cliente real recibiria. Keyfactor hace el doble
    // intento y tiene razon — detras de una IP puede haber N vhosts y el
    // certificado por defecto no es ninguno de ellos.
    const name = unit.sni ?? names.get(unit.address);
    let named: TlsProbeResult | null = null;
    if (name && now() < deadline) {
      await gate();
      stats.sniAttempts += 1;
      named = await probe(unit.address, unit.port, name).catch(() => null);
    }

    const sameCert =
      plain && named && Buffer.isBuffer(plain.der) && Buffer.isBuffer(named.der) && plain.der.equals(named.der);

    if (plain) {
      push(result, unit, plain, { target: unit.address, sni: null, stats });
    }
    if (named && !sameCert) {
      // Certificado distinto por SNI: es OTRO endpoint (vhost por
      // nombre), no el mismo con otra etiqueta. Se identifica por el
      // NOMBRE para que no colisione con la fila de la direccion — que
      // sigue siendo un hecho valido sobre esa IP.
      stats.sniDistinct += 1;
      push(result, unit, named, { target: name!, sni: name!, stats });
    }
  });

  stats.elapsedMs = Math.max(0, now() - started);
  if (result.items.length > SWEEP_MAX_ITEMS) {
    result.items = result.items.slice(0, SWEEP_MAX_ITEMS);
    result.stores = result.stores.slice(0, SWEEP_MAX_ITEMS);
    stats.truncated = stats.truncated ?? "items";
  }

  ctx.logger?.info?.("CDP: barrido de rangos", {
    ranges: stats.ranges,
    addresses: stats.addresses,
    attempts: stats.attempts,
    accepted: stats.accepted,
    answered: stats.answered,
    truncated: stats.truncated,
    elapsedMs: stats.elapsedMs
  });
  return result;
}

function push(
  result: RangeSweepResult,
  unit: Unit,
  hit: TlsProbeResult,
  opts: { target: string; sni: string | null; stats: CdpProbeSweepStats }
): void {
  const key = probeTargetKey({ host: opts.target, port: unit.port });
  const store: CdpStoreInfo = { id: `probe/tcp/${key}`, name: key, scope: "network" };
  const item = parseCertToItem(hit.der, { store, hasPrivateKey: false });
  if (!item) {
    result.parseFailures += 1;
    return;
  }
  opts.stats.answered += 1;
  item.source = "probe";
  // Como en tls-probes.ts: lo que hay al otro lado no es de este equipo.
  item.hasPrivateKey = false;
  item.tls = {
    port: unit.port,
    target: opts.target,
    chainDepth: hit.chainDepth,
    chainAuthorized: hit.chainAuthorized,
    ...(hit.chainError ? { chainError: hit.chainError } : {}),
    ...(hit.protocol ? { protocol: hit.protocol } : {}),
    ...(hit.cipher ? { cipher: hit.cipher } : {}),
    ...(hit.kexGroup ? { kexGroup: hit.kexGroup } : {}),
    ...(hit.kemHybrid !== undefined ? { kemHybrid: hit.kemHybrid } : {}),
    ...(hit.kemProbeError ? { kemProbeError: hit.kemProbeError } : {}),
    ...(hit.startTls ? { startTls: hit.startTls } : {}),
    // Cual de los dos intentos dio ESTE certificado, y de que entrada de
    // rango salio. Sin esto, un operador no puede distinguir «la IP sirve
    // esto» de «este nombre sirve esto», que es justo lo que el doble
    // intento existe para separar.
    ...(opts.sni ? { sni: opts.sni } : {}),
    sweep: unit.range
  };
  result.items.push(item);
  result.stores.push(store);
}
